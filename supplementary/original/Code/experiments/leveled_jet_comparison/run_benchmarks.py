"""Run matched leveled OpenFHE cases sequentially and preserve raw observations.

Every output directory and record is created exclusively. No old evidence is
overwritten. This harness measures library evaluation; it does not certify
security or confer authority on ExactJet artifacts.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import random
import subprocess
import sys
import time
from datetime import datetime, timezone


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def digest_file(path: Path) -> dict:
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def write_json(path: Path, value: object) -> None:
    data = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")
    with path.open("xb") as stream:
        stream.write(data)


def hardware() -> dict:
    result = {"os": platform.platform(), "machine": platform.machine(),
              "logical_processors": os.cpu_count(), "python": sys.version,
              "cpu": platform.processor()}
    if os.name == "nt":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            result["cpu"] = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                        ("total_physical", ctypes.c_ulonglong),
                        ("available_physical", ctypes.c_ulonglong),
                        ("total_page", ctypes.c_ulonglong),
                        ("available_page", ctypes.c_ulonglong),
                        ("total_virtual", ctypes.c_ulonglong),
                        ("available_virtual", ctypes.c_ulonglong),
                        ("available_extended", ctypes.c_ulonglong)]
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            result["physical_memory_bytes"] = status.total_physical
    return result


def case_grid(args: argparse.Namespace) -> list[dict]:
    cases = []
    for scheme, layout, length, mults, jobs in itertools.product(
            args.schemes, args.layouts, args.lengths, args.mults, args.jobs):
        schedules = ["sequential"]
        if args.balanced and mults == 4 and length == max(args.lengths):
            schedules.append("balanced")
        for schedule in schedules:
            cases.append({"scheme": scheme, "layout": layout, "length": length,
                          "mults": mults, "schedule": schedule, "jobs": jobs,
                          "repetitions": args.repetitions, "seed": args.seed})
    random.Random(args.order_seed).shuffle(cases)
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--schemes", nargs="+", choices=["BGV", "BFV"], default=["BGV", "BFV"])
    parser.add_argument("--layouts", nargs="+", choices=["native", "packed_terminal"],
                        default=["native", "packed_terminal"])
    parser.add_argument("--lengths", nargs="+", type=int, default=[4, 8, 16])
    parser.add_argument("--mults", nargs="+", type=int, default=[1, 2, 4])
    parser.add_argument("--jobs", nargs="+", type=int, default=[1, 16])
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--order-seed", type=int, default=20260905)
    parser.add_argument("--balanced", action="store_true")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if min(args.lengths + args.mults + args.jobs + [args.repetitions]) <= 0:
        parser.error("lengths, mults, jobs, and repetitions must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "source").mkdir()
    bindings = []
    for name in ("benchmark.cpp", "CMakeLists.txt", "run_benchmarks.py",
                 "verify_results.py", "test_verify_results.py"):
        source = HERE / name
        if not source.exists():
            raise FileNotFoundError(source)
        dest = output / "source" / name
        with dest.open("xb") as stream:
            stream.write(source.read_bytes())
        bindings.append({"path": dest.relative_to(output).as_posix(),
                         "original_path": source.relative_to(ROOT).as_posix(),
                         **digest_file(dest)})
    executable = {"path": binary.relative_to(ROOT).as_posix(), **digest_file(binary)}
    dependencies = [{"path": path.relative_to(ROOT).as_posix(), **digest_file(path)}
                    for path in sorted(binary.parent.glob("*.dll"))]
    env = dict(os.environ)
    env.update(OMP_NUM_THREADS="1", OMP_DYNAMIC="FALSE", OPENBLAS_NUM_THREADS="1",
               MKL_NUM_THREADS="1")
    env["PATH"] = str(binary.parent) + os.pathsep + env.get("PATH", "")
    cases = case_grid(args)
    run = {"schema": "nilhe.leveled-library-comparison.manifest.v1",
           "status": "MEASURED_LEVELED_LIBRARY_COMPARISON_ONLY",
           "run_id": output.name,
           "started_utc": datetime.now(timezone.utc).isoformat(),
           "environment": {**hardware(), "OMP_NUM_THREADS": 1,
                           "OMP_DYNAMIC": "FALSE", "timed_processes_parallel": False,
                           "execution_order_seed": args.order_seed},
           "publication": {"mode": "exclusive-create", "overwrites_existing": False},
           "claim_boundary": {"independent_security_certification": False,
                              "exactjet_execution": False, "refresh_execution": False,
                              "arbitrary_cyclotomic_security_transfer": False,
                              "measured_library_leveled_evaluation": True},
           "source_bindings": bindings, "executable": executable,
           "dependencies": dependencies, "requested_cases": cases, "cases": []}
    write_json(output / "plan.json", run)
    begin = time.perf_counter()
    for index, config in enumerate(cases, 1):
        stem = (f"{index:03d}-{config['scheme']}-{config['layout']}-e{config['length']}"
                f"-d{config['mults']}-j{config['jobs']}-{config['schedule']}")
        command = [str(binary)]
        for key, value in config.items():
            command.extend(["--" + key, str(value)])
        print(f"[{index}/{len(cases)}] {stem}", flush=True)
        start = time.perf_counter()
        completed = subprocess.run(command, capture_output=True, text=True, env=env,
                                   cwd=ROOT, timeout=args.timeout)
        elapsed = time.perf_counter() - start
        if completed.returncode:
            write_json(output / (stem + "-failure.json"),
                       {"command": command, "returncode": completed.returncode,
                        "stdout": completed.stdout, "stderr": completed.stderr,
                        "elapsed_seconds": elapsed})
            raise RuntimeError(f"Case failed: {stem}: {completed.stderr[-2000:]}")
        record = json.loads(completed.stdout)
        case_path = output / (stem + ".json")
        write_json(case_path, record)
        entry = {"path": case_path.name, **digest_file(case_path), "configuration": config,
                 "process_elapsed_seconds": elapsed}
        if completed.stderr:
            stderr_path = output / (stem + "-stderr.json")
            write_json(stderr_path, {"stderr": completed.stderr})
            entry["stderr"] = {"path": stderr_path.name, **digest_file(stderr_path)}
        run["cases"].append(entry)
        print(f"  recorded {case_path.stat().st_size} bytes, process {elapsed:.2f} s", flush=True)
    if digest_file(binary) != {key: executable[key] for key in ("sha256", "bytes")}:
        raise RuntimeError("Benchmark executable changed during the run")
    run["completed_utc"] = datetime.now(timezone.utc).isoformat()
    run["elapsed_seconds"] = time.perf_counter() - begin
    manifest = output / "manifest.json"
    write_json(manifest, run)
    verify = subprocess.run([sys.executable, str(HERE / "verify_results.py"),
                             str(manifest), "--repo-root", str(ROOT)], cwd=ROOT)
    if verify.returncode:
        return verify.returncode
    print(f"COMPLETED: {manifest}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
