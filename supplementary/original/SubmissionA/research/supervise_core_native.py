"""Fresh bounded native correctness workers; exclusive immutable receipts."""
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import selectors
import signal
import subprocess
import sys
import time

from core_grid_fixture import CELLS, metadata, oracle_states
from core_profile_manifest import select

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
ROOT = PAPER.parent
LIMITS = dict(address_space_bytes=2*2**30, cpu_seconds=160, wall_seconds=180,
              combined_pipe_bytes=4*2**20, individual_file_bytes=8*2**20,
              threads=1, core_dump_bytes=0)


def manifest():
    pending = [Path(__file__), HERE / "core_native_execution.py"]
    paths = set()
    while pending:
        path = pending.pop().resolve()
        if path in paths:
            continue
        paths.add(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = ([node.module] if isinstance(node, ast.ImportFrom) else
                     [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
            for name in names:
                if name:
                    local = HERE / (name.split(".")[0]+".py")
                    if local.is_file() and local.resolve() not in paths:
                        pending.append(local)
    paths.update([HERE / "CORE_GRID_V1_GATE_PROTOCOL.md", HERE / "CORE_GRID_V1_DESIGN.md",
                  HERE / "composition_native_core.cpp", HERE / "composition_optimized_core.cpp",
                  PAPER / "build/composition_optimized_core.so"])
    return {path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def main():
    if not __debug__ or len(sys.argv) != 2 or sys.argv[1] not in CELLS:
        raise SystemExit("Assertions required. Usage: supervise_core_native.py CELL")
    cell = sys.argv[1]
    destination = PAPER / "evidence" / ("core-native-gate-v1-"+cell+".json")
    assert not destination.exists(), "Never overwrite a gate receipt"
    work = PAPER / "build/core-native-gate-v1" / cell
    work.parent.mkdir(exist_ok=True)
    work.mkdir(exist_ok=False)
    before = manifest()
    family, length, jobs = CELLS[cell]
    expected_profile = select(length, family, "raw")["selected"]
    _, expected = oracle_states(cell)
    expected_digest = sha256(expected.tobytes()).hexdigest()
    cpu = min(os.sched_getaffinity(0))
    command = [sys.executable, "-B", str(HERE / "core_native_execution.py"),
               "--supervised-cell", cell]
    env = dict(os.environ)
    env.update(OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1",
               NUMEXPR_NUM_THREADS="1", PYTHONDONTWRITEBYTECODE="1")

    def limits():
        os.sched_setaffinity(0, {cpu})
        for kind, amount in ((resource.RLIMIT_AS, LIMITS["address_space_bytes"]),
                             (resource.RLIMIT_CPU, LIMITS["cpu_seconds"]),
                             (resource.RLIMIT_CORE, 0),
                             (resource.RLIMIT_FSIZE, LIMITS["individual_file_bytes"])):
            resource.setrlimit(kind, (amount, amount))

    capture = [bytearray(), bytearray()]
    result = error = after = None
    selector = selectors.DefaultSelector()
    started = time.monotonic()
    child = subprocess.Popen(command, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, start_new_session=True, preexec_fn=limits, close_fds=True)
    selector.register(child.stdout, selectors.EVENT_READ, 0)
    selector.register(child.stderr, selectors.EVENT_READ, 1)
    deadline = started + LIMITS["wall_seconds"]
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("Native core wall limit")
            for key, _ in selector.select(timeout=min(1, max(0, deadline-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if sum(map(len, capture))+len(chunk) > LIMITS["combined_pipe_bytes"]:
                    raise RuntimeError("Native core pipe-output limit")
                capture[key.data].extend(chunk)
        assert child.wait(timeout=max(0.01, deadline-time.monotonic())) == 0, "Worker failed"
        result = json.loads(capture[0].decode("utf-8"))
        assert result["status"] == "CORE_NATIVE_FUNCTIONAL_PASS"
        assert result["cell"] == cell and result["fixture"] == metadata(cell)
        assert result["profile"] == expected_profile
        assert result["actual_gate_encrypted_execution"] and not result["benchmark"]
        assert not result["security_128_qualified"] and not result["bootstrapping"]
        assert not result["secret_keys_exported"] and not result["phase_diagnostics_exported"]
        assert len(result["batches"]) == 2
        expected_states = (expected_profile["encryptions_per_batch"] + expected_profile["products"]
                           + expected_profile["executed_rekeys"] + expected_profile["executed_prime_drops"])
        for index, batch in enumerate(result["batches"]):
            assert (batch["index"], batch["output_symbols"], batch["output_sha256"], batch["checked_states"]) == (
                index, length*jobs, expected_digest, expected_states)
            assert batch["raw_input_bytes"] == expected_profile["raw_rns_input_bytes"]
            assert batch["raw_output_bytes"] == expected_profile["raw_rns_output_bytes"]
        after = manifest()
        assert after == before, "Source or binary changed during gate"
        assert not list(work.iterdir()), "Unexpected worker-created files"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        code = child.wait(timeout=10)
        selector.close()
        child.stdout.close()
        child.stderr.close()
    if after is None:
        try:
            after = manifest()
        except Exception as exc:
            error = (error+"; " if error else "")+f"After-manifest unavailable: {exc}"
    cpu_model = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                      if line.startswith("model name")), "unavailable")
    record = dict(schema="core-native-functional-gate-v1", status="PASS" if error is None else "FAIL",
        cell=cell, limits=LIMITS, affinity_cpu=cpu, command=command,
        worker_cwd=work.relative_to(ROOT).as_posix(),
        host=dict(kernel=platform.release(), machine=platform.machine(), cpu_model=cpu_model, python=sys.version),
        binary_build_attestation=False, source_manifest=before, sources_unchanged=before == after,
        worker_exit_code=code, worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY=time.monotonic()-started,
        stdout_bytes=len(capture[0]), stderr=capture[1].decode(errors="replace"), error=error, result=result,
        benchmark=False, security_128_qualified=False)
    if error:
        record["failed_stdout"] = capture[0].decode(errors="replace")
    encoded = json.dumps(record, indent=2)+"\n"
    assert len(encoded.encode("utf-8")) < 5*2**20
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(encoded)
    print(json.dumps(dict(status=record["status"], cell=cell, receipt=destination.relative_to(ROOT).as_posix(),
                          receipt_sha256=sha256(destination.read_bytes()).hexdigest(), error=error,
                          checked_states_per_batch=None if result is None else result["batches"][0]["checked_states"],
                          benchmark=False, security_128_qualified=False)), flush=True)
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
