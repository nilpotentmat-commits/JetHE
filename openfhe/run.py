"""Run the packaged OpenFHE adapters and validate every recovered coefficient.

Linux/WSL only. A smoke run changes the workload and is not a paper timing.
Every invocation creates a new result directory and retains failures.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PIN = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"
EXPECTED_SHA = "d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    with Path(path).open("x", encoding="utf-8", newline="\n") as out:
        json.dump(data, out, indent=2)
        out.write("\n")


def expected(jobs, length):
    path = HERE / "fixtures/expected-output.bin"
    if digest(path) != EXPECTED_SHA:
        raise ValueError("The preserved full-output vector has changed")
    full = struct.unpack("<4096H", path.read_bytes())
    return [full[256 * j + i] for j in range(jobs) for i in range(length)]


def validate(result, profile, jobs, length, mode):
    if result.get("status") != "PASS":
        raise ValueError("adapter did not report PASS")
    if result.get("encrypted_execution") != (mode != "clear"):
        raise ValueError("encrypted/clear mode mismatch")
    if result.get("fixture_fnv1a64") != profile["fixture_fnv1a64"]:
        raise ValueError("public input fixture checksum mismatch")
    reference = expected(jobs, length)
    batches = [result] if mode == "clear" else result["batches"]
    if len(batches) != (2 if mode == "benchmark" else 1):
        raise ValueError("unexpected number of checked batches")
    for batch in batches:
        if batch.get("recovered_symbols") != reference:
            raise ValueError("recovered coefficients differ from the preserved exact result")
    if mode == "benchmark":
        actual = result["profile"]
        # Compiler version may differ on another host. The other listed fields
        # describe the exact selected cryptographic configuration.
        for key, value in profile["expected_profile"].items():
            if key != "compiler" and actual.get(key) != value:
                raise ValueError(f"selected profile changed: {key}: {actual.get(key)!r} != {value!r}")
        for batch in batches:
            if batch["executed_inventory"] != profile["expected_inventory"]:
                raise ValueError("executed operation inventory changed")
            if batch["fresh_encryptions"] != profile["expected_encryptions"]:
                raise ValueError("encryption inventory changed")
            if batch["returned_ciphertexts"] != profile["expected_outputs"]:
                raise ValueError("output inventory changed")
    return len(reference) * len(batches)


def check_sources():
    provenance = json.loads((HERE / "PROVENANCE.json").read_text(encoding="utf-8"))
    for entry in provenance["files"]:
        if digest(HERE / entry["destination"]) != entry["released_sha256"]:
            raise ValueError(f"packaged scientific source changed: {entry['destination']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    location = parser.add_mutually_exclusive_group()
    location.add_argument("--binary", type=Path)
    location.add_argument("--build-dir", type=Path)
    parser.add_argument("--profile", choices=["all", "summed", "terminal", "summed-bgv", "terminal-bgv", "relay-bfv"], default="all")
    parser.add_argument("--mode", choices=["clear", "smoke", "benchmark"], default="smoke")
    parser.add_argument("--setups", type=int, default=1)
    parser.add_argument("--cpu", type=int, help="one allowed logical CPU; default lowest allowed")
    parser.add_argument("--timeout", type=float, default=900, help="seconds per subprocess")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or not hasattr(os, "sched_setaffinity"):
        parser.error("run inside Linux or WSL, not Windows Python")
    if args.setups < 1 or args.timeout <= 0:
        parser.error("setups and timeout must be positive")
    if args.mode != "benchmark" and args.setups != 1:
        parser.error("clear/smoke use one setup; use benchmark for repeated fresh setups")
    binary = (args.binary or (args.build_dir or HERE / "build") / "openfhe_matched_w0").resolve(strict=True)
    check_sources()
    allowed = os.sched_getaffinity(0)
    cpu = min(allowed) if args.cpu is None else args.cpu
    if cpu not in allowed:
        parser.error(f"CPU {cpu} is not in allowed affinity {sorted(allowed)}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    for key in ["OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"]:
        env[key] = "1"
    selected = {"summed": "summed-bgv", "terminal": "terminal-bgv"}.get(args.profile, args.profile)
    profiles = ["summed-bgv", "terminal-bgv"] if selected == "all" else [selected]
    jobs, length, batches = (4, 16, 1) if args.mode == "smoke" else (16, 256, 2 if args.mode == "benchmark" else 1)
    source_hashes = {p.relative_to(HERE).as_posix(): digest(p) for p in
                     [HERE / "run.py", HERE / "CMakeLists.txt", *sorted((HERE / "profiles").glob("*.json"))]}
    save(output / "start.json", dict(started_utc=datetime.now(timezone.utc).isoformat(),
         platform=platform.platform(), python=sys.version, binary=str(binary), binary_sha256=digest(binary),
         mode=args.mode, profiles=profiles, setups=args.setups, cpu=cpu, jobs=jobs, length=length,
         declared_openfhe_commit=PIN, declared_commit_is_not_runtime_attestation=True,
         source_hashes=source_hashes, fresh_encrypted_execution=args.mode != "clear"))
    observations = []
    try:
        for setup in range(args.setups):
            # Reversal limits a fixed ordering bias; observations remain serial
            # and are not the paper's original four-arm campaign.
            order = profiles if setup % 2 == 0 else list(reversed(profiles))
            for name in order:
                profile = json.loads((HERE / "profiles" / f"{name}.json").read_text(encoding="utf-8"))
                c = profile["arguments"]
                command = [str(binary), "--mode", "clear" if args.mode == "clear" else "sample",
                           "--arm", c["arm"], "--scheme", c["scheme"], "--ring-dim", str(c["ring_dimension"]),
                           "--baby-width", str(min(c["baby_width"], length)), "--bfv-key-switch", c["bfv_key_switch"],
                           "--jobs", str(jobs), "--length", str(length), "--batches", str(batches)]
                stem = f"setup-{setup:03d}-{name}"
                save(output / f"{stem}-command.json", dict(command=command, cpu=cpu, timeout=args.timeout))
                print(f"Starting {name}, {args.mode}, setup {setup}", flush=True)
                start = time.monotonic()
                with (output / f"{stem}.stdout.json").open("xb") as stdout, (output / f"{stem}.stderr.txt").open("xb") as stderr:
                    completed = subprocess.run(command, env=env, stdout=stdout, stderr=stderr,
                                               timeout=args.timeout, preexec_fn=lambda: os.sched_setaffinity(0, {cpu}))
                if completed.returncode:
                    raise ValueError(f"{stem} exited with {completed.returncode}; logs retained")
                result = json.loads((output / f"{stem}.stdout.json").read_text(encoding="utf-8"))
                symbols = validate(result, profile, jobs, length, args.mode)
                receipt = dict(profile=name, setup=setup, checked_symbols=symbols,
                               subprocess_wall_seconds=time.monotonic()-start,
                               output_sha256=digest(output / f"{stem}.stdout.json"))
                if args.mode == "benchmark":
                    cold, warm = result["batches"]
                    receipt.update(warm_seconds=warm["batch_wall_seconds"],
                                   first_use_seconds=sum(result["setup_seconds"].values())+cold["batch_wall_seconds"],
                                   setup_wall_seconds=result["setup_wall_seconds"])
                observations.append(receipt)
                print(f"PASS {name}: {symbols} recovered symbols checked", flush=True)
        summary = dict(status="PASS", mode=args.mode, observations=observations,
                       uses_full_paper_workload_and_selected_profiles=args.mode == "benchmark",
                       reproduces_original_machine_or_campaign=False, security_certified=False)
        if args.mode == "benchmark":
            summary["medians"] = {name: {field: statistics.median(r[field] for r in observations if r["profile"] == name)
                                         for field in ["warm_seconds", "first_use_seconds"]} for name in profiles}
        save(output / "summary.json", summary)
    except BaseException as exc:
        save(output / "failure.json", dict(status="FAIL", error=repr(exc), observations=observations))
        raise


if __name__ == "__main__":
    main()
