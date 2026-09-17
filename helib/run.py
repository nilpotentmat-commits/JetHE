"""Portable launcher for unchanged supplementary HElib workers."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, time

ROOT = Path(__file__).resolve().parents[1]

if not __debug__:
    raise SystemExit("Run without Python -O/-OO: output verification requires assertions.")

def main():
    profiles = json.loads((ROOT / "helib/profiles.json").read_text(encoding="utf-8"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/helib")
    parser.add_argument("--profile", choices=sorted(profiles))
    parser.add_argument("--setups", type=int, default=1)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if args.list:
        print(json.dumps(profiles, indent=2)); return
    if args.profile is None or args.output is None or args.setups < 1:
        parser.error("--profile, --output and positive --setups are required")
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    config = profiles[args.profile]
    binary = (args.build_dir / config["binary"]).resolve()
    if not binary.is_file(): parser.error("Build the HElib targets first: " + str(binary))
    env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1")
    affinity = None
    if hasattr(os, "sched_getaffinity"):
        affinity = min(os.sched_getaffinity(0)); os.sched_setaffinity(0, {affinity})
    results = []
    for setup in range(args.setups):
        started = time.perf_counter()
        try:
            worker = subprocess.run([str(binary), *config["arguments"]], capture_output=True, text=True, env=env, timeout=args.timeout)
            (output / f"setup-{setup:03d}.stdout.txt").write_text(worker.stdout, encoding="utf-8")
            (output / f"setup-{setup:03d}.stderr.txt").write_text(worker.stderr, encoding="utf-8")
            records = [json.loads(line) for line in worker.stdout.splitlines() if line.startswith("{")]
            final = records[-1] if records else {}
            good = worker.returncode == 0 and final.get("status") in {"SLACK_SAMPLE_PASS", "CORE_MATCHED_PASS"}
            if good and args.profile.startswith("composition-"):
                expected = (ROOT / "recorded/expected-output.bin").read_bytes()
                for batch in final["batches"]:
                    actual = b"".join(int(v).to_bytes(2, "little") for v in batch["recovered_public_fixture_symbols"])
                    assert actual == expected, "Full composition output mismatch"
            result = {"setup": setup, "status": "PASS" if good else "FAILED", "exit_code": worker.returncode,
                "profile": args.profile, "cpu": affinity, "process_wall_seconds_diagnostic": time.perf_counter()-started,
                "worker": final, "fresh_HE_execution": True}
        except subprocess.TimeoutExpired:
            result = {"setup": setup, "status": "TIMEOUT", "profile": args.profile, "fresh_HE_execution": True}
        (output / f"setup-{setup:03d}.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
        results.append(result)
        if result["status"] != "PASS": break
    summary = {"status": "PASS" if len(results)==args.setups and all(r["status"]=="PASS" for r in results) else "FAILED",
        "profile": args.profile, "completed_setups": len(results), "requested_setups": args.setups,
        "fresh_HE_execution": True, "published_measurement_replacement": False}
    (output / "summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if summary["status"] != "PASS": sys.exit(1)

if __name__ == "__main__": main()
