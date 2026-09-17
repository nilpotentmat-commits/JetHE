"""Bounded, pinned heuristic screens of explicitly named leaf row games.

No HE keys or ciphertexts are generated. One scalar sample per independent
zero-payload ring row is an exact marginal; treating every coefficient equation
as independent LWE is a separately labelled heuristic relaxation. Neither is a
security certificate or an attack on the actual shifted hint transcript.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / "Code/experiments/full_jet_refresh/third_party/mlwe-hybrids/PrimalHybrid/lattice_estimator"
SAGE_PREFIX = ROOT / "Code/.research-envs/sage-10.5"
PIN = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"
PROFILES = {
    f"leaf{n}-{mode}": {
        "n": n, "q": str(2**127 - 1), "ring_rows": rows,
        "scalar_samples": rows if mode == "independent" else n * rows,
        "sample_interpretation": (
            "exact one-coordinate marginal of the zero-payload row game"
            if mode == "independent" else
            "heuristic independent-LWE substitution for all correlated ring equations"
        ),
        "secret_law": "iid Uniform{-1,0,1} in displayed tensor normal basis",
        "error_law": "iid CBD20 = Binomial(40,1/2)-20; normalized row error eta",
        "actual_shifted_hint_attack": False,
    }
    for n, rows in ((4096, 513), (8192, 1025))
    for mode in ("independent", "all-equations")
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def linux_path(path):
    path = Path(path).resolve()
    if len(path.drive) != 2 or path.drive[1] != ":":
        raise ValueError("expected an absolute Windows drive path")
    return "/mnt/" + path.drive[0].lower() + path.as_posix()[2:]


def git_read(*args):
    resolved = UPSTREAM.resolve()
    return subprocess.check_output(
        ["git", "-c", "safe.directory=" + resolved.as_posix(), "-C", str(resolved), *args],
        text=True,
    ).strip()


def worker(args):
    # GNU timeout controls wall time; this caps virtual address space before
    # importing Sage. Thread pools are separately capped by the coordinator.
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    output = Path(args.output).resolve()
    plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
    if digest(__file__) != plan["driver_sha256"]:
        raise ValueError("driver changed after the plan was frozen")
    for relative, expected in plan["source_files"].items():
        if digest(UPSTREAM / relative) != expected:
            raise ValueError("pinned estimator source changed: " + relative)
    sys.path.insert(0, str(UPSTREAM))
    import sage.all
    import sage.version
    from estimator import LWE, ND
    from estimator.reduction import RC

    p = plan["profiles"][args.profile]
    parameters = LWE.Parameters(
        n=p["n"], q=int(p["q"]), m=p["scalar_samples"],
        Xs=ND.UniformMod(3), Xe=ND.CenteredBinomial(20), tag=args.profile,
    )
    result = {
        "profile": args.profile, "parameters": p, "sage_version": sage.version.version,
        "estimator_commit": PIN, "attack": args.attack, "status": "ERROR",
        "security_128_qualified": False, "estimates": [],
    }
    started = time.monotonic()
    try:
        attacks = {
            "usvp": LWE.primal_usvp,
            "bdd": LWE.primal_bdd,
            "dual-hybrid": LWE.dual_hybrid,
        }
        for model_name, model in (("MATZOV", RC.MATZOV), ("ADPS16-classical-core-SVP", RC.ADPS16)):
            call_start = time.monotonic()
            cost = attacks[args.attack](parameters, red_cost_model=model)
            value = cost.get("rop", sage.all.oo)
            finite = value > 0 and value < sage.all.oo
            row = {
                "cost_model": model_name, "shape_model": "GSA/default pinned attack model",
                "log2_rop": float(sage.all.log(value, 2)) if finite else None,
                "raw_cost": {str(k): str(v) for k, v in cost.items()},
                "finite": bool(finite), "seconds": time.monotonic() - call_start,
            }
            result["estimates"].append(row)
            print(json.dumps({"profile": args.profile, "attack": args.attack, **row}), flush=True)
        result["status"] = "ESTIMATES_RECORDED"
    except Exception:
        result["error"] = traceback.format_exc()
    result["seconds"] = time.monotonic() - started
    write_new(output / (args.profile + ".json"), result)
    return 0 if result["status"] == "ESTIMATES_RECORDED" else 1


def coordinator(args):
    output = Path(args.output).resolve()
    if not output.is_relative_to((ROOT / "SubmissionA/evidence").resolve()):
        raise ValueError("screens must stay in SubmissionA/evidence")
    if git_read("rev-parse", "HEAD") != PIN:
        raise ValueError("wrong estimator commit")
    if git_read("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("modified pinned estimator")
    if any(Path(p).suffix == ".py" for p in git_read("ls-files", "--others", "--exclude-standard").splitlines()):
        raise ValueError("untracked importable estimator source")
    selected = {name: PROFILES[name] for name in args.profiles}
    sources = {str(p.relative_to(UPSTREAM)).replace("\\", "/"): digest(p)
               for p in sorted((UPSTREAM / "estimator").rglob("*.py"))}
    output.mkdir(parents=True, exist_ok=False)
    for name in ("sage-user", "cache", "matplotlib", "tmp"):
        (output / name).mkdir()
    plan = {
        "schema": "submission-a-leaf-game-screen-v1", "profiles": selected,
        "attack": args.attack, "estimator_commit": PIN, "source_files": sources,
        "driver_sha256": digest(__file__), "seconds_per_worker": args.timeout,
        "threads": 1, "virtual_memory_limit_bytes": 4 * 1024**3,
        "security_128_qualified": False, "encrypted_execution": False,
        "scope": "bounded heuristic attack costs, not a lower bound on all attacks",
    }
    write_new(output / "plan.json", plan)
    completions = []
    for profile in selected:
        command = [
            "wsl", "--distribution", "Ubuntu", "--exec", "env",
            "PATH=" + linux_path(SAGE_PREFIX / "bin") + ":/usr/bin:/bin",
            "CONDA_PREFIX=" + linux_path(SAGE_PREFIX), "OMP_NUM_THREADS=1",
            "OPENBLAS_NUM_THREADS=1", "MKL_NUM_THREADS=1", "PYTHONDONTWRITEBYTECODE=1",
            "DOT_SAGE=" + linux_path(output / "sage-user"),
            "XDG_CACHE_HOME=" + linux_path(output / "cache"),
            "MPLCONFIGDIR=" + linux_path(output / "matplotlib"),
            "TMPDIR=" + linux_path(output / "tmp"),
            "timeout", "--signal=TERM", "--kill-after=5", str(args.timeout),
            linux_path(SAGE_PREFIX / "bin/python"), "-B", linux_path(Path(__file__)),
            "--worker", "--output", linux_path(output), "--profile", profile,
            "--attack", args.attack,
        ]
        write_new(output / (profile + "-command.json"), command)
        started = time.monotonic()
        print("Starting " + profile + " / " + args.attack, flush=True)
        with (output / (profile + "-stdout.txt")).open("xb") as stdout, (output / (profile + "-stderr.txt")).open("xb") as stderr:
            process = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
        completion = {"profile": profile, "exit_code": process.returncode,
                      "seconds": time.monotonic() - started,
                      "result_present": (output / (profile + ".json")).is_file()}
        completions.append(completion)
        print(json.dumps(completion), flush=True)
    write_new(output / "completion.json", {"workers": completions, "security_128_qualified": False})
    return 0 if all(row["exit_code"] == 0 for row in completions) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=list(PROFILES))
    parser.add_argument("--attack", choices=("usvp", "bdd", "dual-hybrid"), default="usvp")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 180:
        parser.error("worker time limit must be between1 and180 seconds")
    return worker(args) if args.worker else coordinator(args)


if __name__ == "__main__":
    raise SystemExit(main())
