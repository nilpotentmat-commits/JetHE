"""V2 containment correction; preserve v1 source, checks, failure and C++ binary."""
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time

import supervise_core_conventional as base

HERE, PAPER, ROOT = base.HERE, base.PAPER, base.ROOT
BINARY, LIMITS = base.BINARY, base.LIMITS
PREFIX = "core-conventional-v2-"


def manifest():
    result = base.manifest()
    for path in (Path(__file__), HERE / "CORE_CONVENTIONAL_GATE_V2.md",
                 ROOT / "Code/third_party/helib-2.3.0/src/log.cpp",
                 ROOT / "Code/third_party/helib-2.3.0/include/helib/log.h"):
        result[base.path_name(path)] = sha256(path.read_bytes()).hexdigest()
    return dict(sorted(result.items()))


def check_directory(work):
    paths = list(work.iterdir())
    assert len(paths) == 1 and paths[0].name == "helib.log", "Unexpected worker-created files"
    path = paths[0]
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size == 0, "Nonempty/nonregular static logger file"
    return [dict(name=path.name, bytes=0, sha256=sha256(path.read_bytes()).hexdigest(),
                 origin="pinned HElib static initialization before main")]


def main():
    assert __debug__, "Assertions are required"
    args = sys.argv[1:]
    if args == ["public-codec"]:
        mode, arm, cell, m, bits, policy = "public-codec", None, None, None, None, None
        label = "public-codec"
    else:
        assert len(args) == 6, "Use MODE ARM CELL M BITS POLICY, or public-codec"
        mode, arm, cell, m_text, bits_text, policy = args
        m, bits = int(m_text), int(bits_text)
        assert mode in ("profile", "gate") and arm in ("crt", "b16") and cell in base.CELLS
        assert m in base.CONDUCTORS and bits in base.BIT_REQUESTS
        if arm == "b16":
            assert cell == "w1-l256-j16" and m == 13107 and policy == "raw"
        else:
            assert policy in (("nn", "ny", "yn", "yy") if base.CELLS[cell][0] == "W2-deep" else ("raw",))
        label = f"{mode}-{arm}-{cell}-m{m}-b{bits}-{policy}"
    destination = PAPER / "evidence" / (PREFIX+label+".json")
    assert not destination.exists(), "Never overwrite a public/gate receipt"
    work_root = PAPER / "build/core-conventional-gate-v2"
    work_root.mkdir(exist_ok=True)
    # Common v1/v2 lock, held for the complete worker and validation lifecycle.
    lock_root = PAPER / "build/core-conventional-gate-v1"
    lock_root.mkdir(exist_ok=True)
    lock = (lock_root / "campaign.lock").open("a+")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    existing = [p for version in (1, 2) for p in (PAPER / "evidence").glob(f"core-conventional-v{version}-*.json")]
    prior_seconds = sum(json.loads(p.read_text())["worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY"] for p in existing)
    assert prior_seconds+LIMITS["wall_seconds"] <= LIMITS["campaign_worker_seconds"], "Campaign time cap"
    assert sum(p.stat().st_size for p in existing) < LIMITS["campaign_receipt_bytes"]-10*2**20, "Campaign receipt cap"
    before = manifest()
    if mode == "gate":
        codec = json.loads((PAPER / "evidence" / (PREFIX+"public-codec.json")).read_text())
        assert codec["status"] == "PASS" and codec["source_manifest"] == before, "Missing/current codec prerequisite"
        carrier_cell = "w1-l256-j16" if arm == "b16" else "w1-l16-j16"
        public_profile = PAPER / "evidence" / (PREFIX+f"profile-{arm}-{carrier_cell}-m{m}-b{bits}-raw.json")
        record = json.loads(public_profile.read_text())
        assert record["source_manifest"] == before, "Public profile source mismatch"
        assert record["status"] == "PASS" and record["result"]["profile"]["library_128_screen"], "Missing eligible public profile"
    work = work_root / label
    work.mkdir(exist_ok=False)
    _, ldd_output = base.dynamic_dependencies()
    cpu = min(os.sched_getaffinity(0))
    command = [str(BINARY), *args]
    env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1",
               NUMEXPR_NUM_THREADS="1", PYTHONDONTWRITEBYTECODE="1")

    def limits():
        os.sched_setaffinity(0, {cpu})
        for kind, amount in ((resource.RLIMIT_AS, LIMITS["address_space_bytes"]),
                             (resource.RLIMIT_CPU, LIMITS["cpu_seconds"]),
                             (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, LIMITS["individual_file_bytes"])):
            resource.setrlimit(kind, (amount, amount))

    capture = [bytearray(), bytearray()]
    selector = selectors.DefaultSelector()
    error = result = after = None
    events, files = [], []
    status = "ERROR"
    started = time.monotonic()
    child = subprocess.Popen(command, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True, preexec_fn=limits, close_fds=True)
    selector.register(child.stdout, selectors.EVENT_READ, 0)
    selector.register(child.stderr, selectors.EVENT_READ, 1)
    deadline = started+LIMITS["wall_seconds"]
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("Conventional core wall limit")
            for key, _ in selector.select(timeout=min(1, max(0, deadline-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if sum(map(len, capture))+len(chunk) > LIMITS["combined_pipe_bytes"]:
                    raise RuntimeError("Conventional pipe-output limit")
                capture[key.data].extend(chunk)
        code = child.wait(timeout=max(0.01, deadline-time.monotonic()))
        worker_elapsed = time.monotonic()-started
        rows = [json.loads(line) for line in capture[0].decode().splitlines() if line.strip()]
        assert rows, "Missing worker result"
        result, events = rows[-1], rows[:-1]
        assert code in (0, 2), f"Worker exit {code}"
        status = base.validate_result(result, mode, arm, cell, m, bits, policy)
        assert code == (2 if status == "REJECT" else 0)
        after = manifest()
        assert before == after, "Source/binary drift during worker"
        files = check_directory(work)
    except Exception as exc:
        worker_elapsed = time.monotonic()-started
        error = f"{type(exc).__name__}: {exc}"
        status = "ERROR"
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
        after = manifest()
    cpu_model = next((s.split(":", 1)[1].strip() for s in Path("/proc/cpuinfo").read_text().splitlines()
                      if s.startswith("model name")), "unavailable")
    receipt = dict(schema="core-conventional-functional-v2", status=status, label=label, mode=mode,
        arguments=args, limits=LIMITS, affinity_cpu=cpu, command=command,
        host=dict(kernel=platform.release(), machine=platform.machine(), cpu_model=cpu_model, python=sys.version),
        dynamic_linker_report=ldd_output, worker_cwd=work.relative_to(ROOT).as_posix(), worker_files=files,
        source_manifest=before, sources_unchanged=before == after, worker_exit_code=code,
        worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY=worker_elapsed,
        stdout_bytes=len(capture[0]), stderr=capture[1].decode(errors="replace"),
        events=events, result=result, error=error, benchmark=False, security_128_qualified=False)
    if error:
        receipt["failed_stdout"] = capture[0].decode(errors="replace")
    encoded = json.dumps(receipt, indent=2)+"\n"
    assert len(encoded.encode()) < 10*2**20
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(encoded)
    print(json.dumps(dict(status=status, receipt=destination.relative_to(ROOT).as_posix(),
        receipt_sha256=sha256(destination.read_bytes()).hexdigest(), error=error,
        worker_seconds_LIMIT_ONLY=worker_elapsed, benchmark=False, security_128_qualified=False)), flush=True)
    if status == "ERROR":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
