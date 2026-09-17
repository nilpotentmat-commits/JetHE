"""V4 legal native small-prime terminal delivery and explicit noise rejections.

No timing/sample mode is accepted. Receipts include public fixture outputs only.
"""
import ast
import fcntl
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import signal
import subprocess
import sys
import time

from core_grid_fixture import CELLS, inputs, metadata, oracle_states
from core_terminal_codec import AdditiveCRT
from supervise_core_conventional_v2 import check_directory

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
ROOT = PAPER.parent
BINARY = PAPER / "build/helib-terminal-core-v3/helib_terminal_core"
PROTOCOL = HERE / "CORE_CONVENTIONAL_GATE_V4.md"
PREFIX = "core-conventional-v4-"
LIMITS = dict(address_space_bytes=2*2**30, cpu_seconds=180, wall_seconds=210,
              combined_pipe_bytes=8*2**20, individual_file_bytes=8*2**20,
              threads=1, core_dump_bytes=0, campaign_worker_seconds=3600,
              campaign_receipt_bytes=2**30)
CONDUCTORS = {4369: (4096, 256), 13107: (8192, 512),
              21845: (16384, 1024), 65535: (32768, 2048)}
BIT_REQUESTS = (20, 60, 120, 180, 240)


def path_name(path):
    path = path.resolve()
    return path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)


def dynamic_dependencies():
    process = subprocess.run(["/usr/bin/ldd", str(BINARY)], capture_output=True, text=True, timeout=15, check=True)
    assert "not found" not in process.stdout
    paths = set()
    for line in process.stdout.splitlines():
        found = re.search(r"(?:=>\s+)?(/\S+)\s+\(", line)
        if found:
            paths.add(Path(found.group(1)).resolve())
    assert paths, "No dynamic dependencies found"
    return sorted(paths), process.stdout


def manifest():
    pending = [Path(__file__)]
    paths = set()
    while pending:
        path = pending.pop().resolve()
        if path in paths:
            continue
        paths.add(path)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = ([node.module] if isinstance(node, ast.ImportFrom) else
                     [a.name for a in node.names] if isinstance(node, ast.Import) else [])
            for name in names:
                if name:
                    local = HERE / (name.split(".")[0]+".py")
                    if local.is_file() and local.resolve() not in paths:
                        pending.append(local)
    paths.update([PROTOCOL, HERE / "CORE_GRID_V1_DESIGN.md", HERE / "CORE_GRID_V1_GATE_PROTOCOL.md",
        HERE / "CORE_CONVENTIONAL_ADAPTER_V1.md", BINARY,
        HERE / "helib_composition/core/core_math.h", HERE / "helib_composition/core/terminal_core.cpp", HERE / "helib_composition/core/terminal_core_v2.cpp", HERE / "helib_composition/core/terminal_core_v3.cpp",
        HERE / "helib_composition/core/natural_terminal/CMakeLists.txt",
        HERE / "CORE_CONVENTIONAL_GATE_V1.md", HERE / "CORE_CONVENTIONAL_GATE_V2.md", HERE / "CORE_CONVENTIONAL_GATE_V3.md",
        PAPER / "build/helib-terminal-core-v3/CMakeCache.txt", PAPER / "build/helib-terminal-core-v3/build.ninja",
        ROOT / "Code/build-helib-2.3.0/install/lib/libhelib.a"])
    backend = ROOT / "Code/third_party/helib-2.3.0"
    paths.update(backend / p for p in ("src/Ctxt.cpp", "src/keys.cpp", "src/EncryptedArray.cpp",
        "src/DoubleCRT.cpp", "src/JsonWrapper.cpp", "src/log.cpp", "src/Context.cpp", "include/helib/Context.h", "include/helib/log.h", "include/helib/Ctxt.h",
        "include/helib/keys.h", "include/helib/JsonWrapper.h", "dependencies/json/json.hpp"))
    dependencies, _ = dynamic_dependencies()
    paths.update(dependencies)
    return {path_name(p): sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def fnv(values):
    h = 14695981039346656037
    for value in values:
        for shift in (0, 8):
            h = ((h ^ ((value >> shift) & 255)) * 1099511628211) & ((1 << 64)-1)
    return str(h)


def validate_codec(result):
    assert result["status"] == "CORE_CONVENTIONAL_CODEC_PASS"
    assert [r["points"] for r in result["tests"]] == [2, 4, 16, 32, 512, 2048]
    assert all(r["points"] == r["complete_horner_points"] == r["roundtrip_coefficients"] for r in result["tests"])
    assert [r["cell"] for r in result["fixtures"]] == list(CELLS)
    for row in result["fixtures"]:
        cell = row["cell"]
        family, length, jobs = CELLS[cell]
        values = inputs(cell)
        assert row["input_fnv64"] == metadata(cell, values)["fnv64"]
        _, expected = oracle_states(cell, values)
        assert row["recovered_public_fixture_symbols"] == list(expected)
        degree = (8 if family == "W2-deep" else 2)*(length-1)
        codec = AdditiveCRT(degree.bit_length())
        hashes = []
        for owner in values.values():
            forward = [x for job in range(jobs) for x in codec.forward(owner[job*length:(job+1)*length])]
            hashes.append(fnv(forward))
        assert row["forward_fnv64"] == hashes
    assert not result["encrypted_execution"] and not result["benchmark"] and not result["security_128_qualified"]


def validate_result(result, mode, arm=None, cell=None, m=None, bits=None, policy=None):
    if mode == "public-codec":
        validate_codec(result)
        return "PASS"
    if result.get("status") == "CORE_CONVENTIONAL_NOISE_REJECT":
        assert mode == "gate" and result["reason"] == "HElib public noise admission rejected before decryption"
        assert result["encrypted_execution"] and not result["full_output_verified"]
        assert not result["benchmark"] and not result["security_128_qualified"]
        return "REJECT"
    profile = result["profile"]
    dimension, slots = CONDUCTORS[m]
    assert (profile["m"], profile["dimension"], profile["slots"], profile["field_degree"],
            profile["requested_bits"], profile["compiler"]) == (m, dimension, slots, 16, bits, arm)
    assert profile["field_polynomial"] == "0x1100b" and profile["sk_hwt"] == 0
    assert profile["requested_digits"] == 2 and profile["ciphertext_primes"]
    assert all(row for row in profile["actual_digit_prime_indices"])
    assert not profile["security_128_qualified"] and not result["security_128_qualified"] and not result["benchmark"]
    q = math.prod(map(int, profile["ciphertext_primes"]))
    q_heuristic = max(0.0, 3.8*dimension/(math.log2(q)-math.log2(profile["adjusted_library_stdev"]))-20)
    assert math.isclose(q_heuristic, profile["published_q_library_heuristic_NOT_CERTIFICATION"], rel_tol=1e-12)
    no_keys = arm == "crt" and policy in ("raw", "nn")
    expected_screen = q_heuristic if no_keys else profile["library_security_estimate_NOT_CERTIFICATION"]
    assert profile["screen_modulus"] == ("Q" if no_keys else "QP")
    assert math.isclose(profile["effective_library_heuristic_NOT_CERTIFICATION"], expected_screen, rel_tol=1e-12)
    assert profile["effective_library_128_screen"] == (expected_screen >= 128)
    if mode == "profile":
        assert result["status"] == "CORE_CONVENTIONAL_PROFILE_PASS"
        assert result["checks"] == dict(roundtrips=2, field_products_checked=slots,
                                         polynomial_automorphisms_checked=15 if arm == "b16" else 0)
        assert not result["encrypted_execution"] and result["keys_generated"] == 0
        return "PASS"
    assert mode == "gate" and result["status"] in ("CORE_CONVENTIONAL_GATE_PASS", "CORE_CONVENTIONAL_GATE_REJECT")
    assert profile["effective_library_128_screen"] and profile["effective_library_heuristic_NOT_CERTIFICATION"] >= 128
    assert (result["cell"], result["compiler"], result["policy"]) == (cell, arm, policy)
    assert result["encrypted_execution"] and not result["bootstrapping"] and not result["process_isolation"]
    assert not result["secret_keys_exported"] and not result["phase_diagnostics_exported"]
    assert "setup_seconds" not in result and len(result["batches"]) == 2
    assert result["fixture_fnv64"] == metadata(cell)["fnv64"]
    _, expected = oracle_states(cell)
    family, length, jobs = CELLS[cell]
    k = 1 << ((8 if family == "W2-deep" else 2)*(length-1)).bit_length()
    groups = (jobs*k+slots-1)//slots if arm == "crt" else 8
    first, second = (policy[0] == "y", policy[1] == "y") if family == "W2-deep" else (False, False)
    parts = (3 if second else 5 if first else 9) if family == "W2-deep" else 3
    products = groups*(7 if family == "W2-deep" else 1) if arm == "crt" else 2048
    expected_inputs = groups*(12 if family == "W2-deep" else 3 if family == "W2-shallow" else 2) if arm == "crt" else 2176
    adds = groups*(4 if family == "W2-deep" else 1 if family == "W2-shallow" else 0) if arm == "crt" else 2040
    relins = groups*(4*first+2*second) if arm == "crt" else 120
    per_component = (16+2*(2 if first else 3)**2+(2 if second else 3 if first else 5)**2) if family == "W2-deep" else 4
    component_products = groups*per_component if arm == "crt" else 8192
    switched = groups*(4*first+2*second*(1 if first else 3)) if arm == "crt" else 120
    expected_matrices = {(2, 1)} if first or second or arm == "b16" else set()
    if second and not first:
        expected_matrices.update({(3, 1), (4, 1)})
    if arm == "b16":
        expected_matrices.update((1, pow(4627, -v, 13107)) for v in range(1, 16))
        assert profile["generators"] == [4627, 12853] and profile["orders"] == [16, 32]
    actual = {(r["power_of_s"], r["power_of_x"]) for r in result["switching_matrices"]}
    assert len(actual) == len(result["switching_matrices"]) and actual == expected_matrices
    accepted = True
    for index, batch in enumerate(result["batches"]):
        assert batch["index"] == index and "seconds" not in batch and "batch_wall_seconds" not in batch
        assert (batch["encryptions"], batch["products"], batch["component_products"], batch["additions"],
                batch["relinearizations"], batch["switched_parts"], batch["rotations"]) == (
                    expected_inputs, products, component_products, adds, relins, switched, 0 if arm == "crt" else 120)
        assert len(batch["output_profiles"]) == groups
        assert batch["terminal_slots_checked"] == groups*slots
        actual_match = batch["recovered_public_fixture_symbols"] == list(expected)
        if batch["all_outputs_match"]:
            assert actual_match
        elif actual_match:
            # A padding/evaluation/degree mismatch may exist despite requested outputs matching.
            assert arm == "crt"
        assert batch["structural_handle_checkpoints"] >= groups
        for row in batch["checkpoints"]:
            if "actual_handles" in row:
                assert sorted(h[0] for h in row["actual_handles"]) == list(range(row["expected_parts"]))
                assert all(h[1:] == [1, 0] for h in row["actual_handles"] if h[0])
        for row in batch["output_profiles"]:
            assert row["parts"] == parts and row["prime_indices"]
        margin = all(row["bit_capacity"] >= 10 and row["library_is_correct"] for row in batch["output_profiles"])
        assert margin == batch["terminal_capacity_gate"]
        admitted = batch["all_outputs_match"] and margin and batch["all_observed_library_correct"]
        assert admitted == batch["functional_admitted"]
        accepted &= admitted
    assert accepted == (result["status"] == "CORE_CONVENTIONAL_GATE_PASS")
    return "PASS" if accepted else "REJECT"


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
        assert mode in ("profile", "gate") and arm in ("crt", "b16") and cell in CELLS
        assert m in CONDUCTORS and bits in BIT_REQUESTS
        if arm == "b16":
            assert cell == "w1-l256-j16" and m == 13107 and policy == "raw"
        else:
            assert policy in (("nn", "ny", "yn", "yy") if CELLS[cell][0] == "W2-deep" else ("raw",))
        label = f"{mode}-{arm}-{cell}-m{m}-b{bits}-{policy}"
    destination = PAPER / "evidence" / (PREFIX+label+".json")
    assert not destination.exists(), "Never overwrite a public/gate receipt"
    work_root = PAPER / "build/core-conventional-gate-v4"
    work_root.mkdir(exist_ok=True)
    lock = (work_root / "campaign.lock").open("a+")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    existing = [p for version in (1, 2, 3, 4) for p in (PAPER / "evidence").glob(f"core-conventional-v{version}-*.json")]
    prior_seconds = sum(json.loads(p.read_text())["worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY"] for p in existing)
    assert prior_seconds+LIMITS["wall_seconds"] <= LIMITS["campaign_worker_seconds"], "Campaign time cap"
    assert sum(p.stat().st_size for p in existing) < LIMITS["campaign_receipt_bytes"]-10*2**20, "Campaign receipt cap"
    if mode == "gate":
        public_path = PAPER / "evidence" / (PREFIX+"public-codec.json")
        assert json.loads(public_path.read_text())["status"] == "PASS", "Missing public codec prerequisite"
        carrier_cell = "w1-l256-j16" if arm == "b16" else "w1-l16-j16"
        public_profile = PAPER / "evidence" / (PREFIX+f"profile-{arm}-{carrier_cell}-m{m}-b{bits}-raw.json")
        record = json.loads(public_profile.read_text())
        assert record["status"] == "PASS", "Missing public profile"
        field = "published_q_library_heuristic_NOT_CERTIFICATION" if arm == "crt" and policy in ("raw", "nn") else "library_security_estimate_NOT_CERTIFICATION"
        assert record["result"]["profile"][field] >= 128, "Ineligible actual-public-modulus screen"
    work = work_root / label
    work.mkdir(exist_ok=False)
    before = manifest()
    dependencies, ldd_output = dynamic_dependencies()
    del dependencies
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
        status = validate_result(result, mode, arm, cell, m, bits, policy)
        if result.get("status") == "CORE_CONVENTIONAL_NOISE_REJECT":
            assert any(row.get("event") == "public_noise_admission_rejection" and row.get("library_is_correct") is False for row in events)
            setup = next(row for row in events if row.get("event") == "core_setup_complete")
            assert setup["profile"]["m"] == m and setup["profile"]["requested_bits"] == bits
            assert setup["profile"]["effective_library_128_screen"]
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
    receipt = dict(schema="core-conventional-functional-v4", status=status, label=label, mode=mode,
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
