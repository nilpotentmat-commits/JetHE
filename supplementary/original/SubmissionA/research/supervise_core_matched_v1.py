"""Bounded, immutable, two-batch matched timing workers; no parameter tuning."""
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

from core_grid_fixture import CELLS, metadata, oracle_states
from core_native_execution import coin_budget
from check_composition_rns_arithmetic import CERTIFICATES
from check_core_conventional_execution import reviewed_warnings
from supervise_core_conventional_v2 import check_directory

HERE = Path(__file__).resolve().parent
PAPER, ROOT = HERE.parent, HERE.parent.parent
BINARY = PAPER / "build/helib-core-matched-v1/helib_core_matched"
PREFIX = "core-matched-v1-"
PROTOCOL = HERE / "CORE_GRID_MATCHED_TIMING_V1.md"
LIMITS = dict(address_space_bytes=2*2**30, cpu_seconds=180, wall_seconds=210,
    combined_pipe_bytes=8*2**20, individual_file_bytes=8*2**20, core_dump_bytes=0,
    threads=1, campaign_workers=120, campaign_worker_seconds=7200, campaign_receipt_bytes=512*2**20)
READBACKS = [PAPER / "evidence" / name for name in (
    "core-native-encrypted-readback-v1.json", "core-conventional-encrypted-readback-v1.json")]


def name(path):
    path = path.resolve()
    return path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)


def prerequisites():
    records, hashes = [], {}
    for path in READBACKS:
        record = json.loads(path.read_text())
        assert record["status"] == "PASS" and not record["benchmark"] and not record["security_128_qualified"]
        for relative, digest in record["sources_sha256"].items():
            source = (ROOT / relative).resolve()
            assert sha256(source.read_bytes()).hexdigest() == digest, relative
            if name(source) in hashes:
                assert hashes[name(source)] == digest
            hashes[name(source)] = digest
        hashes[name(path)] = sha256(path.read_bytes()).hexdigest()
        records.append(record)
    assert records[0]["encrypted_worker_processes"] == 6
    assert records[1]["full_core_fixtures"] == 6 and records[1]["required_w1_alternative_anchor"]
    return records, hashes


def catalog():
    records, _ = prerequisites()
    conventional = records[1]["admitted_batched_candidates"]+records[1]["admitted_single_job_candidates"]
    result = []
    for cell in CELLS:
        result.append(dict(id="native-"+cell, compiler="native", cell=cell,
            gate_receipt=f"SubmissionA/evidence/core-native-gate-v1-{cell}.json"))
        rows = [r for r in conventional if r["cell"] == cell]
        rows.sort(key=lambda r:(r["compiler"] == "b16", r["m"],
            ("raw", "nn", "ny", "yn", "yy").index(r["policy"])))
        for row in rows:
            result.append(dict(id=f'{row["compiler"]}-{cell}-m{row["m"]}-b{row["requested_bits"]}-{row["policy"]}',
                compiler=row["compiler"], cell=cell, m=row["m"], requested_bits=row["requested_bits"],
                policy=row["policy"], gate_receipt=row["receipt"]))
    assert len(result) == 38 and len({r["id"] for r in result}) == len(result)
    return result


def schedule():
    profiles, out = catalog(), []
    for repetition in range(3):
        for cell in CELLS:
            rows = [r for r in profiles if r["cell"] == cell]
            if repetition % 2:
                rows.reverse()
            offset = len(out)
            out.extend(dict(index=offset+i, repetition=repetition, config=row) for i,row in enumerate(rows))
    assert len(out) == 114
    assert [r["index"] for r in out] == list(range(114))
    return out


def dependencies():
    paths, reports = set(), {}
    for binary in (BINARY, PAPER / "build/composition_optimized_core.so", Path(sys.executable)):
        r = subprocess.run(["/usr/bin/ldd", str(binary)], capture_output=True, text=True, check=True, timeout=15)
        assert "not found" not in r.stdout
        reports[name(binary)] = r.stdout
        paths.add(binary.resolve())
        for line in r.stdout.splitlines():
            match = re.search(r"(?:=>\s+)?(/\S+)\s+\(", line)
            if match:
                paths.add(Path(match[1]).resolve())
    return paths, reports


def manifest():
    _, hashes = prerequisites()
    pending = [Path(__file__), HERE / "core_native_measure.py", HERE / "run_core_matched_campaign_v1.py"]
    files = set()
    while pending:
        path = pending.pop().resolve()
        if path in files:
            continue
        files.add(path)
        for node in ast.walk(ast.parse(path.read_text())):
            modules = ([node.module] if isinstance(node, ast.ImportFrom) else
                       [a.name for a in node.names] if isinstance(node, ast.Import) else [])
            for module in modules:
                if module:
                    local = HERE / (module.split(".")[0]+".py")
                    if local.is_file() and local.resolve() not in files:
                        pending.append(local)
    files.update((PROTOCOL, HERE / "helib_composition/core/core_measure.cpp",
        HERE / "helib_composition/core/matched/CMakeLists.txt", BINARY,
        PAPER / "build/helib-core-matched-v1/CMakeCache.txt", PAPER / "build/helib-core-matched-v1/build.ninja"))
    runtime, _ = dependencies()
    files.update(runtime)
    for path in files:
        digest = sha256(path.read_bytes()).hexdigest()
        if name(path) in hashes:
            assert hashes[name(path)] == digest
        hashes[name(path)] = digest
    return dict(sorted(hashes.items()))


def receipt_path(item):
    return PAPER / "evidence" / f'{PREFIX}r{item["repetition"]}-{item["config"]["id"]}.json'


def expected_native_wire(profile):
    n, a = profile["dimension"], profile["chain"][0]
    common = dict(format="JetHE-core-RNS-NTT-uint64le-v1", dimension=n,
                  length=profile["length"], primes=[r[0] for r in CERTIFICATES[:a]])

    def size(meta, parts, limbs):
        return 8+len(json.dumps(meta, sort_keys=True, separators=(",", ":")).encode())+parts*(8+8*n*limbs)

    def cipher(key, limbs, parts):
        return size(dict(common, type="cipher", key=key, limbs=limbs, components=parts), parts, limbs)

    fresh = cipher("s0", a, 2)
    public = fresh
    for level in profile["levels"]:
        if not level["rekey"]:
            continue
        i, limbs = level["level"], level["limbs"]
        # Width48 and these exact prefixes require limbs+1 balanced digits.
        q = math.prod(r[0] for r in CERTIFICATES[:limbs])
        rows = (q.bit_length()+47)//48
        for payload in ("linear", "quadratic"):
            public += size(dict(common, type="bank", source=f"s{i-1}", destination=f"s{i}",
                limbs=limbs, payload=payload, rows=rows), 2*rows, limbs)
    terminal = cipher("s"+str(profile["independent_keys"]-1), profile["chain"][-1], 3)
    return public, fresh*profile["encryptions_per_batch"], terminal


def validate(result, config, events):
    assert result["benchmark"] and not result["security_128_qualified"]
    gate_record = json.loads((ROOT / config["gate_receipt"]).read_text())
    assert gate_record["status"] == "PASS" and gate_record["sources_unchanged"]
    gold = gate_record["result"]
    if result["status"] == "CORE_MATCHED_NOISE_REJECT":
        assert config["compiler"] != "native" and not result["full_output_verified"]
        setup = [r for r in events if r.get("event") == "core_matched_setup_complete"]
        noise = [r for r in events if r.get("event") == "public_noise_admission_rejection"]
        assert len(setup) == 1 and setup[0]["profile"] == gold["profile"]
        assert setup[0]["switching_matrices"] == gold["switching_matrices"]
        assert len(noise) == 1 and not noise[0]["library_is_correct"]
        return "NOISE_REJECT"
    assert result["status"] in ("CORE_MATCHED_PASS", "CORE_MATCHED_REJECT", "CORE_MATCHED_WRONG_OUTPUT")
    assert (result["compiler"], result["cell"], result["profile"]) == (config["compiler"], config["cell"], gold["profile"])
    assert result["encrypted_execution"] and len(result["batches"]) == 2
    for flag in ("bootstrapping", "process_isolation", "secret_keys_exported", "phase_diagnostics_exported",
                 "ciphertext_bodies_exported", "network_transfer_measured"):
        assert result[flag] is False
    assert set(result["setup_seconds"]) == {"public_setup", "keys_and_serialization"}
    assert all(math.isfinite(t) and t > 0 for t in result["setup_seconds"].values())
    assert math.isclose(result["first_use_local_seconds"], sum(result["setup_seconds"].values())+
                        result["batches"][0]["local_compute_seconds"], rel_tol=1e-10)
    assert 0 < result["peak_rss_kib"] < LIMITS["address_space_bytes"]//1024
    _, expected = oracle_states(config["cell"])
    family, length, jobs = CELLS[config["cell"]]
    native = config["compiler"] == "native"
    if native:
        assert result["fixture"] == metadata(config["cell"])
        assert result["coin_budget"] == coin_budget(gold["profile"], batches=2)
        assert result["actual_words_requested"] <= result["coin_budget"]["word_cap"]
        assert result["primitive_error_vectors"] == result["coin_budget"]["error_vectors"]
        wire = expected_native_wire(gold["profile"])
        assert result["public_key_including_hints_bytes_serialized"] == wire[0]
        assert result["raw_public_key_bytes"] == gold["raw_public_key_bytes"]
        assert result["raw_hint_bytes"] == gold["raw_hint_bytes"]
    else:
        assert result["policy"] == config["policy"]
        assert result["fixture_fnv64"] == metadata(config["cell"])["fnv64"]
        assert result["switching_matrices"] == gold["switching_matrices"]
        assert result["profile"]["effective_library_128_screen"]
        assert result["public_key_including_hints_bytes_serialized"] > 0
    admitted = True
    wrong = False
    for index, b in enumerate(result["batches"]):
        assert b["index"] == index
        times, kernels = b["seconds"], b["kernel_seconds"]
        assert all(math.isfinite(t) and t >= 0 for t in (*times.values(), *kernels.values()))
        assert times["evaluation_total"] > 0 and sum(kernels.values()) <= times["evaluation_total"]+1e-6
        assert math.isclose(b["batch_wall_seconds"]-times.get("validation",0), b["local_compute_seconds"], rel_tol=1e-9)
        attributed = sum(v for k,v in times.items() if k != "validation")
        assert b["unallocated_charged_seconds"] >= 0
        assert math.isclose(attributed+b["unallocated_charged_seconds"], b["local_compute_seconds"], rel_tol=1e-9)
        baseline = gold["batches"][index]
        if native:
            assert b["operations"] == baseline["operations"]
            assert b["raw_input_bytes"] == baseline["raw_input_bytes"] and b["raw_output_bytes"] == baseline["raw_output_bytes"]
            assert (b["input_bytes_serialized"], b["output_bytes_serialized"]) == wire[1:]
            for key in ("terminal_key", "terminal_limbs", "terminal_components", "output_symbols"):
                assert b[key] == baseline[key]
            exact = b["output_sha256"] == sha256(expected.tobytes()).hexdigest()
            assert b["prepared_plaintext_cache_bytes"] == gold["profile"]["dimension"]*gold["profile"]["encryptions_per_batch"]
            assert b["all_outputs_match"] == exact
            admitted &= exact
        else:
            for key in ("encryptions", "products", "component_products", "additions", "relinearizations", "switched_parts", "rotations"):
                assert b[key] == baseline[key]
            assert b["structural_handle_checkpoints"] == 0 and b["checkpoints"] == []
            assert len(b["output_profiles"]) == len(baseline["output_profiles"])
            assert b["terminal_slots_checked"] == baseline["terminal_slots_checked"]
            assert b["input_bytes_serialized"] > 0 and b["output_bytes_serialized"] > 0
            for row, original in zip(b["output_profiles"], baseline["output_profiles"]):
                assert row["group"] == original["group"] and row["parts"] == original["parts"] and row["prime_indices"]
            exact = b["recovered_public_fixture_symbols"] == list(expected)
            assert exact or not b["all_outputs_match"]
            margin = all(row["bit_capacity"] >= 10 and row["library_is_correct"] for row in b["output_profiles"])
            assert margin == b["terminal_capacity_gate"]
            accepted = exact and b["all_outputs_match"] and margin and b["all_observed_library_correct"]
            assert accepted == b["functional_admitted"]
            admitted &= accepted
        wrong |= not exact or not b["all_outputs_match"]
    assert admitted == (result["status"] == "CORE_MATCHED_PASS")
    return "PASS" if admitted else "WRONG_OUTPUT" if wrong else "MARGIN_REJECT"


def run(index):
    assert __debug__
    queue = schedule()
    assert 0 <= index < len(queue)
    item, config = queue[index], queue[index]["config"]
    destination = receipt_path(item)
    assert not destination.exists(), "Never overwrite or retry a timing sample"
    work_root = PAPER / "build/core-matched-v1"
    work_root.mkdir(exist_ok=True)
    lock = (work_root / "campaign.lock").open("a+")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    existing = list((PAPER / "evidence").glob(PREFIX+"r*.json"))
    assert len(existing) < LIMITS["campaign_workers"]
    spent = sum(json.loads(p.read_text())["worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY"] for p in existing)
    assert spent+LIMITS["wall_seconds"] <= LIMITS["campaign_worker_seconds"]
    assert sum(p.stat().st_size for p in existing)+10*2**20 <= LIMITS["campaign_receipt_bytes"]
    assert all(receipt_path(x).exists() for x in queue[:index]), "Do not skip planned samples"
    before = manifest()
    work = work_root / destination.stem
    work.mkdir(exist_ok=False)
    command = ([sys.executable, "-B", str(HERE / "core_native_measure.py"), "--supervised-cell", config["cell"]]
        if config["compiler"] == "native" else [str(BINARY), "sample", config["compiler"], config["cell"],
            str(config["m"]), str(config["requested_bits"]), config["policy"]])
    cpu = min(os.sched_getaffinity(0))
    environment = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1",
                       NUMEXPR_NUM_THREADS="1", PYTHONDONTWRITEBYTECODE="1")

    def limits():
        os.sched_setaffinity(0, {cpu})
        for kind, value in ((resource.RLIMIT_AS, LIMITS["address_space_bytes"]),
                           (resource.RLIMIT_CPU, LIMITS["cpu_seconds"]), (resource.RLIMIT_CORE, 0),
                           (resource.RLIMIT_FSIZE, LIMITS["individual_file_bytes"])):
            resource.setrlimit(kind, (value, value))

    capture, events = [bytearray(), bytearray()], []
    result = error = None
    status, files = "ERROR", []
    selector = selectors.DefaultSelector()
    started = time.monotonic()
    child = subprocess.Popen(command, cwd=work, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             preexec_fn=limits, start_new_session=True, close_fds=True)
    selector.register(child.stdout, selectors.EVENT_READ, 0)
    selector.register(child.stderr, selectors.EVENT_READ, 1)
    deadline = started+LIMITS["wall_seconds"]
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                status = "TIMEOUT"
                raise TimeoutError("Matched worker wall limit")
            for key,_ in selector.select(timeout=min(1,max(0,deadline-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(),65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if sum(map(len,capture))+len(chunk) > LIMITS["combined_pipe_bytes"]:
                    status = "RESOURCE_LIMIT"
                    raise RuntimeError("Matched pipe limit")
                capture[key.data].extend(chunk)
        code = child.wait(timeout=max(0.01,deadline-time.monotonic()))
        elapsed = time.monotonic()-started
        if code in (-signal.SIGXCPU, -signal.SIGXFSZ, -signal.SIGKILL):
            status = "RESOURCE_LIMIT"
            raise RuntimeError(f"Worker terminated with signal {-code}; do not infer OOM without evidence")
        assert code in (0,2), f"Worker exit {code}"
        rows = [json.loads(line) for line in capture[0].decode().splitlines() if line.strip()]
        assert rows
        result, events = rows[-1], rows[:-1]
        status = validate(result, config, events)
        assert code == (0 if status == "PASS" else 2)
        stderr = capture[1].decode()
        if config["compiler"] == "native":
            assert not stderr and not list(work.iterdir())
        else:
            reviewed_warnings(stderr)
            files = check_directory(work)
        assert manifest() == before, "Source drift during timing"
    except Exception as exc:
        elapsed = time.monotonic()-started
        error = f"{type(exc).__name__}: {exc}"
        if status not in ("TIMEOUT", "RESOURCE_LIMIT"):
            status = "ERROR"
    finally:
        try:
            os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        code = child.wait(timeout=10)
        selector.close()
        child.stdout.close()
        child.stderr.close()
    after = manifest()
    _, linker = dependencies()
    cpu_model = next((line.split(":",1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                      if line.startswith("model name")), "unavailable")
    record = dict(schema="core-matched-two-batch-timing-v1", status=status, schedule_item=item,
        limits=LIMITS, source_manifest=before, sources_unchanged=after == before,
        host=dict(kernel=platform.release(), machine=platform.machine(), cpu_model=cpu_model, python=sys.version),
        affinity_cpu=cpu, dynamic_linker_reports=linker, command=command,
        worker_cwd=work.relative_to(ROOT).as_posix(), worker_files=files, worker_exit_code=code,
        worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY=elapsed,
        stdout_bytes=len(capture[0]), stderr=capture[1].decode(errors="replace"), events=events,
        result=result, error=error, benchmark=True, security_128_qualified=False,
        network_transfer_measured=False)
    if error:
        record["failed_stdout"] = capture[0].decode(errors="replace")
    with destination.open("x",encoding="utf-8") as stream:
        json.dump(record,stream,indent=2)
        stream.write("\n")
    print(json.dumps(dict(status=status, index=index, receipt=destination.relative_to(ROOT).as_posix(),
        sha256=sha256(destination.read_bytes()).hexdigest(), error=error,
        warm_local_seconds=result["batches"][1]["local_compute_seconds"] if status == "PASS" else None,
        security_128_qualified=False)),flush=True)
    if status == "ERROR":
        raise SystemExit(1)


if __name__ == "__main__":
    assert len(sys.argv) == 2
    if sys.argv[1] == "--preflight":
        queue, hashes = schedule(), manifest()
        for item in queue:
            gold = json.loads((ROOT / item["config"]["gate_receipt"]).read_text())["result"]
            if item["config"]["compiler"] == "native":
                wire = expected_native_wire(gold["profile"])
                assert wire[0] > gold["raw_hint_bytes"]+gold["raw_public_key_bytes"]
                assert wire[1] > gold["profile"]["raw_rns_input_bytes"]
                assert wire[2] > gold["profile"]["raw_rns_output_bytes"]
        print(json.dumps(dict(status="PUBLIC_PREFLIGHT_PASS", configurations=len(catalog()),
            scheduled_workers=len(queue), scheduled_encrypted_batches=2*len(queue),
            source_files=len(hashes), encrypted_execution=False, timing_collected=False,
            security_128_qualified=False),indent=2))
    else:
        run(int(sys.argv[1]))
