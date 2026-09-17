"""Read back the finite conventional core admission, without executing HE.

Replays the frozen supervisor's public-output/inventory checks, then separately
checks the complete ascending candidate search, prerequisite bindings, all
single-job counterparts, retained failures and the current source manifests.
Resource-limit durations are deliberately not turned into benchmark samples.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re

import supervise_core_conventional_v4 as gate

ROOT, PAPER, HERE = gate.ROOT, gate.PAPER, gate.HERE
FAMILIES = (
    ("crt", "w1-l16-j16"),
    ("crt", "w1-l256-j16"),
    ("crt", "w2-shallow-l256-j16"),
    ("crt", "w2-deep-l256-j16"),
    ("b16", "w1-l256-j16"),
)
RETAINED_ERRORS = {
    "core-conventional-v1-public-codec.json":
        "86eb5c2840f008328207d467b1f338129c7f355c99ad896a020a6efec8f87601",
    "core-conventional-v3-gate-crt-w1-l16-j16-m4369-b20-raw.json":
        "8cf5cc5e846b999d3494c9de774d244af36a5ba97d1aa01b3d242808b5312588",
}


def reviewed_warnings(stderr):
    """Recognize only the two retained, source-reviewed Context.cpp advisories.

    Lines 835--843 report prime-bit-size granularity; lines 712--722/1068
    report small primes without NTL's FFT-prime flag. Neither excuses failed
    output checks or substitutes a different modulus/performance measurement.
    """
    messages = []
    for line in stderr.splitlines():
        match = re.fullmatch(r"\[ \d\d:\d\d:\d\d \] WARNING: (.*)", line)
        assert match and match[1] in (
            "ctxtPrimeSize: non-optimal targetSize", "CheckPrimes: non-FFT prime in smallPrimes"), line
        messages.append(match[1])
    return messages


def receipt_path(args):
    label = "public-codec" if args == ["public-codec"] else (
        f"{args[0]}-{args[1]}-{args[2]}-m{args[3]}-b{args[4]}-{args[5]}")
    return PAPER / "evidence" / (gate.PREFIX+label+".json")


def check():
    assert __debug__
    current = gate.manifest()
    scheduler = HERE / "run_core_conventional_campaign_v4.py"
    files = {Path(__file__), scheduler, HERE / "run_core_single_job_gates.py"}
    records, decisions, selected, single_jobs = {}, [], [], []

    def read(args):
        path = receipt_path(args)
        if path in records:
            return records[path]
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["schema"] == "core-conventional-functional-v4"
        assert record["arguments"] == args and record["mode"] == args[0]
        assert record["source_manifest"] == current and record["sources_unchanged"]
        assert record["status"] in ("PASS", "REJECT") and record["error"] is None
        assert record["limits"] == gate.LIMITS and record["affinity_cpu"] >= 0
        assert record["stdout_bytes"] <= gate.LIMITS["combined_pipe_bytes"]
        assert record["worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY"] < gate.LIMITS["wall_seconds"]
        assert not record["benchmark"] and not record["security_128_qualified"]
        assert record["worker_exit_code"] == (0 if record["status"] == "PASS" else 2)
        reviewed_warnings(record["stderr"])
        work = (ROOT / record["worker_cwd"]).resolve()
        assert work.is_relative_to((PAPER / "build/core-conventional-gate-v4").resolve())
        assert gate.check_directory(work) == record["worker_files"]
        if args == ["public-codec"]:
            assert gate.validate_result(record["result"], "public-codec") == "PASS"
        else:
            mode, arm, cell, m, bits, policy = args
            m, bits = int(m), int(bits)
            assert gate.validate_result(record["result"], mode, arm, cell, m, bits, policy) == record["status"]
            if mode == "gate":
                carrier_cell = "w1-l256-j16" if arm == "b16" else "w1-l16-j16"
                public = read(["profile", arm, carrier_cell, str(m), str(bits), "raw"])
                original = public["result"]["profile"]
                no_hints = arm == "crt" and policy in ("raw", "nn")
                field = ("published_q_library_heuristic_NOT_CERTIFICATION" if no_hints
                         else "library_security_estimate_NOT_CERTIFICATION")
                assert original[field] >= 128
                setup = [r for r in record["events"] if r.get("event") == "core_setup_complete"]
                assert len(setup) == 1
                expected = dict(original)
                matrices = (0 if no_hints else 16 if arm == "b16" else 3 if policy == "ny" else 1)
                expected.update(assumed_switching_matrices=matrices,
                    screen_modulus="Q" if no_hints else "QP",
                    effective_library_heuristic_NOT_CERTIFICATION=original[field],
                    effective_library_128_screen=True)
                assert setup[0]["profile"] == expected
                assert len(setup[0]["switching_matrices"]) == matrices
                if record["result"]["status"] == "CORE_CONVENTIONAL_NOISE_REJECT":
                    rejected = [r for r in record["events"]
                                if r.get("event") == "public_noise_admission_rejection"]
                    assert len(rejected) == 1 and rejected[0]["library_is_correct"] is False
                    assert not record["result"]["full_output_verified"]
                else:
                    assert record["result"]["profile"] == expected
        records[path] = record
        files.add(path)
        return record

    def resource_row(record):
        result = record["result"]
        assert record["status"] == "PASS" and result["status"] == "CORE_CONVENTIONAL_GATE_PASS"
        profile, batches = result["profile"], result["batches"]
        first = batches[0]
        invariant = ("encryptions", "products", "component_products", "additions", "relinearizations",
                     "switched_parts", "rotations", "input_bytes_serialized")
        assert all(all(b[k] == first[k] for k in invariant) for b in batches)
        return dict(cell=result["cell"], compiler=result["compiler"], policy=result["policy"],
            m=profile["m"], dimension=profile["dimension"], slots=profile["slots"],
            requested_bits=profile["requested_bits"], ciphertext_primes=profile["ciphertext_primes"],
            screen_modulus=profile["screen_modulus"],
            heuristic_screen_NOT_CERTIFICATION=profile["effective_library_heuristic_NOT_CERTIFICATION"],
            switching_matrices=len(result["switching_matrices"]),
            public_key_including_hints_bytes_serialized=result["public_key_including_hints_bytes_serialized"],
            operations_per_batch={k:first[k] for k in invariant if k != "input_bytes_serialized"},
            inputs=first["encryptions"], outputs=len(first["output_profiles"]),
            input_bytes_serialized=first["input_bytes_serialized"],
            output_bytes_serialized_by_batch=[b["output_bytes_serialized"] for b in batches],
            terminal_parts=sorted({o["parts"] for b in batches for o in b["output_profiles"]}),
            terminal_minimum_capacity_by_batch=[min(o["bit_capacity"] for o in b["output_profiles"]) for b in batches],
            receipt=receipt_path(record["arguments"]).relative_to(ROOT).as_posix())

    read(["public-codec"])
    for arm, cell in FAMILIES:
        path = PAPER / "evidence" / f"core-conventional-admission-v4-{arm}-{cell}.json"
        decision = json.loads(path.read_text(encoding="utf-8"))
        assert decision["schema"] == "core-conventional-finite-admission-v4"
        assert (decision["compiler"], decision["cell"]) == (arm, cell)
        assert decision["source_manifest"] == current
        assert decision["scheduler_sha256"] == sha256(scheduler.read_bytes()).hexdigest()
        assert decision["complete_for_declared_family"] and not decision["global_parameter_optimality"]
        assert not decision["benchmark"] and not decision["security_128_qualified"]
        policies = ("nn", "ny", "yn", "yy") if cell == "w2-deep-l256-j16" else ("raw",)
        expected_pairs = [(m, p) for m in (gate.CONDUCTORS if arm == "crt" else [13107]) for p in policies]
        assert [(r["m"], r["policy"]) for r in decision["decisions"]] == expected_pairs
        for row in decision["decisions"]:
            m, policy = row["m"], row["policy"]
            candidates = row["candidates"]
            assert 0 < len(candidates) <= len(gate.BIT_REQUESTS)
            assert [r["requested_bits"] for r in candidates] == list(gate.BIT_REQUESTS[:len(candidates)])
            passed = []
            for index, candidate in enumerate(candidates):
                bits = candidate["requested_bits"]
                carrier_cell = "w1-l256-j16" if arm == "b16" else "w1-l16-j16"
                public = read(["profile", arm, carrier_cell, str(m), str(bits), "raw"])
                field = ("published_q_library_heuristic_NOT_CERTIFICATION"
                         if arm == "crt" and policy in ("raw", "nn")
                         else "library_security_estimate_NOT_CERTIFICATION")
                eligible = public["result"]["profile"][field] >= 128
                assert eligible == (candidate["status"] != "LIBRARY_SCREEN_REJECT")
                if not eligible:
                    assert candidate == dict(requested_bits=bits, status="LIBRARY_SCREEN_REJECT")
                    continue
                args = ["gate", arm, cell, str(m), str(bits), policy]
                record, gate_path = read(args), receipt_path(args)
                assert candidate == dict(requested_bits=bits, status=record["status"],
                    receipt=gate_path.relative_to(ROOT).as_posix(), sha256=sha256(gate_path.read_bytes()).hexdigest())
                if record["status"] == "PASS":
                    assert index == len(candidates)-1, "Search continued after first admission"
                    passed.append(candidate)
                    selected.append(resource_row(record))
                    if arm == "crt" and cell.startswith("w1-"):
                        single_args = ["gate", arm, cell.replace("-j16", "-j1"), str(m), str(bits), policy]
                        single = read(single_args)
                        assert single["status"] == "PASS", "Unadmitted single-job counterpart"
                        single_jobs.append(resource_row(single))
            assert row["selected"] == (passed[0] if passed else None)
            if not passed:
                assert len(candidates) == len(gate.BIT_REQUESTS)
        decisions.append(dict(compiler=arm, cell=cell, carrier_policies=len(expected_pairs),
            admitted=sum(r["selected"] is not None for r in decision["decisions"]),
            exhausted=sum(r["selected"] is None for r in decision["decisions"])))
        files.add(path)

    assert len(single_jobs) == 8
    assert {r["cell"] for r in selected+single_jobs if r["compiler"] == "crt"} == set(gate.CELLS)
    assert any(r["compiler"] == "b16" for r in selected), "Required alternative anchor unadmitted"
    # Every v4 gate has a reason to exist in the declared finite queue.
    existing = set((PAPER / "evidence").glob(gate.PREFIX+"gate-*.json"))
    assert existing == {p for p, r in records.items() if r["mode"] == "gate"}
    historical = []
    for filename, digest in RETAINED_ERRORS.items():
        path = PAPER / "evidence" / filename
        assert sha256(path.read_bytes()).hexdigest() == digest
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["status"] == "ERROR" and not record["benchmark"]
        historical.append(dict(receipt=path.relative_to(ROOT).as_posix(), sha256=digest,
                               status="ERROR", old_manifest_revalidated=False))
        files.add(path)
    all_versions = [p for v in (1, 2, 3, 4) for p in (PAPER / "evidence").glob(f"core-conventional-v{v}-*.json")]
    total_limit_seconds = sum(json.loads(p.read_text())["worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY"] for p in all_versions)
    assert total_limit_seconds <= gate.LIMITS["campaign_worker_seconds"]
    assert sum(p.stat().st_size for p in all_versions) < gate.LIMITS["campaign_receipt_bytes"]
    files.update(all_versions)
    for name, digest in current.items():
        path = ROOT / name
        assert path.is_file() and sha256(path.read_bytes()).hexdigest() == digest
        files.add(path)
    assert gate.manifest() == current
    statuses = {s:sum(r["status"] == s for r in records.values() if r["mode"] == "gate") for s in ("PASS", "REJECT")}
    rejections = dict(public_noise_bound=0, complete_output_margin=0, wrong_output=0)
    for record in records.values():
        if record["mode"] != "gate" or record["status"] != "REJECT":
            continue
        result = record["result"]
        reason = ("public_noise_bound" if result["status"] == "CORE_CONVENTIONAL_NOISE_REJECT" else
                  "complete_output_margin" if all(b["all_outputs_match"] for b in result["batches"]) else "wrong_output")
        rejections[reason] += 1
    return dict(schema="core-conventional-encrypted-readback-v1", status="PASS",
        finite_families=decisions, admitted_batched_candidates=selected, admitted_single_job_candidates=single_jobs,
        encrypted_gate_statuses=statuses, rejection_categories=rejections,
        complete_verified_encrypted_batches=2*statuses["PASS"],
        full_core_fixtures=6, required_w1_alternative_anchor=True,
        retained_historical_errors=historical, finite_family_only=True,
        library_warnings_retained=sorted({w for r in records.values() for w in reviewed_warnings(r["stderr"])}),
        readback_runs_encryption=False, benchmark=False, security_128_qualified=False,
        global_parameter_optimality=False, manuscript_complete=False,
        sources_sha256={gate.path_name(p):sha256(p.read_bytes()).hexdigest() for p in sorted(files)})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    result = check()
    if args.output:
        destination = args.output.resolve()
        assert destination.parent == (PAPER / "evidence").resolve()
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    else:
        assert json.loads(args.verify.read_text(encoding="utf-8")) == result
    print(json.dumps({k:v for k,v in result.items() if k not in (
        "sources_sha256", "admitted_batched_candidates", "admitted_single_job_candidates")}, indent=2))
