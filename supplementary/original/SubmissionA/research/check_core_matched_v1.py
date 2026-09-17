"""Independent aggregate readback of the complete matched core, without HE.

Checks immutable order, bindings, public fixture outputs and all priced phases.
The conventional endpoint is explicitly selected from the finite measured
family, not asserted to be a globally optimal or security-qualified baseline.
"""
import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
from statistics import median

import supervise_core_matched_v1 as campaign
from core_grid_fixture import CELLS, oracle_states
from check_composition_rns_arithmetic import CERTIFICATES

ROOT, PAPER = campaign.ROOT, campaign.PAPER


def stats(values):
    assert values and all(math.isfinite(x) and x >= 0 for x in values)
    return dict(n=len(values), median=median(values), minimum=min(values), maximum=max(values), raw=values)


def check():
    assert __debug__
    assert [r[0] for r in CERTIFICATES[:4]] == [1152921504002872321,1152921503566671361,
                                              1152921503264686081,1152921503096916481]
    assert [r[0].bit_length() for r in CERTIFICATES[:4]] == [60]*4
    assert [math.prod(r[0] for r in CERTIFICATES[:a]).bit_length() for a in (1,2,3)] == [60,120,180]
    manifest = campaign.manifest()
    queue = campaign.schedule()
    decision_path = PAPER / "evidence/core-matched-campaign-v1.json"
    decision = json.loads(decision_path.read_text())
    assert decision["schema"] == "core-matched-campaign-v1"
    assert decision["status"] in ("COMPLETE", "COMPLETE_WITH_FAILED_SAMPLES")
    assert decision["source_manifest"] == manifest
    scheduler = campaign.HERE / "run_core_matched_campaign_v1.py"
    assert decision["scheduler_sha256"] == sha256(scheduler.read_bytes()).hexdigest()
    assert len(decision["samples"]) == len(queue) == 114
    assert decision["benchmark"] and not decision["security_128_qualified"] and not decision["manuscript_complete"]
    expected = {cell:oracle_states(cell)[1] for cell in CELLS}
    records, hashes, statuses = {}, dict(manifest), {}
    reference_host = reference_cpu = None
    spent, verified_symbols, raw_bytes = 0.0, 0, 0
    for item, selection in zip(queue, decision["samples"]):
        assert selection["item"] == item
        path = campaign.receipt_path(item)
        assert selection["receipt"] == path.relative_to(ROOT).as_posix()
        assert selection["sha256"] == sha256(path.read_bytes()).hexdigest()
        record = json.loads(path.read_text())
        assert record["schema"] == "core-matched-two-batch-timing-v1"
        assert record["status"] == selection["status"] and record["status"] != "ERROR"
        assert record["schedule_item"] == item and record["source_manifest"] == manifest and record["sources_unchanged"]
        assert record["benchmark"] and not record["security_128_qualified"] and not record["network_transfer_measured"]
        assert record["limits"] == campaign.LIMITS
        if reference_host is None:
            reference_host, reference_cpu = record["host"], record["affinity_cpu"]
        assert record["host"] == reference_host and record["affinity_cpu"] == reference_cpu
        spent += record["worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY"]
        raw_bytes += path.stat().st_size
        statuses[record["status"]] = statuses.get(record["status"],0)+1
        hashes[path.relative_to(ROOT).as_posix()] = selection["sha256"]
        config = item["config"]
        records.setdefault(config["id"],[]).append(record)
        if record["status"] != "PASS":
            # Failed records remain in the complete table, never timed as zero.
            assert record["status"] in ("TIMEOUT", "RESOURCE_LIMIT", "NOISE_REJECT", "MARGIN_REJECT", "WRONG_OUTPUT")
            continue
        assert record["worker_exit_code"] == 0 and record["error"] is None
        result = record["result"]
        assert result["status"] == "CORE_MATCHED_PASS" and result["cell"] == config["cell"]
        assert result["compiler"] == config["compiler"] and result["benchmark"]
        assert result["encrypted_execution"] and not result["security_128_qualified"]
        gold = json.loads((ROOT / config["gate_receipt"]).read_text())["result"]
        assert result["profile"] == gold["profile"]
        for flag in ("bootstrapping", "process_isolation", "secret_keys_exported", "phase_diagnostics_exported",
                     "ciphertext_bodies_exported", "network_transfer_measured"):
            assert not result[flag]
        assert set(result["setup_seconds"]) == {"public_setup", "keys_and_serialization"}
        assert all(t > 0 and math.isfinite(t) for t in result["setup_seconds"].values())
        assert math.isclose(result["first_use_local_seconds"],sum(result["setup_seconds"].values())+
                            result["batches"][0]["local_compute_seconds"],rel_tol=1e-10)
        assert 0 < result["peak_rss_kib"] < campaign.LIMITS["address_space_bytes"]//1024
        want = expected[config["cell"]]
        native = config["compiler"] == "native"
        if native:
            assert not record["stderr"] and not list((ROOT / record["worker_cwd"]).iterdir())
            wire = campaign.expected_native_wire(gold["profile"])
            assert result["public_key_including_hints_bytes_serialized"] == wire[0]
        else:
            campaign.reviewed_warnings(record["stderr"])
            assert campaign.check_directory(ROOT / record["worker_cwd"]) == record["worker_files"]
            assert result["switching_matrices"] == gold["switching_matrices"]
        assert len(result["batches"]) == 2
        for index,b in enumerate(result["batches"]):
            assert b["index"] == index and b["all_outputs_match"]
            times = b["seconds"]
            assert all(math.isfinite(t) and t >= 0 for t in times.values())
            assert times["evaluation_total"] > 0
            assert math.isclose(b["batch_wall_seconds"]-times["validation"],b["local_compute_seconds"],rel_tol=1e-9)
            total = sum(t for k,t in times.items() if k != "validation")
            assert b["unallocated_charged_seconds"] >= 0
            assert math.isclose(total+b["unallocated_charged_seconds"],b["local_compute_seconds"],rel_tol=1e-9)
            assert sum(b["kernel_seconds"].values()) <= times["evaluation_total"]+1e-6
            if native:
                assert b["output_sha256"] == sha256(want.tobytes()).hexdigest() and b["output_symbols"] == len(want)
                assert b["operations"] == gold["batches"][index]["operations"]
                assert (b["input_bytes_serialized"],b["output_bytes_serialized"]) == wire[1:]
                for k in ("terminal_key", "terminal_limbs", "terminal_components", "raw_input_bytes", "raw_output_bytes"):
                    assert b[k] == gold["batches"][index][k]
            else:
                assert b["recovered_public_fixture_symbols"] == list(want)
                assert b["functional_admitted"] and b["terminal_capacity_gate"] and b["all_observed_library_correct"]
                assert not b["checkpoints"] and b["structural_handle_checkpoints"] == 0
                for k in ("encryptions", "products", "component_products", "additions", "relinearizations", "rotations", "switched_parts"):
                    assert b[k] == gold["batches"][index][k]
                assert len(b["output_profiles"]) == len(gold["batches"][index]["output_profiles"])
                for row,original in zip(b["output_profiles"],gold["batches"][index]["output_profiles"]):
                    assert row["parts"] == original["parts"] and row["group"] == original["group"]
                    assert row["prime_indices"] and row["bit_capacity"] >= 10 and row["library_is_correct"]
            verified_symbols += len(want)
    assert set((PAPER / "evidence").glob(campaign.PREFIX+"r*.json")) == {campaign.receipt_path(x) for x in queue}
    assert spent <= campaign.LIMITS["campaign_worker_seconds"] and raw_bytes <= campaign.LIMITS["campaign_receipt_bytes"]
    assert (statuses.get("PASS",0) == len(queue)) == (decision["status"] == "COMPLETE")
    summaries = []
    for config in campaign.catalog():
        group = records[config["id"]]
        assert [r["schedule_item"]["repetition"] for r in group] == [0,1,2]
        good = [r["result"] for r in group if r["status"] == "PASS"]
        row = dict(config=config,statuses=[r["status"] for r in group],complete_all_three=len(good) == 3)
        if good:
            def measured_batch(phase):
                batches = [r["batches"][phase] for r in good]
                return dict(local_seconds=stats([b["local_compute_seconds"] for b in batches]),
                    evaluation_seconds=stats([b["seconds"]["evaluation_total"] for b in batches]),
                    owners_seconds=stats([sum(v for k,v in b["seconds"].items()
                        if k.startswith("owner") or k == "input_serialization") for b in batches]),
                    recipient_seconds=stats([sum(v for k,v in b["seconds"].items()
                        if k.startswith("recipient") or k == "output_serialization") for b in batches]),
                    residual_seconds=stats([b["unallocated_charged_seconds"] for b in batches]),
                    input_bytes=stats([b["input_bytes_serialized"] for b in batches]),
                    output_bytes=stats([b["output_bytes_serialized"] for b in batches]),
                    prepared_plaintext_cache_bytes=stats([b["prepared_plaintext_cache_bytes"] for b in batches]))
            row.update(first=measured_batch(0),warm=measured_batch(1),
                first_use_local_seconds=stats([r["first_use_local_seconds"] for r in good]),
                public_setup_seconds=stats([r["setup_seconds"]["public_setup"] for r in good]),
                keys_and_serialization_seconds=stats([r["setup_seconds"]["keys_and_serialization"] for r in good]),
                public_keys_and_hints_bytes=stats([r["public_key_including_hints_bytes_serialized"] for r in good]),
                process_peak_rss_mib=stats([r["peak_rss_kib"]/1024 for r in good]),
                profile=good[0]["profile"])
        summaries.append(row)
    endpoints = []
    for cell,(family,length,jobs) in CELLS.items():
        rows = [r for r in summaries if r["config"]["cell"] == cell and r["complete_all_three"]]
        native = [r for r in rows if r["config"]["compiler"] == "native"]
        primary = [r for r in rows if r["config"]["compiler"] == "crt"]
        if not native or not primary:
            endpoints.append(dict(cell=cell,status="INCOMPLETE_MATCHED_THREE_SETUP_COMPARISON"))
            continue
        native = native[0]
        warm = min(primary,key=lambda r:(r["warm"]["local_seconds"]["median"],r["config"]["id"]))
        first = min(primary,key=lambda r:(r["first_use_local_seconds"]["median"],r["config"]["id"]))
        nt,ct = native["warm"]["local_seconds"]["median"],warm["warm"]["local_seconds"]["median"]
        endpoints.append(dict(cell=cell,family=family,length=length,jobs=jobs,status="DESCRIPTIVE_FINITE_FAMILY_ONLY",
            native_id=native["config"]["id"],primary_warm_endpoint=warm["config"]["id"],
            primary_first_use_endpoint=first["config"]["id"],
            conventional_over_native_warm_ratio=ct/nt,
            native_jobs_per_second=jobs/nt,primary_jobs_per_second=jobs/ct,
            native_useful_field_coefficients_per_second=jobs*length/nt,
            primary_useful_field_coefficients_per_second=jobs*length/ct))
    for p in (Path(__file__),decision_path,campaign.HERE / "CORE_GRID_MATCHED_TIMING_V1_ERRATA.md"):
        hashes[p.relative_to(ROOT).as_posix()] = sha256(p.read_bytes()).hexdigest()
    assert campaign.manifest() == manifest
    return dict(schema="core-matched-complete-readback-v1",status="PASS",campaign_status=decision["status"],
        profiles=summaries,endpoints=endpoints,worker_statuses=statuses,independent_worker_setups=len(queue),
        complete_verified_batches=2*statuses.get("PASS",0),terminal_symbol_comparisons=verified_symbols,
        host=reference_host,affinity_cpu=reference_cpu,readback_runs_encryption=False,
        native_prime_bits=60,native_gadget_width=48,editorial_protocol_erratum_bound=True,
        benchmark_evidence=True,network_transfer_measured=False,security_128_qualified=False,
        parameter_optimality=False,statistical_significance_claim=False,manuscript_complete=False,
        sources_sha256=dict(sorted(hashes.items())))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output",type=Path)
    mode.add_argument("--verify",type=Path)
    args = parser.parse_args()
    result = check()
    if args.output:
        destination = args.output.resolve()
        assert destination.parent == (PAPER / "evidence").resolve()
        with destination.open("x",encoding="utf-8") as stream:
            json.dump(result,stream,indent=2)
            stream.write("\n")
    else:
        assert json.loads(args.verify.read_text()) == result
    print(json.dumps({k:v for k,v in result.items() if k not in ("profiles","sources_sha256")},indent=2))
