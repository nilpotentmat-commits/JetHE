"""Read back six immutable encrypted gates without executing HE or timing."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

from core_grid_fixture import CELLS, metadata, oracle_states
from core_profile_manifest import select

ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "SubmissionA"


def check():
    assert __debug__ and sys.byteorder == "little"
    files = [Path(__file__)]
    cases = []
    common_manifest = None
    states = symbols = 0
    for cell, (family, length, jobs) in CELLS.items():
        path = PAPER / "evidence" / ("core-native-gate-v1-"+cell+".json")
        files.append(path)
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["schema"] == "core-native-functional-gate-v1"
        assert record["status"] == "PASS" and record["cell"] == cell
        assert record["sources_unchanged"] and record["worker_exit_code"] == 0
        assert record["error"] is None and record["stderr"] == ""
        assert record["limits"] == dict(address_space_bytes=2*2**30, cpu_seconds=160,
            wall_seconds=180, combined_pipe_bytes=4*2**20, individual_file_bytes=8*2**20,
            threads=1, core_dump_bytes=0)
        assert record["worker_elapsed_seconds_LIMIT_DIAGNOSTIC_ONLY"] < 180
        assert record["stdout_bytes"] < 4*2**20
        assert not record["benchmark"] and not record["security_128_qualified"]
        assert not record["binary_build_attestation"]
        if common_manifest is None:
            common_manifest = record["source_manifest"]
        assert record["source_manifest"] == common_manifest
        result = record["result"]
        profile = select(length, family, "raw")["selected"]
        assert result["status"] == "CORE_NATIVE_FUNCTIONAL_PASS"
        assert result["cell"] == cell and result["profile"] == profile
        assert result["actual_gate_encrypted_execution"]
        assert not profile["encrypted_execution"]  # The older public admission stays public-only.
        assert result["fixture"] == metadata(cell)
        assert result["public_fixture_output_digest_only"]
        for flag in ("secret_keys_exported", "phase_diagnostics_exported", "process_isolation",
                     "benchmark", "security_128_qualified", "bootstrapping"):
            assert not result[flag]
        masks = sum(v["incoming_rows"]*v["limbs"] for v in profile["key_vertices"])
        ternary = profile["independent_keys"]+2*profile["encryptions_per_batch"]
        errors = 1+profile["hint_rows"]+4*profile["encryptions_per_batch"]
        word_cap = profile["dimension"]*(8*(masks+ternary)+errors)
        assert result["coin_budget"] == dict(mask_channels=masks, ternary_vectors=ternary,
            error_vectors=errors, word_cap=word_cap, rejection_rounds=8)
        assert result["primitive_error_vectors"] == errors
        assert 0 < result["actual_words_requested"] <= word_cap
        assert result["raw_hint_bytes"] == profile["raw_rns_hint_bytes"]
        assert result["raw_public_key_bytes"] == profile["raw_rns_public_key_bytes"]
        _, expected = oracle_states(cell)
        digest = sha256(expected.tobytes()).hexdigest()
        count = (profile["encryptions_per_batch"]+profile["products"]
                 + profile["executed_rekeys"]+profile["executed_prime_drops"])
        assert len(result["batches"]) == 2
        for index, batch in enumerate(result["batches"]):
            assert batch["index"] == index and batch["checked_states"] == count
            assert batch["output_symbols"] == length*jobs and batch["output_sha256"] == digest
            assert batch["operations"] == dict(products=profile["products"],
                rekeys=profile["executed_rekeys"], prime_drops=profile["executed_prime_drops"])
            assert batch["raw_input_bytes"] == profile["raw_rns_input_bytes"]
            assert batch["raw_output_bytes"] == profile["raw_rns_output_bytes"]
            assert batch["terminal_key"] == "s"+str(profile["independent_keys"]-1)
            assert batch["terminal_limbs"] == profile["chain"][-1]
            assert batch["terminal_components"] == 3
            states += count
            symbols += length*jobs
        cases.append(dict(cell=cell, batches=2, states_per_batch=count, symbols_per_batch=length*jobs,
            chain=profile["chain"], hint_rows=profile["hint_rows"],
            raw_hint_bytes=profile["raw_rns_hint_bytes"], raw_output_bytes=profile["raw_rns_output_bytes"],
            output_sha256=digest))
    assert (states, symbols) == (94, 25632)
    required = ["core_native_execution.py", "core_grid_fixture.py", "supervise_core_native.py",
                "core_native.py", "core_profile_manifest.py", "composition_full_run.py",
                "composition_native.py", "composition_optimized.py", "CORE_GRID_V1_GATE_PROTOCOL.md",
                "composition_native_core.cpp", "composition_optimized_core.cpp"]
    assert all("SubmissionA/research/"+name in common_manifest for name in required)
    assert "SubmissionA/build/composition_optimized_core.so" in common_manifest
    for relative, expected_hash in common_manifest.items():
        path = (ROOT / relative).resolve()
        assert path.is_relative_to(PAPER) and path.is_file()
        assert sha256(path.read_bytes()).hexdigest() == expected_hash
        files.append(path)
    return dict(schema="core-native-encrypted-gate-readback-v1", status="PASS", cells=cases,
        encrypted_worker_processes=6, encrypted_batches=12, checked_states=states,
        terminal_symbol_comparisons=symbols, distinct_public_fixtures=6,
        readback_runs_encryption=False, benchmark=False, security_128_qualified=False,
        matched_conventional_execution=False, alternative_anchor_execution=False,
        manuscript_complete=False,
        sources_sha256={p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
                        for p in sorted(set(files))})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--output", type=Path)
    modes.add_argument("--verify", type=Path)
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
    print(json.dumps({k: v for k, v in result.items() if k not in ("sources_sha256", "cells")}, indent=2))
