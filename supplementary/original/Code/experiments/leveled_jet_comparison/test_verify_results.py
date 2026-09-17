"""Synthetic unit fixtures for the read-only verifier; never benchmark evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import tempfile
import unittest
from pathlib import Path

import verify_results as verifier


def refresh_fixture_fields(case):
    digest = 14695981039346656037
    for job in case["inputs"]:
        for factor in job:
            for bit in factor:
                digest = ((digest ^ bit) * 1099511628211) % (1 << 64)
    case["fixture_fnv1a64"] = str(digest)
    outputs = verifier.oracle_outputs(case["inputs"], case["jobs"], case["mults"] + 1,
                                      case["length"])
    for trial in case["trials"]:
        trial["decoded_outputs"] = copy.deepcopy(outputs)


def synthetic_case(layout="native", scheme="BGV", schedule="balanced"):
    """Invented times and tiny modulus are deliberately unit-test-only data."""
    jobs, length, mults, dimension = 2, 4, 4, 128
    factors = mults + 1
    points = factors * (length - 1) + 1
    capacity = 1 if layout == "native" else dimension // points
    batches = (jobs + capacity - 1) // capacity
    q = 257 * 769
    case = {
        "schema": "leveled-jet-comparison-v1", "status": "PASS",
        "synthetic_unit_test_fixture": True,
        "scheme": scheme, "layout": layout, "schedule": schedule,
        "length": length, "mults": mults, "jobs": jobs, "fixture_seed": 11,
        "parameter_multiplicative_depth": mults,
        "security_requested": "HEStd_128_classic", "independent_security_certification": False,
        "omp_num_threads": "1",
        "plaintext_modulus": 2 if layout == "native" else 65537,
        "ring_dimension": dimension, "evaluation_points": points,
        "integer_low_coefficient_bound": math.comb(length - 1 + mults, mults),
        "jobs_per_ciphertext_capacity": capacity, "ciphertext_batches": batches,
        "input_ciphertexts": batches * factors, "output_ciphertexts": batches,
        "ctct_calls_per_trial": batches * mults,
        "ctct_depth": mults if schedule == "sequential" else 3,
        "rotation_calls": 0, "bootstrap_calls": 0, "warmup_trials_excluded": 1,
        "ciphertext_q_primes": ["257", "769"], "ciphertext_q_towers": 2,
        "ciphertext_q_bits": q.bit_length(), "ciphertext_q_log2": math.log2(q),
        "output_q_towers": 1, "key_switching_technique": "HYBRID",
        "key_switching_p_primes": ["3329"], "key_switching_p_bits": (3329).bit_length(),
        "key_switching_qp_bits": (q * 3329).bit_length(),
        "secret_key_distribution": "UNIFORM_TERNARY",
        "public_key_bytes": 10, "relinearization_key_bytes": 20,
        "input_bytes": 30, "output_bytes": 40, "peak_rss_bytes": 50,
        "setup_ms": 1.0, "precomputation_ms": 0.5, "repetitions": 3,
        "verified_output_coefficients_including_warmup": jobs * length * 4,
        "inputs": [[[1, (job + factor) % 2, factor % 2, job % 2]
                    for factor in range(factors)] for job in range(jobs)],
        "trials": [dict(zip((name + "_ms" for name in verifier.TIMINGS),
                            (scale, 2 * scale, 3 * scale, 4 * scale, 5 * scale)))
                   for scale in (1.0, 2.0, 3.0)],
        "median_ms": {"encode": 2.0, "encrypt": 4.0, "eval": 6.0,
                      "decrypt": 8.0, "decode": 10.0, "end_to_end": 30.0},
    }
    refresh_fixture_fields(case)
    return case


def write_bound(root: Path, relative: str, raw: bytes):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as handle:
        handle.write(raw)
    return {"path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def configuration(case):
    result = {key: case[key] for key in ("scheme", "layout", "schedule", "length",
                                        "mults", "jobs", "repetitions")}
    result["seed"] = case["fixture_seed"]
    return result


class IndependentVerifierTests(unittest.TestCase):
    def test_known_carryless_oracle(self):
        self.assertEqual(verifier.carryless_product(0b11, 0b11), 0b101)
        inputs = [[[1, 1, 0, 0], [1, 0, 1, 0], [1, 0, 0, 1]]]
        self.assertEqual(verifier.oracle_outputs(inputs, 1, 3, 4), [[1, 1, 1, 0]])

    def test_all_schemes_layouts_and_schedules(self):
        cases = [synthetic_case(layout, scheme, schedule)
                 for layout in ("native", "packed_terminal")
                 for scheme in ("BFV", "BGV")
                 for schedule in ("sequential", "balanced")]
        for case in cases:
            summary = verifier.verify_case(case)
            self.assertEqual(summary["verified_measured_output_coefficients"], 24)
            self.assertEqual(summary["timings_ms"]["eval"], {"min": 3, "median": 6, "max": 9})
            self.assertAlmostEqual(summary["throughput_jobs_per_second"]["end_to_end"]["median"],
                                   2000 / 30)
        verifier.verify_fixture_matching(cases)
        verifier.verify_schedule_profiles(cases)

    def test_schedule_parameter_profiles_match(self):
        sequential = synthetic_case(schedule="sequential")
        balanced = synthetic_case(schedule="balanced")
        verifier.verify_schedule_profiles([sequential, balanced])
        balanced["ring_dimension"] *= 2
        with self.assertRaisesRegex(verifier.VerificationError, "changed parameter profile"):
            verifier.verify_schedule_profiles([sequential, balanced])

    def test_meaningful_negative_mutations(self):
        mutations = {
            "decoded plaintext": lambda c: c["trials"][0]["decoded_outputs"][0].__setitem__(1,
                                         c["trials"][0]["decoded_outputs"][0][1] ^ 1),
            "nonunit input": lambda c: c["inputs"][0][0].__setitem__(0, 0),
            "fixture hash": lambda c: c.__setitem__("fixture_fnv1a64", "0"),
            "integer bound": lambda c: c.__setitem__("integer_low_coefficient_bound", 1),
            "evaluation count": lambda c: c.__setitem__("evaluation_points", 4),
            "packed plaintext": lambda c: c.__setitem__("plaintext_modulus", 17),
            "packed dimension": lambda c: c.__setitem__("ring_dimension", 65536),
            "packing capacity": lambda c: c.__setitem__("jobs_per_ciphertext_capacity", 1),
            "ciphertext count": lambda c: c.__setitem__("input_ciphertexts", 1),
            "multiplication count": lambda c: c.__setitem__("ctct_calls_per_trial", 1),
            "balanced depth": lambda c: c.__setitem__("ctct_depth", 4),
            "balanced parameter reduction": lambda c: c.__setitem__("parameter_multiplicative_depth", 3),
            "extra reserved parameter budget": lambda c: c.__setitem__("parameter_multiplicative_depth", 5),
            "timing median": lambda c: c["median_ms"].__setitem__("eval", 0.5),
            "negative sample": lambda c: c["trials"][0].__setitem__("encrypt_ms", -1),
            "nonfinite sample": lambda c: c["trials"][0].__setitem__("eval_ms", float("nan")),
            "QP exposure": lambda c: c.__setitem__("key_switching_qp_bits", c["ciphertext_q_bits"]),
            "Q bit count": lambda c: c.__setitem__("ciphertext_q_bits", 1),
            "unrequested security": lambda c: c.__setitem__("security_requested", "HEStd_NotSet"),
            "security promotion": lambda c: c.__setitem__("independent_security_certification", True),
            "ExactJet promotion": lambda c: c.__setitem__("exactjet_authority", True),
            "refresh promotion": lambda c: c.__setitem__("bootstrap_calls", 1),
            "producer OpenMP setting": lambda c: c.__setitem__("omp_num_threads", "2"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                case = synthetic_case("packed_terminal")
                mutate(case)
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_case(case)

    def test_coherently_changed_fixture_cannot_evade_matching(self):
        native = synthetic_case("native")
        packed = synthetic_case("packed_terminal")
        packed["inputs"][0][0][1] ^= 1
        refresh_fixture_fields(packed)
        verifier.verify_case(packed)  # Internally consistent but unfair comparison.
        with self.assertRaisesRegex(verifier.VerificationError, "fixture mismatch"):
            verifier.verify_fixture_matching([native, packed])
        packed = synthetic_case("packed_terminal")
        packed["fixture_seed"] += 1
        with self.assertRaisesRegex(verifier.VerificationError, "fixture mismatch"):
            verifier.verify_fixture_matching([native, packed])

    def test_bound_manifest_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory(prefix="leveled-verifier-synthetic-") as temporary:
            repo = Path(temporary)
            run = repo / "synthetic-run"
            run.mkdir()
            sources = [write_bound(run, "source/synthetic-producer.cpp", b"synthetic test source\n")]
            executable = write_bound(repo, "synthetic-build/not-an-executable.bin", b"synthetic unit fixture\n")
            records = [synthetic_case(layout) for layout in ("native", "packed_terminal")]
            cases = [{**write_bound(run, f"{case['layout']}.json", json.dumps(case).encode()),
                      "configuration": configuration(case)} for case in records]
            manifest = {
                "schema": "nilhe.leveled-library-comparison.manifest.v1",
                "status": "MEASURED_LEVELED_LIBRARY_COMPARISON_ONLY",
                "run_id": "synthetic-unit-test-only",
                "environment": {"synthetic": True, "OMP_NUM_THREADS": 1,
                                "OMP_DYNAMIC": "FALSE", "timed_processes_parallel": False},
                "publication": {"mode": "exclusive-create", "overwrites_existing": False},
                "source_bindings": sources, "executable": executable, "cases": cases,
                "requested_cases": [configuration(case) for case in records],
            }
            write_bound(run, "manifest.json", json.dumps(manifest).encode())
            result = verifier.verify_manifest(run / "manifest.json", repo)
            self.assertEqual(result["case_count"], 2)
            mutations = {
                "missing record": lambda m: m["cases"].pop(),
                "extra record": lambda m: m["cases"].append(copy.deepcopy(m["cases"][0])),
                "changed bound config": lambda m: m["cases"][0]["configuration"].__setitem__("seed", 12),
                "changed requested config": lambda m: m["requested_cases"][0].__setitem__("repetitions", 7),
                "changed record order": lambda m: m["cases"].reverse(),
                "missing requested grid": lambda m: m.pop("requested_cases"),
                "environment threads": lambda m: m["environment"].__setitem__("OMP_NUM_THREADS", 2),
                "environment dynamic": lambda m: m["environment"].__setitem__("OMP_DYNAMIC", "TRUE"),
                "concurrent timings": lambda m: m["environment"].__setitem__("timed_processes_parallel", True),
            }
            for index, (name, mutate) in enumerate(mutations.items()):
                with self.subTest(name=name):
                    changed = copy.deepcopy(manifest)
                    mutate(changed)
                    filename = f"negative-manifest-{index}.json"
                    write_bound(run, filename, json.dumps(changed).encode())
                    with self.assertRaises(verifier.VerificationError):
                        verifier.verify_manifest(run / filename, repo)
            # Even agreeing request/binding lies cannot override recorded output metadata.
            changed = copy.deepcopy(manifest)
            changed["requested_cases"][0]["repetitions"] = 7
            changed["cases"][0]["configuration"]["repetitions"] = 7
            write_bound(run, "coherent-config-lie.json", json.dumps(changed).encode())
            with self.assertRaisesRegex(verifier.VerificationError, "requested/actual repetitions"):
                verifier.verify_manifest(run / "coherent-config-lie.json", repo)
            # Changes elsewhere in the workspace do not invalidate frozen source snapshots.
            write_bound(repo, "current/synthetic-producer.cpp", b"later version\n")
            verifier.verify_manifest(run / "manifest.json", repo)
            with (run / "source/synthetic-producer.cpp").open("ab") as handle:
                handle.write(b"tamper")
            with self.assertRaisesRegex(verifier.VerificationError, "byte length mismatch"):
                verifier.verify_manifest(run / "manifest.json", repo)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory(prefix="leveled-verifier-synthetic-") as temporary:
            root = Path(temporary)
            write_bound(root, "duplicate.json", b'{"status":"PASS","status":"FAIL"}')
            with self.assertRaisesRegex(verifier.VerificationError, "duplicate JSON key"):
                verifier.read_json(root / "duplicate.json")


if __name__ == "__main__":
    unittest.main()
