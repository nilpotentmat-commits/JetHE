"""Read-only, independent checks for measured leveled-library comparisons.

The plaintext oracle uses packed integer XOR products, independently of the
producer's coefficient arithmetic.  Checking recorded measurements does not
independently certify security or prove historical execution/non-overwriting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from pathlib import Path
from typing import Any


class VerificationError(ValueError):
    """A record violates the declared comparison contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def integer(value: Any, name: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, f"{name}: invalid integer")
    return value


def finite_number(value: Any, name: str, positive: bool = False) -> float:
    require(type(value) in (int, float), f"{name}: invalid number")
    result = float(value)
    require(math.isfinite(result), f"{name}: non-finite number")
    require(result > 0 if positive else result >= 0, f"{name}: invalid sign")
    return result


def close(actual: Any, expected: float, name: str) -> None:
    actual_value = finite_number(actual, name)
    require(math.isclose(actual_value, expected, rel_tol=1e-8, abs_tol=1e-9),
            f"{name}: {actual_value} != recomputed {expected}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    try:
        result = json.loads(path.read_text(encoding="utf-8"),
                            object_pairs_hook=_unique_object,
                            parse_constant=lambda value: (_ for _ in ()).throw(
                                VerificationError(f"non-finite JSON token: {value}")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read strict JSON {path}: {error}") from error
    require(type(result) is dict, f"{path}: expected JSON object")
    return result


def carryless_product(left: int, right: int) -> int:
    """Multiply F_2 polynomials stored as integer bit strings."""
    result = 0
    while right:
        low_bit = right & -right
        result ^= left << (low_bit.bit_length() - 1)
        right ^= low_bit
    return result


def oracle_outputs(inputs: Any, jobs: int, factors: int, length: int) -> list[list[int]]:
    require(type(inputs) is list and len(inputs) == jobs, "inputs: job count")
    outputs = []
    for job_index, job in enumerate(inputs):
        require(type(job) is list and len(job) == factors,
                f"inputs[{job_index}]: factor count")
        product = 1
        for factor_index, factor in enumerate(job):
            require(type(factor) is list and len(factor) == length,
                    f"inputs[{job_index}][{factor_index}]: length")
            require(all(type(bit) is int and bit in (0, 1) for bit in factor),
                    "inputs: coefficients must be binary integers")
            require(factor[0] == 1, "inputs: each factor must be a binary unit")
            packed = sum(bit << index for index, bit in enumerate(factor))
            product = carryless_product(product, packed)
        outputs.append([(product >> index) & 1 for index in range(length)])
    return outputs


def check_binding(binding: Any, repo_root: Path) -> Path:
    require(type(binding) is dict, "binding: expected object")
    relative = binding.get("path")
    require(type(relative) is str and bool(relative), "binding: missing path")
    target = (repo_root / relative).resolve()
    require(target.is_relative_to(repo_root.resolve()), "binding: path outside repository")
    require(target.is_file(), f"binding: missing file {relative}")
    raw = target.read_bytes()
    require(integer(binding.get("bytes"), "binding.bytes") == len(raw),
            f"binding: byte length mismatch {relative}")
    require(binding.get("sha256") == hashlib.sha256(raw).hexdigest(),
            f"binding: SHA-256 mismatch {relative}")
    return target


TIMINGS = ("encode", "encrypt", "eval", "decrypt", "decode")
FORBIDDEN_POSITIVE_CLAIMS = {
    "independent_security_certification", "certified_128_bit_security",
    "exactjet", "exactjet_authority", "refresh_authority", "full_refresh_authority",
    "reusable_bootstrap", "reusable_fhe", "publication_authority",
    "failure_probability_certification", "security_authority",
    "exactjet_execution", "refresh_execution", "arbitrary_cyclotomic_security_transfer",
}


def check_claim_boundaries(value: Any) -> None:
    if type(value) is dict:
        for key, child in value.items():
            if key in FORBIDDEN_POSITIVE_CLAIMS:
                require(child is False, f"unsupported positive claim: {key}")
            check_claim_boundaries(child)
    elif type(value) is list:
        for child in value:
            check_claim_boundaries(child)


def triple(samples: list[float]) -> dict[str, float]:
    return {"median": statistics.median(samples), "min": min(samples), "max": max(samples)}


def prime64(value: int) -> bool:
    """Deterministic Miller-Rabin for an unsigned 64-bit modulus."""
    if value < 2 or value >= 1 << 64:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % small == 0:
            return value == small
    odd, twos = value - 1, 0
    while odd % 2 == 0:
        odd //= 2
        twos += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % value == 0:
            continue
        residue = pow(base, odd, value)
        if residue in (1, value - 1):
            continue
        for _ in range(twos - 1):
            residue = residue * residue % value
            if residue == value - 1:
                break
        else:
            return False
    return True


def verify_case(case: dict[str, Any]) -> dict[str, Any]:
    require(case.get("schema") == "leveled-jet-comparison-v1", "case: schema")
    require(case.get("status") == "PASS", "case: producer failed")
    check_claim_boundaries(case)
    require(case.get("security_requested") == "HEStd_128_classic", "security preset")
    require(case.get("independent_security_certification") is False,
            "independent security certification must be false")
    require(case.get("omp_num_threads") == "1", "case OpenMP thread setting")
    require(case.get("scheme") in ("BFV", "BGV"), "scheme")
    layout = case.get("layout")
    require(layout in ("native", "packed_terminal"), "layout")
    schedule = case.get("schedule")
    require(schedule in ("sequential", "balanced"), "schedule")
    length = integer(case.get("length"), "length", 1)
    mults = integer(case.get("mults"), "mults", 1)
    require(length in (4, 8, 16) and mults in (1, 2, 4), "unsupported workload")
    require(integer(case.get("parameter_multiplicative_depth"),
                    "parameter_multiplicative_depth", 1) == mults,
            "parameter depth must equal multiplication count for both schedules")
    jobs = integer(case.get("jobs"), "jobs", 1)
    factors = mults + 1
    dimension = integer(case.get("ring_dimension"), "ring_dimension", 1)
    require(dimension & (dimension - 1) == 0, "ring dimension must be a power of two")
    require(length <= dimension, "jet exceeds native nilpotence index")
    points = factors * (length - 1) + 1
    require(case.get("evaluation_points") == points, "evaluation-point count")
    bound = math.comb(length - 1 + mults, mults)
    require(case.get("integer_low_coefficient_bound") == bound, "integer coefficient bound")
    require(bound < 65537 and points <= 65537, "integer lift is unsafe")
    if layout == "packed_terminal":
        require(case.get("plaintext_modulus") == 65537, "packed plaintext modulus")
        require(65536 % (2 * dimension) == 0, "packed ring lacks complete batching")
        capacity = dimension // points
        require(capacity >= 1, "no packed job fits")
    else:
        require(case.get("plaintext_modulus") == 2, "native plaintext modulus")
        capacity = 1
    batches = (jobs + capacity - 1) // capacity
    depth = mults if schedule == "sequential" else (factors - 1).bit_length()
    expected_counts = {
        "jobs_per_ciphertext_capacity": capacity,
        "ciphertext_batches": batches,
        "input_ciphertexts": batches * factors,
        "output_ciphertexts": batches,
        "ctct_calls_per_trial": batches * mults,
        "ctct_depth": depth,
        "rotation_calls": 0,
        "bootstrap_calls": 0,
        "warmup_trials_excluded": 1,
    }
    for key, expected in expected_counts.items():
        require(integer(case.get(key), key) == expected, f"{key}: incorrect count/depth")

    primes = case.get("ciphertext_q_primes")
    require(type(primes) is list and bool(primes), "ciphertext Q primes missing")
    require(all(type(item) is str and item.isdecimal() for item in primes), "Q prime encoding")
    moduli = [int(item) for item in primes]
    require(all(prime64(item) and (item - 1) % (2 * dimension) == 0 for item in moduli),
            "Q prime or NTT condition")
    require(len(set(moduli)) == len(moduli), "duplicate Q primes")
    q_value = math.prod(moduli)
    require(case.get("ciphertext_q_towers") == len(moduli), "Q tower count")
    require(case.get("ciphertext_q_bits") == q_value.bit_length(), "Q bit count")
    require(abs(finite_number(case.get("ciphertext_q_log2"), "Q log2")
                - sum(math.log2(item) for item in moduli)) <= 2e-6, "Q logarithm")
    p_primes = case.get("key_switching_p_primes")
    require(type(p_primes) is list, "key-switch P primes missing")
    require(all(type(item) is str and item.isdecimal() for item in p_primes), "P prime encoding")
    p_moduli = [int(item) for item in p_primes]
    require(all(prime64(item) and (item - 1) % (2 * dimension) == 0 for item in p_moduli),
            "P prime or NTT condition")
    require(len(set(moduli + p_moduli)) == len(moduli) + len(p_moduli), "Q/P prime overlap")
    p_value = math.prod(p_moduli)
    require(case.get("key_switching_p_bits") == (p_value.bit_length() if p_moduli else 0),
            "P bit count")
    require(case.get("key_switching_qp_bits") == (q_value * p_value).bit_length(), "QP bit count")
    technique = case.get("key_switching_technique")
    require(technique in ("BV", "HYBRID"), "key-switching technique")
    require(bool(p_moduli) == (technique == "HYBRID"), "key-switching P exposure")
    require(case.get("secret_key_distribution") in ("UNIFORM_TERNARY", "GAUSSIAN", "SPARSE_TERNARY"),
            "secret-key distribution missing")
    output_towers = integer(case.get("output_q_towers"), "output_q_towers", 1)
    require(output_towers <= len(moduli), "output Q towers exceed input")
    for key in ("public_key_bytes", "relinearization_key_bytes", "input_bytes", "output_bytes"):
        integer(case.get(key), key, 1)
    for key in ("setup_ms", "precomputation_ms"):
        finite_number(case.get(key), key)
    integer(case.get("peak_rss_bytes"), "peak_rss_bytes")

    expected_outputs = oracle_outputs(case.get("inputs"), jobs, factors, length)
    # Bind exactly the bytes the producer hashes, independently of its PRNG.
    fixture_hash = 14695981039346656037
    for job in case["inputs"]:
        for factor in job:
            for bit in factor:
                fixture_hash = ((fixture_hash ^ bit) * 1099511628211) & ((1 << 64) - 1)
    require(case.get("fixture_fnv1a64") == str(fixture_hash), "fixture hash")
    integer(case.get("fixture_seed"), "fixture_seed")
    trials = case.get("trials")
    repetitions = integer(case.get("repetitions"), "repetitions", 1)
    require(type(trials) is list and len(trials) == repetitions, "trial count")
    require(case.get("verified_output_coefficients_including_warmup")
            == jobs * length * (repetitions + 1), "verified coefficient count")
    samples: dict[str, list[float]] = {name: [] for name in (*TIMINGS, "end_to_end")}
    for trial_index, trial in enumerate(trials):
        require(type(trial) is dict, "trial: expected object")
        require(trial.get("decoded_outputs") == expected_outputs,
                f"trial {trial_index}: independent plaintext oracle mismatch")
        require(all(type(bit) is int for row in trial["decoded_outputs"] for bit in row),
                "decoded outputs must be integer bits")
        total = 0.0
        for name in TIMINGS:
            timing = finite_number(trial.get(name + "_ms"), name + "_ms")
            samples[name].append(timing)
            total += timing
        require(total > 0 and samples["eval"][-1] > 0, "nonpositive timed execution")
        samples["end_to_end"].append(total)
        if "ctct_calls" in trial:
            require(trial["ctct_calls"] == batches * mults, "trial multiplication count")
        if "ctct_depth" in trial:
            require(trial["ctct_depth"] == depth, "trial multiplication depth")
    medians = case.get("median_ms")
    require(type(medians) is dict, "median_ms missing")
    for name, values in samples.items():
        recorded = finite_number(medians.get(name), f"median_ms.{name}")
        # Five individually rounded six-decimal measurements may accumulate error.
        require(abs(recorded - statistics.median(values)) <= 4e-6,
                f"median_ms.{name}: does not match serialized trials")
    return {
        "scheme": case["scheme"], "layout": layout, "schedule": schedule,
        "length": length, "mults": mults, "jobs": jobs,
        "parameter_multiplicative_depth": mults, "ctct_depth": depth,
        "verified_measured_trials": repetitions,
        "verified_measured_output_coefficients": jobs * length * repetitions,
        "timings_ms": {name: triple(values) for name, values in samples.items()},
        "throughput_jobs_per_second": {
            name: triple([1000 * jobs / value for value in samples[name]])
            for name in ("eval", "end_to_end")},
    }


def verify_fixture_matching(cases: list[dict[str, Any]]) -> None:
    fixtures: dict[tuple[int, int, int], Any] = {}
    identities: set[tuple[Any, ...]] = set()
    for case in cases:
        group = tuple(case[key] for key in ("length", "mults", "jobs"))
        identity = group + tuple(case[key] for key in ("scheme", "layout", "schedule"))
        require(identity not in identities, "duplicate case")
        identities.add(identity)
        if group in fixtures:
            require((case["fixture_seed"], case["inputs"]) == fixtures[group],
                    "cross-layout/scheme fixture mismatch")
        else:
            fixtures[group] = (case["fixture_seed"], case["inputs"])


def verify_schedule_profiles(cases: list[dict[str, Any]]) -> None:
    """Schedule comparisons retain one requested and emitted parameter profile."""
    profiles: dict[tuple[Any, ...], tuple[Any, ...]] = {}
    fields = ("parameter_multiplicative_depth", "plaintext_modulus", "ring_dimension",
              "ciphertext_q_primes", "key_switching_p_primes", "security_requested",
              "key_switching_technique", "secret_key_distribution", "scaling_technique",
              "encryption_technique", "multiplication_technique")
    for case in cases:
        group = tuple(case[key] for key in ("scheme", "layout", "length", "mults", "jobs"))
        profile = tuple(case.get(key) for key in fields)
        if group in profiles:
            require(profile == profiles[group], "schedule comparison changed parameter profile")
        else:
            profiles[group] = profile


def verify_manifest(manifest_path: Path, repo_root: Path) -> dict[str, Any]:
    manifest = read_json(manifest_path)
    require(manifest.get("schema") == "nilhe.leveled-library-comparison.manifest.v1", "manifest schema")
    require(manifest.get("status") == "MEASURED_LEVELED_LIBRARY_COMPARISON_ONLY", "manifest status")
    check_claim_boundaries(manifest)
    require(type(manifest.get("run_id")) is str and bool(manifest["run_id"]), "run_id")
    publication = manifest.get("publication")
    require(type(publication) is dict and publication.get("mode") == "exclusive-create"
            and publication.get("overwrites_existing") is False, "publication policy")
    environment = manifest.get("environment")
    require(type(environment) is dict and bool(environment), "environment")
    require(type(environment.get("OMP_NUM_THREADS")) is int
            and environment["OMP_NUM_THREADS"] == 1, "environment OpenMP thread count")
    require(environment.get("OMP_DYNAMIC") == "FALSE", "environment dynamic OpenMP")
    require(environment.get("timed_processes_parallel") is False, "parallel timed processes")
    root = manifest_path.resolve().parent
    sources = manifest.get("source_bindings")
    require(type(sources) is list and bool(sources), "source bindings")
    source_paths = [check_binding(binding, root) for binding in sources]
    require(len(set(source_paths)) == len(source_paths), "duplicate source binding")
    check_binding(manifest.get("executable"), repo_root)
    dependencies = manifest.get("dependencies", [])
    require(type(dependencies) is list, "dependencies")
    for binding in dependencies:
        check_binding(binding, repo_root)
    bindings = manifest.get("cases")
    require(type(bindings) is list and bool(bindings), "cases")
    requested = manifest.get("requested_cases")
    require(type(requested) is list and len(requested) == len(bindings),
            "requested-case coverage count")
    case_paths = [check_binding(binding, root) for binding in bindings]
    require(len(set(case_paths)) == len(case_paths), "duplicate case path")
    cases = [read_json(path) for path in case_paths]
    configuration_keys = {"scheme", "layout", "schedule", "length", "mults", "jobs",
                          "repetitions", "seed"}
    for index, (request, binding, case) in enumerate(zip(requested, bindings, cases)):
        require(type(request) is dict and set(request) == configuration_keys,
                f"requested case {index}: configuration fields")
        for key in ("length", "mults", "jobs", "repetitions", "seed"):
            integer(request[key], f"requested case {index}.{key}", 0 if key == "seed" else 1)
        require(type(binding.get("configuration")) is dict
                and binding["configuration"] == request,
                f"case {index}: ordered requested/bound configuration mismatch")
        for key, expected in request.items():
            output_key = "fixture_seed" if key == "seed" else key
            require(type(case.get(output_key)) is type(expected) and case[output_key] == expected,
                    f"case {index}: requested/actual {key} mismatch")
    summaries = [verify_case(case) for case in cases]
    verify_fixture_matching(cases)
    verify_schedule_profiles(cases)
    return {
        "status": "PASS",
        "scope": "record_integrity_and_independent_plaintext_checks_only",
        "case_count": len(cases),
        "independent_security_certification": False,
        "warmup_outputs_independently_verified": False,
        "historical_execution_or_nonoverwrite_independently_proved": False,
        "case_summaries": summaries,
    }


def check_statistics(samples: list[float], summary: Any, name: str) -> None:
    require(type(summary) is dict, f"{name}: missing summary")
    for key, expected in (("median", statistics.median(samples)),
                          ("min", min(samples)), ("max", max(samples))):
        close(summary.get(key), expected, f"{name}.{key}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repo-root", type=Path,
                        default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    try:
        result = verify_manifest(args.manifest, args.repo_root)
    except (VerificationError, KeyError, TypeError, ValueError) as error:
        print(f"FAIL: {error}")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
