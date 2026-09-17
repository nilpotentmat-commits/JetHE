"""Portable finite checks for JetHE; Python 3.10+ and the standard library.

These executions do not certify proofs, evaluate encrypted workloads, sample
Gaussian keys, estimate security, or implement the cited modern matrix exponent.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from fractions import Fraction
from hashlib import sha256
from io import StringIO
import json
from math import factorial
from pathlib import Path
from random import Random
import sys

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE / "lib"))


def capture_main(module):
    stream = StringIO()
    with redirect_stdout(stream):
        module.main()
    return json.loads(stream.getvalue())


def codec():
    import codec as implementation
    return capture_main(implementation)


def worked_example():
    import worked_example as implementation
    return capture_main(implementation)


def hasse():
    import hasse_transport as transport
    import hasse_minors as minors
    cases = [transport.case(length, q, order, fixture)
             for length in (2, 4, 8)
             for q in (17, 97, 315, 65537)
             for order in (1 << j for j in range(length.bit_length() - 1))
             for fixture in range(3)]
    assert len(cases) == 72
    production = minors.production_minors()
    assert production["tested_minors"] == 64
    return {
        "toy_transport_cases": cases,
        "toy_odd_conductor": 5,
        "row_ledgers": transport.count_rows(),
        "production_residue_minors": production,
        "scope": "Public affine identities and selected unit minors; the universal payload minimum remains a written theorem.",
    }


def admission():
    import admission_bounds as bounds
    trace = bounds.trace_spec()
    digits = [bounds.digits(a, w) for a, w in zip(bounds.CHAIN, bounds.WIDTHS)]
    families = [2, 12, 8, 6, 2]
    rows = sum(f * d for f, d in zip(families, digits))
    pairs = sum(f * d * a for f, d, a in zip(families, digits, bounds.CHAIN))
    public = pairs + sum(bounds.CHAIN)
    incoming = [1, 8, 37, 12, 16, 9, 10, 9, 5]
    assert digits == [4, 4, 3, 3, 2]
    assert (rows, pairs, public, sum(incoming), max(incoming)) == (102, 284, 297, 107, 37)
    exponential_lower = sum(
        (Fraction(225, 2) ** j / factorial(j) for j in range(513)), Fraction()
    )
    union_upper = Fraction(1024 * 59 * 2 * bounds.N, 1) / exponential_lower
    assert union_upper < Fraction(1, 2**129)
    assert trace[-1][-1] == 72824530783593675310113562548789870
    return {
        "states": [dict(state=n, key=k, limbs=a, components=c,
                        error_bound=str(b), strict_margin=str(bounds.Q[a] - 2 - 4*b))
                   for n, k, a, c, b in trace],
        "stage_widths": bounds.WIDTHS,
        "chain": bounds.CHAIN,
        "digits": digits,
        "hint_rows": rows,
        "hint_row_prime_pairs": pairs,
        "public_raw_MiB": public,
        "incoming_rows": incoming,
        "fixed_batches": 1024,
        "polynomial_bad_events": 59,
        "ideal_failure_strict_upper": "2^-129",
        "bound_method": "513 positive Taylor terms give an exact rational lower bound for exp(225/2)",
        "optimistic_exclusions": [bounds.optimistic_exclusion(w) for w in ("prefix", "h8", "h2")],
        "scope": "Arithmetic implications of the existing fixed-input concentration proof; its probabilistic independence premises are not verified by this program.",
    }


def fixed_field():
    import fixed_field as witness
    import boolean_screen as boolean
    symbolic = [witness.symbolic_check(length) for length in (8, 16, 32)]
    powers, _ = boolean.powers(8)
    truth_rank, evaluations = boolean.truth_table_check(8, powers)
    assert truth_rank == symbolic[0]["full_boolean_rank"]
    rng = Random(20260914)
    points = [witness.point_checks(8, [a << 1 for a in range(128)])]
    for length in (16, 32, 64):
        assignments = [0, 2, (1 << length) - 2]
        assignments += [rng.getrandbits(length - 1) << 1 for _ in range(16)]
        points.append(witness.point_checks(length, assignments))
    return {
        "symbolic": symbolic,
        "length8_truth_rank": truth_rank,
        "length8_truth_coefficient_evaluations": evaluations,
        "point_checks": points,
        "count_table": witness.count_table(),
        "scope": "Exact finite Boolean ranks and coefficient witnesses, plus integer count formulas; no finite-to-asymptotic extrapolation.",
        "bounded_subset_of_original_campaign": True,
    }


def encoding():
    import encoding as implementation
    return implementation.check()


def gaussian():
    import gaussian_family as family
    import gaussian_budget as budget
    cases = []
    for parameter in (256, 257, 511, 512, 513, 1024, 4095, 4096, 65536):
        d = (parameter - 1).bit_length()
        for k in range(1, d + 1):
            for radix in (1, 4, 48):
                cases.append(budget.budget(family.synthesize(parameter, k, radix)))
    assert len(cases) == 285
    states = sum(row["admitted_states"] for row in cases)
    assert states == 1719
    selected = next(row for row in cases if
                    (row["parameter"], row["prepared"], row["radix_bits"]) == (256, 8, 48))
    assert (selected["modulus_bits"], selected["hint_rows"], selected["inputs"],
            selected["gaussian_polynomials"], selected["uniform_polynomials"]) == (195, 12, 511, 1548, 13)
    assert selected["new_budget"]["strict_upper_exponent"] == 229
    assert selected["tables"]["raw_threshold_bytes"] == 550600848
    cdf = family.rounded_cdf_checks()
    assert (cdf["exhaustive_weight_laws"], cdf["enumerated_uniform_inputs"]) == (4077, 375084)
    constants = budget.finite_constants()
    constants["general_monotonicity_and_distribution_arguments"] = "paper/appendices/gaussian-security-family.tex (prop:gaussian-prepared-workflow)"
    return {
        "constants": constants,
        "parameter_cases": len(cases),
        "admitted_complete_states": states,
        "selected": selected,
        "rounded_cdf": cdf,
        "cases": cases,
        "scope": "Exact Gaussian reference recurrence, inventory and sufficient probability-budget arithmetic. No Gaussian tables, samples, primes or cryptographic keys are generated.",
    }


def arithmetic():
    import exact_arithmetic as implementation
    result = implementation.check()
    result["proof_scope"] = "Finite exact arithmetic checks; general argument: paper/appendices/fast-prepared-work.tex (lem:fast-physical-products)."
    return result


def rational_matrix():
    import rational_matrix as implementation
    implementation.check_tensor()
    rng = Random(20260915)
    integer_cases = 0
    for n in (1, 2, 4, 8):
        for _ in range(5):
            a = [[rng.randrange(-(1 << 256), 1 << 256) for _ in range(n)] for _ in range(n)]
            b = [[rng.randrange(-(1 << 256), 1 << 256) for _ in range(n)] for _ in range(n)]
            assert implementation.exact_kernel(a, b) == implementation.naive(a, b)
            integer_cases += 1
    fixtures = []
    cases = [(e, ell, q, False) for e in (1, 2, 4) for ell in (1, 2) for q in (2, 6, 15)]
    cases += [(2, 1, q, True) for q in (2, 6, 15)]
    cases += [(2, 1, (1 << 60) - 93, False), (2, 1, ((1 << 60)-93)*((1 << 60)-107), False)]
    for e, ell, q, dense in cases:
        def polynomial():
            if dense:
                return {(i, j): q-1 for i in range(ell) for j in range(1, 257)}
            p = {(rng.randrange(ell), rng.randrange(1, 257)): rng.randrange(q) for _ in range(4)}
            p[ell-1, 256] = q-1
            p[ell-1, 1] = q-1
            return p
        a, b = ([[polynomial() for _ in range(e)] for _ in range(e)] for _ in range(2))
        assert implementation.packed_product(a, b, ell, q) == implementation.oracle_product(a, b, ell, q)
        fixtures.append(dict(relative_width=e, quotient_length=ell, modulus=str(q), dense=dense))
    theta = Fraction(593, 250)
    threshold, prefix = 1 / (theta-1), (theta-2) / (theta-1)
    assert (threshold, prefix, 1+prefix) == (Fraction(250,343), Fraction(93,343), Fraction(436,343))
    for d in range(8, 257):
        k = (2*93*d+343)//(2*343)
        assert 1 <= k <= d and 2*abs(343*k-93*d) <= 343
    return {
        "integer_matrix_cases": integer_cases,
        "ring_matrix_fixtures": fixtures,
        "arithmetic_counts": dict(implementation.COUNTS),
        "theta": str(theta),
        "work_exponent": str(1+prefix),
        "threshold_exponent": str(threshold),
        "prefix_exponent": str(prefix),
        "prefix_rounding_cases": 249,
        "kernel": "rescaled Strassen, denominator 2, integer exact division by 8",
        "modern_exponent_kernel_implemented": False,
        "bounded_subset_of_original_campaign": True,
        "scope": "Finite rational-kernel and quotient-ring packing checks, including noninvertible denominators; the fast asymptotic matrix theorem remains a written result.",
    }


def batched_hasse():
    import batched_hasse as implementation
    algebra, coefficients = implementation.algebra_cases()
    traces = implementation.trace_cases()
    return {
        "algebra_cases": algebra,
        "algebra_coefficients_compared": coefficients,
        "trace_cases": traces,
        "scope": "Known public ciphertext-shaped arrays; direct versus joint Hasse transport and following algebraic states. No encryption or cryptographic sampling.",
    }


CHECKS = {
    "codec": codec, "worked-example": worked_example, "hasse": hasse,
    "admission": admission, "fixed-field": fixed_field, "encoding": encoding,
    "gaussian": gaussian, "arithmetic": arithmetic,
    "rational-matrix": rational_matrix, "batched-hasse": batched_hasse,
}


def verify_packaged_sources():
    manifest = json.loads((HERE / "provenance.json").read_text(encoding="utf-8"))
    files = manifest["files"] + manifest.get("new_files", [])
    for entry in files:
        path = HERE / entry["path"]
        actual = sha256(path.read_bytes()).hexdigest()
        if actual != entry["packaged_sha256"]:
            raise ValueError(f"Packaged source hash mismatch: {entry['path']}")
    return len(files)


def main():
    if not __debug__:
        raise RuntimeError("Assertions are required: do not use Python -O or -OO.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="List finite check groups.")
    parser.add_argument("--check", action="append", choices=tuple(CHECKS), help="Run selected groups; repeat to select several. Default: all.")
    parser.add_argument("--output", type=Path, help="Write detailed JSON to a new file; never overwrites an earlier result.")
    args = parser.parse_args()
    if args.list:
        print("\n".join(CHECKS))
        return
    if args.output and args.output.exists():
        raise FileExistsError(f"Output already exists: {args.output}")
    verified = verify_packaged_sources()
    names = args.check or list(CHECKS)
    results = {}
    for name in names:
        print(f"Running finite check: {name}", file=sys.stderr, flush=True)
        results[name] = CHECKS[name]()
    report = {
        "schema": "jethe-portable-theory-checks-v1",
        "status": "FINITE_CHECKS_PASS",
        "checks": results,
        "packaged_sources_hash_verified": verified,
        "provenance_manifest_sha256": sha256((HERE / "provenance.json").read_bytes()).hexdigest(),
        "python": sys.version.split()[0],
        "proof_certification": False,
        "new_he_execution": False,
        "performance_benchmark": False,
        "numerical_security_qualification": False,
        "scope": "Only the finite configurations stated in each check were executed; no coverage claim for the entire supplement.",
    }
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    print(json.dumps(dict(status=report["status"], checks=list(results),
                          packaged_sources_hash_verified=verified,
                          detailed_output=args.output.name if args.output else None), indent=2))


if __name__ == "__main__":
    main()
