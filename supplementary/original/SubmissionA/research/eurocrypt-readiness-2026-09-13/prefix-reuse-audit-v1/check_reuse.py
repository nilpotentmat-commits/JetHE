"""Exact public admission and reuse ledgers. No HE, samples, primes or timing."""
from fractions import Fraction
from hashlib import sha256
from importlib.util import spec_from_file_location, module_from_spec
from math import isqrt
from pathlib import Path
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
READY = HERE.parent
ROOT = HERE.parents[3]
OLD = READY.parent / 'check_gaussian_family_resources.py'


def binding(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=sha256(data).hexdigest())


def load_module():
    spec = spec_from_file_location('preserved_gaussian_reference', OLD)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inputs():
    paths = [HERE / n for n in ('PLAN.md', 'PROOF.md', 'check_reuse.py')]
    paths += [OLD, READY / 'MULTI_JOB_READINESS_AUDIT.md']
    paths += [READY / 'manuscript' / n for n in (
        'sections/prepared-composition.tex', 'appendices/resource-ledgers.tex',
        'appendices/gaussian-security-family.tex', 'appendices/prepared-modulus-details.tex',
        'appendices/fast-prepared-work.tex')]
    paths += [READY / 'gaussian-relay-audit-v1/PROOF.md']
    return {p.relative_to(ROOT).as_posix(): binding(p) for p in paths}


def next_power_two(value):
    return 1 << (value - 1).bit_length()


def strict_exponent(value):
    assert 0 < value < 1
    exponent = value.denominator.bit_length() - value.numerator.bit_length()
    if value >= Fraction(1, 1 << exponent):
        exponent -= 1
    assert Fraction(1, 1 << (exponent + 1)) <= value < Fraction(1, 1 << exponent)
    return exponent


def recount(lam, k, radix, exponent, gadget):
    """Iterate the positive recurrence without using the synthesis closed form."""
    d = (lam - 1).bit_length()
    L = 1 << d
    tau, M, kappa = d - k, (1 << k) - 1, 511 * L
    fresh = (2 * kappa * lam + 1) * lam
    delta = kappa * (1 << (radix - 1)) * lam * gadget
    carry = (kappa + 1) // 2
    prefix = fresh + M * kappa * (2 * fresh + 2 * fresh * fresh) + (M * kappa + 1) // 2
    current = prefix + 2 * delta
    bounds = [fresh, prefix, current]
    for _ in range(tau):
        transported = current + delta
        raw = kappa * (transported + fresh + 2 * transported * fresh) + carry
        aligned = current + delta
        following = aligned + raw + 2 * delta + 1
        assert following >= max(transported, raw, aligned, fresh)
        bounds += [transported, raw, aligned, following]
        current = following
    assert max(bounds) == current
    threshold = 2 + 4 * current
    if (1 << exponent) > threshold:
        interval = 'ALL_PRIMES_IN_INTERVAL_ADMITTED'
    elif (1 << (exponent + 1)) <= threshold:
        interval = 'NO_PRIME_IN_INTERVAL_PASSES_THIS_SUFFICIENT_RECURRENCE'
    else:
        interval = 'ACTUAL_Q_REQUIRED_FOR_THIS_SUFFICIENT_RECURRENCE'
    vertex_rows = [1, 2 * gadget]
    for j in reversed(range(tau)):
        vertex_rows.extend((2 * (1 << j) * gadget + 1, 3 * gadget))
    H = gadget * ((1 << (tau + 1)) + 3 * tau)
    I = 2 * M + 1 + tau
    U = H + tau + 1
    assert sum(vertex_rows) == U and len(vertex_rows) == 2 * tau + 2
    source_rows = max(2, *vertex_rows)
    assert source_rows == (2 * gadget if tau == 0 else max(3 * gadget, (1 << tau) * gadget + 1))
    setup = sum(vertex_rows) + tau + 1
    evaluation = 3 * (M + tau) + 2 * H
    warm = evaluation + 2 * I + 1
    assert setup == H + 2 * tau + 2
    assert warm == 7 * M + 5 * tau + 2 * H + 3
    assert warm - 2 * setup == 7 * M + tau - 1 > 0
    assert (M + H + 1) ** 2 >= 8 * gadget * L
    return dict(parameter=lam, length=L, dimension=256 * L, levels=d, prefix=k, tail=tau,
                radix_bits=radix, interval_exponent=exponent, modulus_bits=exponent + 1,
                gadget=gadget, admission=interval, checked_bounds=len(bounds), final_bound=current,
                inputs=I, hint_rows=H, vertex_rows=vertex_rows, source_rows=source_rows,
                source_rows_with_reserved_pivots=source_rows + lam, public_keys=tau + 1,
                vertex_secrets=2 * tau + 2, setup_gaussians=H + 3 * tau + 3,
                uniform_setup_polynomials=U, gaussian_draws_per_batch=3 * I,
                ring_products_setup=setup, ring_products_evaluation=evaluation,
                ring_products_warm=warm, decompositions_per_batch=2 + 3 * tau,
                codec_calls_per_batch=I + 1, owner_products_per_batch=16 * (M - k))


def horizon(row, B):
    lam, d, N = row['parameter'], row['levels'], row['dimension']
    I, H, tau = row['inputs'], row['hint_rows'], row['tail']
    G = row['setup_gaussians'] + B * row['gaussian_draws_per_batch']
    U = row['uniform_setup_polynomials']
    root = isqrt(lam * d * d)
    W = root + int(root * root != lam * d * d) + 1
    J = 2 * W + 1
    rho = N * (16 * Fraction(1, 1 << (2 * lam)) + Fraction(1, 1 << (4 * d * d))
               + 5 * J * Fraction(1, 1 << (8 * d * d)))
    budget = (U * N + 1) * Fraction(1, 1 << (4 * d * d)) + G * rho + 2 * G * N * Fraction(1, 1 << (2 * lam))
    transitions = len(row['vertex_rows']) + B * I
    padded = next_power_two(transitions)
    assert padded >= transitions and (padded == 1 or padded // 2 < transitions)
    R = row['ring_products_setup'] + B * row['ring_products_warm']
    x, g, L = 1 << row['prefix'], row['gadget'], row['length']
    expanded = (7 * B * x + 2 * (2 * B + 1) * g * L // x
                + (3 * (2 * B + 1) * g + 5 * B + 2) * tau + 2 - 4 * B)
    assert R == expanded
    assert H + B * I >= 2 * L // x + B * x
    if B <= 2 * L:
        assert (H + B * I) ** 2 >= 8 * B * L
    else:
        assert H + B * I >= 2 * L + B
    return dict(batches=B, gaussian_polynomials=G, uniform_polynomials=U,
                query_positions=B * I, row_hybrids=len(row['vertex_rows']),
                padded_hybrids=padded, source_gap_factor=2 * padded,
                failure_budget_strict_upper_exponent=strict_exponent(budget),
                ring_products_total=R, ring_products_amortized=str(Fraction(R, B)),
                explicit_public_and_batch_objects=H + tau + 1 + B * (I + 1))


def main():
    assert __debug__
    before = inputs()
    old = load_module()
    families, profiles, horizons, comparisons = [], 0, 0, 0
    for lam in (256, 257, 512, 1024, 4096, 65536):
        d = (lam - 1).bit_length()
        L = 1 << d
        target = L * (d + 1) ** 2
        balanced = min(d, next(k for k in range(d + 8) if 1 << (2 * k) >= target))
        for radix in (1, 4, 48):
            base = old.synthesize(lam, balanced, radix)
            ref = recount(lam, balanced, radix, base['modulus_bits'] - 1, base['gadget'])
            rows = []
            for k in range(1, d + 1):
                own = old.synthesize(lam, k, radix)
                row = recount(lam, k, radix, own['modulus_bits'] - 1, own['gadget'])
                assert row['admission'] == 'ALL_PRIMES_IN_INTERVAL_ADMITTED'
                assert (row['inputs'], row['hint_rows'], row['uniform_setup_polynomials']) == (own['inputs'], own['hint_rows'], own['uniform_polynomials'])
                assert row['setup_gaussians'] + 3 * row['inputs'] == own['gaussian_polynomials']
                shared = recount(lam, k, radix, base['modulus_bits'] - 1, base['gadget'])
                row['balanced_interval_test'] = dict(admission=shared['admission'], source_rows=shared['source_rows'],
                    original_source_rows=ref['source_rows'], source_projection_available=shared['source_rows'] <= ref['source_rows'],
                    correctness_and_source_projection=(shared['admission'] == 'ALL_PRIMES_IN_INTERVAL_ADMITTED' and shared['source_rows'] <= ref['source_rows']))
                row['horizons'] = [horizon(row, B) for B in sorted(set((1, 2, 16, 1024, L, L * L)))]
                profiles += 1
                comparisons += row['checked_bounds'] + shared['checked_bounds']
                horizons += len(row['horizons'])
                rows.append(row)
            minima = []
            warm_min = min(r['ring_products_warm'] for r in rows)
            for idx in range(len(rows[0]['horizons'])):
                B = rows[0]['horizons'][idx]['batches']
                best = min(r['horizons'][idx]['ring_products_total'] for r in rows)
                winners = [r for r in rows if r['horizons'][idx]['ring_products_total'] == best]
                assert all(2 * B * r['ring_products_warm'] <= (2 * B + 1) * warm_min for r in winners)
                minima.append(dict(batches=B, prefixes=[r['prefix'] for r in winners], ring_products_total=best,
                                   scope='Minimum ring-product count over these own-interval profiles; not complete time or matched security'))
            families.append(dict(parameter=lam, radix_bits=radix, balanced_prefix=balanced,
                                 balanced_modulus_bits=base['modulus_bits'], balanced_source_rows=ref['source_rows'],
                                 warm_ring_count_minimizers=[r['prefix'] for r in rows if r['ring_products_warm'] == warm_min],
                                 ring_count_minima=minima, profiles=rows))
    assert inputs() == before
    out = dict(status='PREFIX_REUSE_EXACT_ADMISSION_AND_COUNT_AUDIT_PASS', families=families,
               parameter_radix_families=len(families), prefix_profiles=profiles, horizon_profiles=horizons,
               own_and_balanced_interval_bound_comparisons=comparisons,
               source_bindings=before, new_he_execution=False, new_timing=False,
               primes_selected=0, gaussian_polynomials_sampled=0, security_bits=None,
               general_proof_machine_checked=False, global_runtime_optimum=False,
               scope='Exact finite recurrences, source inventories and count minima; manual asymptotic proof is separate')
    (HERE / 'audit.json').write_text(json.dumps(out, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in out.items() if k not in ('families', 'source_bindings')}, indent=2))
    for f in families:
        if f['radix_bits'] == 48:
            print(json.dumps(dict(parameter=f['parameter'], balanced=f['balanced_prefix'],
                 min_count_prefixes={str(x['batches']): x['prefixes'] for x in f['ring_count_minima']},
                 same_source_admitted=[r['prefix'] for r in f['profiles'] if r['balanced_interval_test']['correctness_and_source_projection']]), separators=(',', ':')))


if __name__ == '__main__':
    main()
