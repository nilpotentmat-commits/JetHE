"""Exact current-interface Hasse accounting; no HE run or file output.

The phase fixtures are integer polynomial identities with bounded error
symbols instantiated by deterministic public values. They do not generate
cryptographic keys, row masks, encrypted owner inputs or timing observations.
"""
from hashlib import sha256
from itertools import product
import json
from math import prod
from pathlib import Path
from random import Random


ROOT = Path(__file__).resolve().parents[3]
PRIMES = (1152921504002872321, 1152921503566671361,
          1152921503264686081, 1152921503096916481)
STAGES = ((8, 4, 5), (4, 4, 5), (2, 3, 4), (1, 2, 3))
L, N, KAPPA, WIDTH, BETA = 256, 65536, 130816, 48, 20
FRESH = (2 * KAPPA + 1) * BETA


def digits(value, width, count):
    base, limit = 1 << width, 1 << (width - 1)
    result = []
    for _ in range(count - 1):
        digit = (value + limit) % base - limit
        result.append(digit)
        value = (value - digit) // base
    result.append(value)
    assert max(map(abs, result), default=0) <= limit
    return result


def arithmetic_profile(changed):
    moduli = {a: prod(PRIMES[:a]) for a in range(1, 5)}
    delta = lambda g: KAPPA * g * (1 << (WIDTH - 1)) * BETA
    raw = FRESH + 15 * KAPPA * ((1 + 2 * FRESH) * FRESH + FRESH)
    raw += (15 * KAPPA + 1) // 2
    bound = raw + 2 * delta(5)
    assert moduli[4] > 2 + 4 * bound
    records = []
    old_limbs = 4
    rows, row_limbs, families = 10, 40, 2  # unchanged prefix rekey
    for r, a, g in STAGES:
        assert g == (moduli[a].bit_length() + WIDTH - 1) // WIDTH
        if a != old_limbs:
            assert a == old_limbs - 1
            dropped = PRIMES[a]
            bound = (2 * bound - 1 + (KAPPA + 2) * dropped) // (2 * dropped)
        entry = bound
        d = delta(g)
        hasse_increment = 3 * d // 2 if r in changed else d
        hasse = bound + hasse_increment
        bypass = bound + d
        raw_product = KAPPA * ((1 + 2 * FRESH) * hasse + FRESH) + (KAPPA + 1) // 2
        rekeyed_product = raw_product + 2 * d
        bound = bypass + rekeyed_product + 1
        assert all(moduli[a] > 2 + 4 * value for value in
                   (entry, hasse, bypass, raw_product, rekeyed_product, bound))
        hasse_families = r + 1 if r in changed else 2 * r
        stage_families = hasse_families + 3  # bypass and two product banks
        stage_rows = stage_families * g
        rows += stage_rows
        row_limbs += stage_rows * a
        families += stage_families
        records.append(dict(r=r, limbs=a, gadget=g, entry_bound=entry,
                            hasse_increment=hasse_increment, hasse_bound=hasse,
                            bypass_bound=bypass, raw_product_bound=raw_product,
                            rekeyed_product_bound=rekeyed_product,
                            final_bound=bound, hasse_families=hasse_families,
                            hasse_rows=hasse_families*g, stage_rows=stage_rows,
                            strict_margin=moduli[a]-2-4*bound,
                            whole_margin_bits=(moduli[a]//(2+4*bound)).bit_length()-1,
                            admitted=True))
        old_limbs = a
    # Every row consists of two dimension-N arrays of 64-bit RNS words.
    raw_hint_bytes = row_limbs * 2 * N * 8
    return dict(changed_orders=sorted(changed, reverse=True), stages=records,
                final_bound=bound, hint_families=families, hint_rows=rows,
                hint_row_limbs=row_limbs, raw_hint_bytes=raw_hint_bytes,
                raw_public_key_bytes=17*2*N*8,
                raw_input_bytes=137*2*N*8, raw_output_bytes=2*2*N*8,
                independent_keys=10, public_keys=5, owner_inputs=35,
                maximum_receiving_row_batch=max(1, 10, *(
                    count for x in records for count in
                    (x['hasse_rows']+1, 3*x['gadget']))))


def phase_checks():
    rng = Random(2026091301)
    counts = dict(integral_phase_identities=0, support_positions=0,
                  actual_radix_boundary_values=0, signed_digit_reuses=0)
    for a, g in ((4, 5), (3, 4), (2, 3)):
        q, base, limit = prod(PRIMES[:a]), 1 << WIDTH, 1 << (WIDTH-1)
        values = {0, 1, -1, q//2, -(q//2)}
        for power in range(g):
            for sign, offset in product((-1, 1), (-1, 0, 1)):
                v = sign * (limit * base**power + offset)
                if abs(v) <= q//2:
                    values.add(v)
        for value in values:
            ds = digits(value, WIDTH, g)
            assert sum(d*base**j for j, d in enumerate(ds)) == value
            assert sum((-d)*base**j for j, d in enumerate(ds)) == -value
            counts['actual_radix_boundary_values'] += 1
            counts['signed_digit_reuses'] += 1
    for length in (2, 4, 8, 16):
        for p in (3, 5):
            dimension = length * (p-1)
            kappa = length * (2*p-3)

            def add(x, y):
                return [a+b for a, b in zip(x, y)]

            def mul(x, y):
                out = [0] * dimension
                for i, xv in enumerate(x):
                    if not xv:
                        continue
                    ai, bi = divmod(i, p-1)
                    for j, yv in enumerate(y):
                        if not yv:
                            continue
                        aj, bj = divmod(j, p-1)
                        target_a = (ai+aj) % length
                        target_b = (bi+bj+2) % p
                        value = xv*yv*(-1 if ai+aj >= length else 1)
                        if target_b:
                            out[target_a*(p-1)+target_b-1] += value
                        else:
                            for b in range(p-1):
                                out[target_a*(p-1)+b] -= value
                return out

            def shift(x, exponent):
                out = [0]*dimension
                for i in range(length):
                    quotient, target = divmod(i+exponent, length)
                    for b in range(p-1):
                        out[target*(p-1)+b] = (-1 if quotient%2 else 1)*x[i*(p-1)+b]
                return out

            def hasse(x, r):
                out = [0]*dimension
                for i in range(length):
                    if i & r:
                        out[(i-r)*(p-1):(i-r+1)*(p-1)] = x[i*(p-1):(i+1)*(p-1)]
                return out

            def signed_relative(x, r, j):
                out = [0]*dimension
                for i in range(j, length, r):
                    for b in range(p-1):
                        out[(i-j)*(p-1)+b] = (-1 if i&r else 1)*x[i*(p-1)+b]
                return out

            for r in (1, 2, 4, 8):
                if r >= length:
                    continue
                assert sum(1 for i in range(length) if i&r) == length//2
                for j in range(r):
                    assert len(range(j, length, r)) == length//r
                    counts['support_positions'] += length//r
                counts['support_positions'] += length//2
                for width in (2, 4):
                    g, beta, input_cap = 4, 2, 3
                    base, limit = 1 << width, 1 << (width-1)
                    for _ in range(4):
                        c1 = [rng.randrange(-17, 18) for _ in range(dimension)]
                        secret = [rng.randrange(-2, 3) for _ in range(dimension)]
                        mu = [rng.randrange(2) for _ in range(dimension)]
                        error = [rng.randrange(-input_cap, input_cap+1) for _ in range(dimension)]
                        intended = [m+2*e for m, e in zip(mu, error)]
                        c0 = [v-z for v, z in zip(intended, mul(c1, secret))]
                        scalar_digits = [digits(v, width, g) for v in c1]
                        dg = [[scalar_digits[i][j] for i in range(dimension)] for j in range(g)]
                        coefficient_maps = [lambda x: hasse(x, r)]
                        coefficient_maps += [lambda x, j=j: signed_relative(x, r, j) for j in range(r)]
                        payloads = [secret] + [hasse(shift(secret, j), r) for j in range(r)]
                        output = hasse(c0, r)
                        insertion = [0]*dimension
                        for transform, payload in zip(coefficient_maps, payloads):
                            transformed_digits = [transform(x) for x in dg]
                            target = transform(c1)
                            assert all(sum(base**j*transformed_digits[j][i] for j in range(g)) == target[i]
                                       for i in range(dimension))
                            for j, d in enumerate(transformed_digits):
                                assert max(map(abs, d)) <= limit
                                primitive_error = [rng.randrange(-beta, beta+1) for _ in range(dimension)]
                                row_phase = [base**j*x+2*e for x, e in zip(payload, primitive_error)]
                                output = add(output, mul(d, row_phase))
                                insertion = add(insertion, mul(d, primitive_error))
                        final_error = add(hasse(error, r), insertion)
                        expected = [m+2*e for m, e in zip(hasse(mu, r), final_error)]
                        assert output == expected
                        assert max(map(abs, insertion)) <= 3*kappa*g*limit*beta//2
                        assert max(map(abs, final_error)) <= input_cap+3*kappa*g*limit*beta//2
                        assert all(x in (0, 1) for x in hasse(mu, r))
                        counts['integral_phase_identities'] += 1
    return counts


def main():
    reference = arithmetic_profile(set())
    all_maps = arithmetic_profile({8, 4, 2, 1})
    strict_savings = arithmetic_profile({8, 4, 2})
    assert (reference['hint_rows'], reference['hint_row_limbs']) == (203, 754)
    assert (strict_savings['hint_rows'], strict_savings['hint_row_limbs']) == (149, 542)
    assert all_maps['raw_hint_bytes'] == strict_savings['raw_hint_bytes']
    assert all_maps['final_bound'] > strict_savings['final_bound'] > reference['final_bound']
    sources = ['SubmissionA/research/composition_full_run.py',
               'SubmissionA/research/check_composition_modulus_chain.py',
               'SubmissionA/research/check_composition_rns_arithmetic.py',
               'SubmissionA/sections/prepared-composition.tex',
               'SubmissionA/sections/leveled-construction.tex',
               'SubmissionA/research/core-resolution/norm-one-hasse-frontier-v1.tex']
    print(json.dumps(dict(status='CURRENT_INTERFACE_PAID_HASSE_ANALYSIS_PASS',
                          phase_checks=phase_checks(), reference=reference,
                          all_maps=all_maps, strict_row_savings=strict_savings,
                          deltas=dict(hint_rows=54, hint_row_limbs=212,
                                      raw_hint_bytes=212*2*N*8,
                                      external_product_residue_multiplications=424*N,
                                      masked_row_setup_residue_multiplications=212*N),
                          source_hashes={p: sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},
                          scope=dict(production_he_execution=False,
                                     new_backend_implementation=False,
                                     timing_or_peak_memory_measurement=False,
                                     security_level_estimate=False,
                                     file_output=False)), indent=2))


if __name__ == '__main__':
    main()
