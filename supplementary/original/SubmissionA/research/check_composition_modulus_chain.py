"""Attained leveled RNS schedules, not HE execution or secure parameters.

The scan is a declared control: global digit width, stagewise field-cheapest
direct/BSGS/tree option, nonincreasing prime-prefix moduli, and prime-at-a-time
parity-preserving drops between complete two-component stages. It is NOT a
cost/noise Pareto optimum over all possible compilers or drop positions.
"""
from itertools import combinations_with_replacement
from math import prod
from random import Random
import json

from check_composition_rns_arithmetic import (
    CERTIFICATES, KAPPA_J, KAPPA_C, BETA, native_noise, native_receipt,
    admit_rns, conventional_schedule_receipt, priced_conventional_options,
    FastField, fused_maps,
)
from check_composition_small_carriers import SMALL_PLANS, signed_weights, small_priced_options, public_carrier_checks

PRIMES = [c[0] for c in CERTIFICATES]
MODULI = [1] + [prod(PRIMES[:a]) for a in range(1, 9)]
WIDTHS = (8, 16, 24, 32, 40, 48, 56, 60)
PLANS = {
    'J': dict(m=65536, kappa=KAPPA_J, groups=1, FM=721408, IM=721664, A=1572864, neg=0),
    'C': dict(m=32768, kappa=KAPPA_C, groups=2, FM=389376, IM=405760, A=991232, neg=24576),
}
PLANS.update(SMALL_PLANS)
FIELDS = ('M', 'A', 'neg', 'crt_coefficients', 'crt_growing_products', 'digit_coefficients',
          'digit_channel_lifts', 'hint_bytes', 'drop_coefficients', 'drop_channel_lifts',
          'banks', 'rows', 'input_ciphertexts', 'input_bytes')
FIELDS += ('mask_bytes_upper', 'owner_public_key_bytes')


def empty():
    return dict.fromkeys(FIELDS, 0)


def add(left, right):
    return {key: left[key] + right[key] for key in FIELDS}


def gadget(a, width):
    return (MODULI[a].bit_length() + width - 1) // width


def admit(B, a):
    return MODULI[a] > 2 + 4 * B


def prefix_noise(kind, g, width):
    p = PLANS[kind]
    k, fresh = p['kappa'], (2 * p['kappa'] + 1) * BETA
    lam = (511 if kind == 'J' else k) * g * (1 << (width - 1)) * BETA
    return (fresh + 15 * k * ((1 + 2 * fresh) * fresh + fresh)
            + (15 * k + 1) // 2 + (512 if kind == 'J' else 2) * lam)


def tail_noise(kind, B, g, width, option):
    if kind != 'J':
        return option['a'] * B + option['z']
    k, fresh = KAPPA_J, (2 * KAPPA_J + 1) * BETA
    lam = 511 * g * (1 << (width - 1)) * BETA
    return B + 768 * lam + k * ((1 + 2 * fresh) * (B + 256 * lam) + fresh) + (k + 1) // 2 + 1


def stage_cost(kind, stage, a, width, option=None):
    p, out, g = PLANS[kind], empty(), gadget(a, width)
    m, groups = p['m'], p['groups']
    if stage == 0:
        decomps, inputs, banks = 2 * groups, 31 * groups, 2
        point_m, point_a = groups * (45 + 4 * g), groups * (75 + 4 * g)
        extra_m, extra_a = 0, 0
    elif kind == 'J':
        r, decomps, inputs = 1 << (4 - stage), 3, 1
        h, banks = 2 * r, 2 * r + 3
        point_m = point_a = (4 * r + 6) * g + 3
        extra_m = m * (2 * h * (h.bit_length() - 1) - 3 * h + 4) // (2 * h)
        extra_a = m * (2 * (h.bit_length() - 1) - 1)
    else:
        decomps, inputs, banks = option['decomps'], 2 * groups, option['banks']
        point_m, point_a = option['point'], option['point_add'] + 2 * groups
        extra_m, extra_a = 0, 0
    F, I, T = 2 * inputs + decomps * g, decomps, a * (a - 1) // 2
    out.update(M=a * (F * p['FM'] + I * p['IM'] + point_m * m + extra_m) + decomps * m * T,
               A=a * (F * p.get('FA', p.get('A')) + I * p.get('IA', p.get('A')) + point_a * m + extra_a) + decomps * m * T,
               neg=a * (F + I) * p['neg'], crt_coefficients=decomps * m,
               crt_growing_products=decomps * m * (a - 1), digit_coefficients=decomps * m * g,
               digit_channel_lifts=a * decomps * m * g, hint_bytes=2 * banks * g * m * a * 8,
               banks=banks, rows=banks * g, input_ciphertexts=inputs, input_bytes=2 * inputs * m * a * 8)
    out['owner_public_key_bytes'] = 2 * m * a * 8
    if kind != 'J' and stage:
        out['mask_bytes_upper'] = option['mask_terms'] * m * a * 8
    return out


def export_cost(kind, a):
    p, out = PLANS[kind], empty()
    poly, m, T = 2 * p['groups'], p['m'], a * (a - 1) // 2
    out.update(M=poly * (a * p['IM'] + m * T), A=poly * (a * p.get('IA', p.get('A')) + m * T),
               neg=poly * a * p['neg'], crt_coefficients=poly * m,
               crt_growing_products=poly * m * (a - 1))
    return out


def drop_noise(B, kappa, prime):
    return (2 * B - 1 + (kappa + 2) * prime) // (2 * prime)


def drop(kind, B, source, target):
    """Only the dropped channel is inverted; no full-q CRT is used."""
    p, total = PLANS[kind], empty()
    poly, m = 2 * p['groups'], p['m']
    for a in range(source, target, -1):
        remain, cost = a - 1, empty()
        B = drop_noise(B, p['kappa'], PRIMES[a - 1])
        if not admit(B, remain):
            return None, None
        cost.update(M=poly * (p['IM'] + remain * p['FM'] + remain * m),
                    A=poly * (p.get('IA', p.get('A')) + remain * p.get('FA', p.get('A')) + remain * m), neg=poly * a * p['neg'],
                    drop_coefficients=poly * m, drop_channel_lifts=poly * remain * m)
        total = add(total, cost)
    return B, total


def minimum_options(field):
    options = {}
    for stage in range(1, 5):
        weights = fused_maps(stage + 4, field)
        signed = tuple(signed_weights(m) for m in weights)
        for kind in ('C', *SMALL_PLANS):
            for a in range(1, 9):
                for width in WIDTHS:
                    choices = (priced_conventional_options(weights, gadget(a, width), width, a) if kind == 'C'
                               else small_priced_options(signed, gadget(a, width), width, a, PLANS[kind]))
                    chosen = min(choices, key=lambda o: (o['price'], o['point_add'], o['z']))
                    chosen['mask_terms'] = sum(len(m) for m in (weights if kind == 'C' else signed)) + 1
                    options[kind, stage, a, width] = chosen
    return options


def run_schedule(kind, chain, width, options):
    a, B, cost, stages, selected = chain[0], None, empty(), [], []
    for stage, current in enumerate(chain):
        if stage:
            B, scaling = drop(kind, B, a, current)
            if B is None:
                return None
            cost = add(cost, scaling)
        a, g = current, gadget(current, width)
        option = options[kind, stage, a, width] if kind != 'J' and stage else None
        B = prefix_noise(kind, g, width) if stage == 0 else tail_noise(kind, B, g, width, option)
        if not admit(B, a):
            return None
        cost = add(cost, stage_cost(kind, stage, a, width, option))
        stages.append({'channels': a, 'gadget': g, 'noise': B, 'margin': MODULI[a] - 2 - 4 * B})
        if option:
            selected.append([option['pre'], option['post']])
    # No final drop: output has the last complete-stage modulus. An optional
    # additional terminal normalization is a different declared boundary.
    cost = add(cost, export_cost(kind, a))
    return dict(kind=kind, chain=chain, width=width, stages=stages, methods=selected, cost=cost)


def fixed_modulus_checks(options):
    native = admit_rns(CERTIFICATES, lambda g: native_noise(g, 48), 48)
    target = native_receipt(native)
    actual = run_schedule('J', [4] * 5, 48, options)['cost']
    assert (actual['M'], actual['A'], actual['hint_bytes']) == (target['total_field_multiplications'], target['additions'], target['prepared_hint_bytes'])
    schedule = [options['C', s, 8, 60] for s in range(1, 5)]
    target = conventional_schedule_receipt(MODULI[8], 8, 60, schedule)
    actual = run_schedule('C', [8] * 5, 60, options)['cost']
    assert (actual['M'], actual['A'], actual['neg'], actual['hint_bytes']) == (target['total_field_multiplications'], target['additions'], target['negations'], target['prepared_hint_bytes'])
    return 2


def polynomial_mul(x, y):
    result, n = [0] * len(x), len(x)
    for i, a in enumerate(x):
        for j, b in enumerate(y):
            result[(i + j) % n] += a * b * (-1 if i + j >= n else 1)
    return result


def public_drop_checks():
    rng, cases, phases = Random(2026090831), 0, 0
    for source in range(2, 9):
        q, prime, target = MODULI[source], PRIMES[source - 1], MODULI[source - 1]
        values = [0, 1, -1, q // 2, -(q // 2), prime // 2, -prime // 2, prime - 1, 1 - prime]
        values += [rng.randrange(-(q // 2), q // 2 + 1) for _ in range(64)]
        for x in values:
            residue = x % prime
            remainder = residue - prime if residue & 1 else residue
            y = (x - remainder) // prime
            assert remainder % 2 == 0 and abs(remainder) < prime and (y - x) % 2 == 0
            assert all(((x % p - remainder % p) * pow(prime, -1, p)) % p == y % p for p in PRIMES[:source - 1])
            assert abs(prime * y - x) < prime
            cases += 1
        for _ in range(24):
            n, B = 4, 100
            secret = [rng.randrange(-1, 2) for _ in range(n)]
            mu, noise = [rng.randrange(2) for _ in range(n)], [rng.randrange(-B, B + 1) for _ in range(n)]
            c1 = [rng.randrange(q) for _ in range(n)]
            product = polynomial_mul(c1, secret)
            c0 = [(m + 2 * e - v) % q for m, e, v in zip(mu, noise, product)]
            switched = []
            for component in (c0, c1):
                residues = [x % prime for x in component]
                remainder = [x - prime if x & 1 else x for x in residues]
                switched.append([((x - r) // prime) % target for x, r in zip(component, remainder)])
            product = polynomial_mul(switched[1], secret)
            phase = [(x + v) % target for x, v in zip(switched[0], product)]
            phase = [x - target if x > target // 2 else x for x in phase]
            assert all((x - m) % 2 == 0 for x, m in zip(phase, mu))
            assert max(abs((x - m) // 2) for x, m in zip(phase, mu)) <= drop_noise(B, n, prime)
            phases += 1
    return dict(scalar_rns_drop_cases=cases, public_integer_phase_cases=phases)


def main():
    field = FastField()
    options, results = minimum_options(field), {}
    assert fixed_modulus_checks(options) == 2
    for kind in PLANS:
        valid, tested, best = 0, 0, None
        for increasing in combinations_with_replacement(range(1, 9), 5):
            chain = list(reversed(increasing))
            for width in WIDTHS:
                tested += 1
                row = run_schedule(kind, chain, width, options)
                if row:
                    valid += 1
                    if best is None or row['cost']['M'] < best['cost']['M']:
                        best = row
        assert best
        results[kind] = dict(tested=tested, admitted=valid, selected=best)
    print(json.dumps(dict(status='PUBLIC_ATTAINED_LEVELED_MODULUS_CHAIN_ONLY',
                          fixed_modulus_replays=2, drop_checks=public_drop_checks(),
                          carrier_checks=public_carrier_checks(field), results=results), indent=2))


if __name__ == '__main__':
    main()
