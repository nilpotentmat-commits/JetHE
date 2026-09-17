"""Public smaller-carrier layouts/codelets; no HE keys or security estimates."""
from math import gcd, prod
from random import Random

from check_composition_rns_arithmetic import (CERTIFICATES, OddNormal, normal_axis,
                                             full_counts, Arithmetic, tensor_run)
from check_fused_composition_frontier import FastField, fused_maps, apply_weights, bsgs_support

SMALL_PLANS = {
    'C4096': dict(m=4096, kappa=15841, groups=16, FM=41504, IM=41504, FA=98304, IA=98304,
                  neg=0, conductor=4369, delta=2026, gamma=4115, D=2, twist=15, factors=(17, 257)),
    'C8192': dict(m=8192, kappa=47523, groups=8, FM=87104, IM=91200, FA=212992, IA=208896,
                  neg=4096, conductor=13107, delta=2026, gamma=12853, D=4, twist=14, factors=(3, 17, 257)),
    'C16384': dict(m=16384, kappa=110887, groups=4, FM=186496, IM=186496, FA=462848, IA=471040,
                   neg=4096, conductor=21845, delta=11291, gamma=21591, D=8, twist=4, factors=(5, 17, 257)),
}


def signed_weights(old):
    result = {}
    for (flip, shift), diagonal in old.items():
        if not flip:
            result[0, shift] = list(diagonal)
        else:
            for half, sign in ((0, 1), (1, -1)):
                mask = [x if i // 128 == half else 0 for i, x in enumerate(diagonal)]
                if any(mask):
                    result[sign, shift] = mask
    return result


def physical_auto(vector, exponent, plan, field):
    delta, shift = exponent
    out, D = [], plan['D']
    for a in range(D):
        for c in range(128):
            aa, cc = a + delta, c + shift
            twist = (plan['twist'] * (aa // D) + 8 * (cc // 128)) % 16
            x = vector[128 * (aa % D) + cc % 128]
            out.append(field.exponents[(field.logs[x] * (1 << twist)) % 65535] if x else 0)
    return out


def physical_bsgs(weights, vector, plan, field, width):
    maps = {e: mask * (plan['D'] // 2) for e, mask in weights.items()}
    babies, giants = bsgs_support([maps], width)
    baby_values = {j: physical_auto(vector, (0, j), plan, field) for j in babies}
    accum = {e: [0] * len(vector) for e in giants}
    for (delta, shift), mask in maps.items():
        j, giant = shift % width, (delta, shift - shift % width)
        # Inverse delta is NEGATION, not the old involutory XOR action.
        twisted = physical_auto(mask, (-giant[0], -giant[1]), plan, field)
        accum[giant] = [x ^ field.mul(w, b) for x, w, b in zip(accum[giant], twisted, baby_values[j])]
    out = [0] * len(vector)
    for e, values in accum.items():
        out = [x ^ y for x, y in zip(out, physical_auto(values, e, plan, field))]
    return out


def small_methods(maps, raw, kappa):
    c, nu, d = len(maps), 2 if raw else 1, sum(len(m) for m in maps)
    result = [dict(name='direct' + ('_raw' if raw else ''), banks=nu * d, switch=nu * d,
                   destinations=1, ext=nu * d, decompositions=nu * c, public_products=d,
                   additive_constant=d - 2)]
    for width in (1, 2, 4, 8, 16, 32, 64, 128, 256):
        babies, giants = bsgs_support(maps, width)
        v, h = len(babies), len(giants)
        result.append(dict(name=f'bsgs{width}' + ('_raw' if raw else ''), banks=nu * v + h,
                           switch=nu * d * kappa + h, destinations=2, ext=nu * c * v + h,
                           decompositions=nu * c + h, public_products=2 * d,
                           additive_constant=2 * d - c * v - h - 2))
    result.append(dict(name='signed_tree' + ('_raw' if raw else ''), banks=19 + 2 * (nu - 1),
                       switch=d * kappa * (8 + nu), destinations=9, ext=c * (1278 + 2 * (nu - 1)),
                       decompositions=c * (510 + nu), public_products=2 * d,
                       additive_constant=2 * d - 1278 * c - 2))
    return result


def physical_tree(weights, vector, plan, field):
    leaves, edges = {0: vector}, 0
    for bit in range(8):
        next_leaves = {}
        for exponent, values in leaves.items():
            next_leaves[exponent] = values
            next_leaves[exponent + (1 << bit)] = physical_auto(values, (0, 1 << bit), plan, field)
            edges += 2  # Both identity and generator HE edges are charged.
        leaves = next_leaves
    out = [0] * len(vector)
    for shift, values in leaves.items():
        for delta in (-1, 0, 1):
            moved = physical_auto(values, (delta, 0), plan, field)
            edges += 1
            if (delta, shift) in weights:
                mask = weights[delta, shift] * (plan['D'] // 2)
                out = [x ^ field.mul(w, y) for x, w, y in zip(out, mask, moved)]
    assert edges == 1278
    return out


def small_priced_options(weights, g, width, channels, plan):
    pre, odd, even = weights
    k, G, m = plan['kappa'], plan['groups'], plan['m']
    p, h, fresh = len(pre), len(odd) + len(even), (2 * k + 1) * 20
    lam, results = k * g * (1 << (width - 1)) * 20, []
    for pm in small_methods([pre], False, k):
        for raw in (False, True):
            for qm in small_methods([odd, even], raw, k):
                separate = int(not raw)
                D = G * (pm['decompositions'] + qm['decompositions'] + 4 * separate)
                E = G * (pm['ext'] + qm['ext'] + 1 + 4 * separate)
                public = G * (pm['public_products'] + qm['public_products'] + 1)
                point = 2 * g * E + public + 6 * G
                A = G * (2 * g * pm['ext'] + pm['additive_constant']
                         + 2 * g * qm['ext'] + qm['additive_constant']
                         + 2 * g + 1 + 5 + separate * (8 * g - 2))
                gain = k * (h * k * (1 + 2 * fresh) * p * k + 1)
                before = pm['switch'] * lam + (p * k + 1) // 2
                product = k * ((1 + 2 * fresh) * before + fresh) + (k + 1) // 2 + 2 * separate * lam
                constant = k * h * product + (qm['switch'] + 1) * lam + ((h + 1) * k + 1) // 2
                results.append(dict(pre=pm['name'], post=qm['name'], raw=raw, decomps=D, ext=E,
                                    point=point, point_add=A, banks=pm['banks'] + qm['banks'] + 1 + 2 * separate,
                                    destinations=pm['destinations'] + qm['destinations'] + separate,
                                    a=gain, z=constant,
                                    price=channels * (D * (g * plan['FM'] + plan['IM']) + point * m)
                                          + D * m * channels * (channels - 1) // 2))
    assert len({r['a'] for r in results}) == 1
    return results


def public_carrier_checks(field):
    rng, result = Random(2026090841), {}
    old_maps = [fused_maps(b, field) for b in range(5, 9)]
    converted = [tuple(signed_weights(m) for m in maps) for maps in old_maps]
    assert [[len(m) for m in maps] for maps in converted] == [[89, 88, 85], [185, 184, 181], [377, 376, 373], [761, 760, 757]]
    prime, generator, _ = CERTIFICATES[0]
    for kind, plan in SMALL_PLANS.items():
        conductor, delta, gamma, D = plan['conductor'], plan['delta'], plan['gamma'], plan['D']
        assert pow(delta, D, conductor) == pow(2, plan['twist'], conductor)
        assert pow(gamma, 128, conductor) == pow(2, 8, conductor)
        representatives = {(a, c): pow(delta, a, conductor) * pow(gamma, c, conductor) % conductor
                           for a in range(D) for c in range(128)}
        assert len({r * pow(2, e, conductor) % conductor for r in representatives.values() for e in range(16)}) == plan['m']
        assert all(gcd(r, conductor) == 1 for r in representatives.values())
        matrix_cases = 0
        for job in range(D // 2):
            for row in range(256):
                u, c = divmod(row, 128)
                for column in range(256):
                    uu, cc = divmod(column, 128)
                    auto = pow(delta, uu - u, conductor) * pow(gamma, (cc - c) % 256, conductor) % conductor
                    assert representatives[u + 2 * job, c] * auto % conductor == representatives[uu + 2 * job, cc]
                    matrix_cases += 1
        bsgs_cases, tree_cases = 0, 0
        for originals, maps in zip(old_maps, converted):
            vector = [rng.randrange(65536) for _ in range(128 * D)]
            for original, new in zip(originals, maps):
                reference = sum([apply_weights(original, vector[j:j + 256], field) for j in range(0, len(vector), 256)], [])
                for width in (32, 64, 128, 256):
                    assert physical_bsgs(new, vector, plan, field, width) == reference
                    bsgs_cases += 1
                if originals is old_maps[-1]:
                    assert physical_tree(new, vector, plan, field) == reference
                    tree_cases += 1
        axes = [OddNormal(f, prime, generator) if f in (3, 5) else normal_axis(f, prime, generator) for f in plan['factors']]
        assert (full_counts(axes).mul, full_counts(axes).add, full_counts(axes).neg) == (plan['FM'], plan['FA'], plan['neg'])
        assert (full_counts(axes, True).mul, full_counts(axes, True).add, full_counts(axes, True).neg) == (plan['IM'], plan['IA'], plan['neg'])
        vector = [rng.randrange(prime) for _ in range(plan['m'])]
        encoded = tensor_run(vector, axes, Arithmetic(prime))
        assert tensor_run(encoded, axes, Arithmetic(prime), inverse=True) == vector
        result[kind] = dict(matrix_entry_cases=matrix_cases, physical_bsgs_cases=bsgs_cases,
                            full_signed_tree_cases=tree_cases, full_tensor_roundtrips=1)
    return result


if __name__ == '__main__':
    print(public_carrier_checks(FastField()))
