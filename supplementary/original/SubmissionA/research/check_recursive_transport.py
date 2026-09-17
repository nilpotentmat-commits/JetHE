"""Bounded public algebra checks; no HE keys, security estimates or timings.

The sparse coordinates omit the independent E=O_257 factor. Its final
normal-basis Frobenius permutation is checked separately. Integer signs,
prime-power cyclotomic reduction and common-ring module actions are retained.
"""
from collections import defaultdict
from fractions import Fraction


def clean(x):
    return {b: c for b, c in x.items() if c}


def aux_reduce(n, p, j):
    if j == 0:
        assert n == 0
        return {0: 1}
    t = p ** (j - 1)
    n %= p * t
    if n < (p - 1) * t:
        return {n: 1}
    return {r * t + n % t: -1 for r in range(p - 1)}


def mono(v, z, d, p, j):
    sign = -1 if (v // d) % 2 else 1
    return {(v % d, k): sign * c for k, c in aux_reduce(z, p, j).items()}


def add_into(out, x, scale=1):
    for b, c in x.items():
        out[b] += scale * c


def mul(x, y, d, p, j):
    out = defaultdict(int)
    for (v, z), c in x.items():
        for (w, u), f in y.items():
            add_into(out, mono(v + w, z + u, d, p, j), c * f)
    return clean(out)


def down(x, a, p, j):
    out = defaultdict(int)
    for (v, z), c in x.items():
        out[v // a, (p * z if j > 1 else 0) + v % a] += c
    return clean(out)


def fold(x, d, p, j):
    out = defaultdict(int)
    for (v, z), c in x.items():
        add_into(out, mono(2 * v, z, d, p, j), c)
    return clean(out)


def up(x, a, p, j):
    out = defaultdict(int)
    for (v, z), c in x.items():
        i, previous_z = (z % p, z // p) if j > 1 else (z, 0)
        if v % 2 == 0 and i < a:
            out[2 * i + a * v, previous_z] += c
    return clean(out)


def dim_aux(p, j):
    return 1 if j == 0 else (p - 1) * p ** (j - 1)


def inventory(d, a, p, k):
    assert a >= 2 and a & (a - 1) == 0 and p - 1 >= a
    assert d % (a ** k) == 0 and d // a ** k >= 2
    degrees = [d // a ** j for j in range(k + 1)]
    dims = [degrees[j] * dim_aux(p, j) for j in range(k + 1)]
    ranks = [None] + [p - 1] + [p] * (k - 1)
    exact = 2 * (sum(a * dims[j] for j in range(1, k + 1))
                 + degrees[k] * dims[k]
                 + sum(2 * ranks[j] * dims[j - 1] for j in range(1, k + 1)))
    closed = 2 * (3 * a * sum(dims[1:]) + degrees[k] * dims[k])
    assert exact == closed and min(dims) == d
    delta = [1] + [p ** (j - 1) * (2 * p - 3) for j in range(1, k + 1)]
    noise = sum(delta[j - 1] * degrees[j - 1]
                * (2 + Fraction(ranks[j], a)) for j in range(1, k + 1))
    noise += delta[k] * degrees[k]
    assert noise.denominator == 1
    return Fraction(exact, d), int(noise), dims


def check_maps():
    profiles = [(32, 4, 5, 2), (128, 4, 5, 3), (64, 2, 3, 5),
                (512, 16, 17, 2), (64, 4, 7, 2)]
    columns = identities = norm_rows = 0
    for d, a, p, k in profiles:
        for v in range(d):
            x = {(v, 0): 1}
            for j in range(1, k + 1):
                x = down(x, a, p, j)
            x = fold(x, d // a ** k, p, k)
            for j in range(k, 0, -1):
                x = up(x, a, p, j)
            assert x == mono(2 * v, 0, d, p, 0)
            columns += 1
        for j in range(1, k + 1):
            dj, prev = d // a ** j, d // a ** (j - 1)
            hprev, h = dim_aux(p, j - 1), dim_aux(p, j)
            stages = [
                (prev, j - 1, dj, j, lambda x: down(x, a, p, j),
                 [(a, 0, 1, 0)] + ([(0, 1, 0, p)] if j > 1 else []), 1),
                (dj, j, prev, j - 1, lambda x: up(x, a, p, j),
                 [(2, 0, 2 * a, 0)] + ([(0, p, 0, 1)] if j > 1 else []), 1)]
            if j == k:
                stages.append((dj, j, dj, j, lambda x: fold(x, dj, p, j),
                               [(0, 1, 0, 1)], 2))
            for sd, sj, td, tj, action, generators, expected_norm in stages:
                row_abs = defaultdict(int)
                for v in range(sd):
                    for z in range(dim_aux(p, sj)):
                        for b, c in action({(v, z): 1}).items():
                            row_abs[b] += abs(c)
                assert max(row_abs.values()) == expected_norm
                norm_rows += len(row_abs)
                # Boundary exponents exercise prime-power and dyadic carries.
                for v in sorted({0, sd // 2, sd - 1}):
                    for z in sorted({0, dim_aux(p, sj) - 1}):
                        x = {(v, z): 1}
                        for sv, sz, tv, tz in generators:
                            lhs = action(mul(mono(sv, sz, sd, p, sj), x, sd, p, sj))
                            rhs = mul(mono(tv, tz, td, p, tj), action(x), td, p, tj)
                            assert lhs == rhs, (d, a, p, k, j, lhs, rhs)
                            identities += 1
        inventory(d, a, p, k)
    permutation = [(2 * b) % 257 for b in range(1, 257)]
    assert sorted(permutation) == list(range(1, 257))
    return columns, identities, norm_rows


def check_growth():
    profiles = [(p, j) for p in (3, 5, 7) for j in (1, 2, 3)] + [(17, 2)]
    pairs = 0
    for p, j in profiles:
        h = dim_aux(p, j)
        rows = defaultdict(int)
        for u in range(h):
            for v in range(h):
                for b, c in aux_reduce(u + v, p, j).items():
                    rows[b] += abs(c)
                pairs += 1
        assert max(rows.values()) == p ** (j - 1) * (2 * p - 3)
    return len(profiles), pairs


def check_resources():
    # k=1 specializes exactly to the proved three-tunnel theorem.
    one_level = 0
    for a, p in [(2, 3), (4, 5), (4, 7), (8, 11), (16, 17)]:
        for b in (2, 4, 8, 16, 32):
            d = a * b
            ratio, noise, _ = inventory(d, a, p, 1)
            assert ratio == 2 * (p - 1) * (3 + Fraction(d, a * a))
            assert noise == 2 * d + (3 * p - 4) * b
            one_level += 1
    stop_cases = 0
    for d in (32, 64, 128, 256, 512, 1024, 2048):
        for k in range(1, 6):
            if d % (4 ** (k + 1)) or d // 4 ** (k + 1) < 2:
                continue
            before = inventory(d, 4, 5, k)[0]
            after = inventory(d, 4, 5, k + 1)[0]
            b = d // 4 ** k
            assert (after < before) == (b > Fraction(240, 11))
            stop_cases += 1
    expected = {(32, 1): (40, 152), (64, 1): (56, 304),
                (128, 2): (74, 1392), (256, 2): (94, 2784)}
    for (d, k), values in expected.items():
        got = inventory(d, 4, 5, k)
        assert got[:2] == values, (d, k, got, values)
    return one_level, stop_cases


if __name__ == '__main__':
    print('maps (basis columns, module identities, norm rows):', check_maps())
    print('multiplication gains (profiles, basis pairs):', check_growth())
    print('resources (one-level reductions, stopping cases):', check_resources())
    for d, k in [(32, 1), (32, 2), (64, 1), (64, 2), (128, 2), (256, 2)]:
        ratio, noise, dims = inventory(d, 4, 5, k)
        print(f'D={d}, k={k}: K/(gm)={ratio}, noise/lambda={noise}, '
              f'carrier dimensions/e={dims}')
    print('PASS: public algebra only; no HE/security/performance admission.')
