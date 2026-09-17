"""Public phase algebra and exact modulus/bit counts, not HE execution.

No cryptographic keys, ciphertexts, samplers, timing samples or attack estimates
are produced. The odd moduli below are correctness envelopes, not secure or
transform-qualified parameter choices.
"""
from fractions import Fraction
from math import gcd, isqrt
from random import Random

from check_frobenius_chain import multiply, psi
from check_recursive_transport import inventory


def norm(x):
    return max((abs(v) for v in x.values()), default=0)


def plus(x, y, scale=1):
    out = dict(x)
    for b, c in y.items():
        out[b] = out.get(b, 0) + scale * c
    return {b: c for b, c in out.items() if c}


def digits(x, b):
    """Centered q_b representative; the final digit may equal +128."""
    g = (b + 7) // 8
    out = []
    for _ in range(g - 1):
        r = (x + 128) % 256 - 128
        out.append(r)
        x = (x - r) // 256
    out.append(x)
    assert max(map(abs, out)) <= 128
    return out


def square_bound(d, B, g, beta=20, e=256):
    kappa = (2 * e - 1) * d
    return 2 * kappa * B * (B + 1) + (kappa + 1) // 2 + 2 * g * kappa * 128 * beta


def linear_bound(d, k, B, g, beta=20):
    _, factor, _ = inventory(d, 4, 5, k)
    return 2 * B + 1 + factor * 511 * g * 128 * beta


def tree_bound(d, B, g, beta=20):
    levels = d.bit_length() - 1
    assert 1 << levels == d
    return 2 * B + 1 + levels * d ** 3 * 511 * g * 128 * beta


def automorphism(x, u):
    d = len(x)
    out = [0] * d
    for i, c in enumerate(x):
        out[(u * i) % d] += c * (-1 if ((u * i) // d) % 2 else 1)
    return out


def a_multiply(x, u):
    d, r = len(x), (2 - u) % (2 * len(x))
    y = automorphism(x, pow(r, -1, 2 * d))
    total, prefix, out = sum(y), 0, []
    for c in y:
        prefix += c
        out.append(2 * prefix - total)
    return automorphism(out, r)


def convolution(x, y):
    d, out = len(x), [0] * len(x)
    for i, c in enumerate(x):
        for j, v in enumerate(y):
            out[(i + j) % d] += c * v * (-1 if i + j >= d else 1)
    return out


def tree_checks():
    rng = Random(20260908)
    columns = public_products = normalized_rows = 0
    for d in (2, 4, 8, 16, 32, 64, 128):
        generators = [-1] + [pow(5, 1 << j, 2 * d)
                             for j in range(d.bit_length() - 2)]
        reached = [1]
        for u in generators:
            reached += [(v * u) % (2 * d) for v in reached]
        assert sorted(reached) == list(range(1, 2 * d, 2))
        for i in range(d):
            x = [int(j == i) for j in range(d)]
            actual = [0] * d
            for u in reached:
                term = a_multiply(automorphism(x, u), u)
                actual = [a + b for a, b in zip(actual, term)]
            expected = [0] * d
            expected[(2 * i) % d] = d * (-1 if 2 * i >= d else 1)
            assert actual == expected
            columns += 1
        x = [rng.randrange(-20, 21) for _ in range(d)]
        for u in reached:
            au = automorphism([1] * d, (2 - u) % (2 * d))
            assert a_multiply(x, u) == convolution(au, x)
            public_products += 1
        # Public toy error recurrences: every switched row error is divisible
        # by d. Pure dyadic coefficient multiplication has gain d.
        if d <= 16:
            branches = [(1, [0] * d)]
            for u in generators:
                next_branches = []
                for label, err in branches:
                    for selected in (1, u):
                        mapped = automorphism(err, selected)
                        digit = [rng.randrange(-2, 3) for _ in range(d)]
                        eta = [rng.randrange(-1, 2) for _ in range(d)]
                        addition = convolution(digit, eta)
                        next_branches.append((label * selected % (2 * d),
                                              [v + d * w for v, w in zip(mapped, addition)]))
                branches = next_branches
            total = [0] * d
            for u, err in branches:
                term = a_multiply(err, u)
                total = [v + w for v, w in zip(total, term)]
            assert all(v % d == 0 for v in total)
            assert max(abs(v // d) for v in total) <= len(generators) * d ** 3 * 2
        for q in (31, 63, 127):
            inverse = pow(d, -1, q)
            assert len({a * inverse % q for a in range(q)}) == q
            for a in range(q):
                s, shift, eta = 7, 13, a % 5 - 2
                value = (-a * s + shift + 2 * d * eta) % q
                assert inverse * value % q == (-(inverse * a % q) * s
                                               + inverse * shift + 2 * eta) % q
                normalized_rows += 1
    return columns, public_products, normalized_rows


def minimum_bits(bound):
    for b in range(3, 1025):
        g, q = (b + 7) // 8, (1 << b) - 1
        if q > 2 + 4 * bound(g):
            assert all((1 << j) - 1 <= 2 + 4 * bound((j + 7) // 8)
                       for j in range(3, b))
            return b, g, bound(g)
    raise AssertionError('bounded public envelope search exceeded1024bits')


def max_input(d, k, b, ordinary):
    g, q = (b + 7) // 8, (1 << b) - 1
    lam = 511 * g * 128 * 20
    if ordinary:
        kap = 511 * d
        cap = (q - 3 - 4 * ((kap + 1) // 2) - 8 * d * lam) // (8 * kap)
        result = (isqrt(1 + 4 * cap) - 1) // 2 if cap >= 0 else -1
        bound = lambda B: square_bound(d, B, g)
    else:
        factor = inventory(d, 4, 5, k)[1]
        result = (q - 7 - 4 * factor * lam) // 8
        bound = lambda B: linear_bound(d, k, B, g)
    if result >= 0:
        assert 2 + 4 * bound(result) < q
        assert 2 + 4 * bound(result + 1) >= q
    return result


def phase_checks():
    rng = Random(20260908)
    count = 0
    for p, d in [(3, 2), (3, 8), (5, 4), (17, 4), (257, 128)]:
        basis = [(i, j) for i in range(d) for j in range(1, p)]
        kap = (2 * (p - 1) - 1) * d
        for B in (0, 1, 7, 1 << 20):
            for _ in range(4):
                chosen = rng.sample(basis, min(24, len(basis)))
                mu = {b: 1 for b in chosen if rng.randrange(2)}
                err = {b: rng.randrange(-B, B + 1) for b in chosen}
                phase = plus(mu, err, 2)
                raw = multiply(phase, phase, d, p)
                binary_square = {b: c % 2 for b, c in multiply(mu, mu, d, p).items()
                                 if c % 2}
                frob = {b: c % 2 for b, c in psi(mu, d, p).items() if c % 2}
                assert binary_square == frob
                residual = plus(raw, binary_square, -1)
                assert all(c % 2 == 0 for c in residual.values())
                out_error = {b: c // 2 for b, c in residual.items()}
                bound = 2 * kap * B * (B + 1) + (kap + 1) // 2
                assert norm(out_error) <= bound
                # Two arbitrary bounded digit/error products model the
                # complete-payload bank errors, independently of key masks.
                digit = {b: rng.randrange(-128, 129) for b in chosen[:8]}
                eta = {b: rng.randrange(-20, 21) for b in chosen[:8]}
                switched = multiply(digit, eta, d, p)
                assert norm(switched) <= kap * 128 * 20
                total = plus(out_error, switched, 2)
                assert norm(total) <= bound + 2 * kap * 128 * 20
                count += 1
    return count


def digit_checks():
    rng = Random(20260908)
    count = 0
    for b in list(range(3, 18)) + [24, 32, 48, 52, 64, 115, 127, 128, 129, 255]:
        q = (1 << b) - 1
        values = list(range(-(q // 2), q // 2 + 1)) if b <= 9 else [
            -(q // 2), -(q // 2) + 1, -128, -1, 0, 1, 127, 128, q // 2 - 1, q // 2]
        values += [rng.randrange(-(q // 2), q // 2 + 1) for _ in range(16)]
        for x in values:
            ds = digits(x, b)
            assert sum(v * 256 ** j for j, v in enumerate(ds)) == x
            count += 1
    return count


def resource_checks():
    B, d, k, m = 1 << 48, 128, 2, 32768
    linear = minimum_bits(lambda g: linear_bound(d, k, B, g))
    ordinary = minimum_bits(lambda g: square_bound(d, B, g))
    tree = minimum_bits(lambda g: tree_bound(d, B, g))
    assert linear[:2] == (52, 7)
    assert ordinary[:2] == (115, 15)
    assert tree[:2] == (52, 7)
    recursive_coprime = next(b for b in range(linear[0], 1025)
                            if gcd((1 << b) - 1, 2 * 257 * 5) == 1
                            and (1 << b) - 1 > 2 + 4 * linear_bound(d, k, B, (b + 7) // 8))
    assert recursive_coprime == 53
    assert 74 * 7 * m * recursive_coprime == 899612672
    assert gcd((1 << ordinary[0]) - 1, 2 * 257) == 1
    assert gcd((1 << tree[0]) - 1, 2 * 257) == 1
    assert inventory(d, 4, 5, k)[0] == 74
    linear_bits, ordinary_bits = 74 * linear[1] * m * linear[0], 4 * ordinary[1] * m * ordinary[0]
    assert (linear_bits, ordinary_bits) == (882638848, 226099200)
    same_q = (1 << 127) - 1
    assert same_q > 2 + 4 * square_bound(d, B, 16)
    assert same_q > 2 + 4 * linear_bound(d, k, B, 16)
    assert Fraction(74 * 16 * m, 4 * 16 * m) == Fraction(37, 2)
    maxima = [max_input(d, k, 127, ordinary=x) for x in (False, True)]
    print('D128 correctness-only minimal (bits,digits,noise):', linear, ordinary)
    print('D128 serialized hint bits (linear,ordinary):', linear_bits, ordinary_bits)
    print('D128 tree minimal (bits,digits,noise):', tree)
    print('D128 tree serialized hint bits:', 4 * 7 * tree[1] * m * tree[0])
    assert same_q > 2 + 4 * tree_bound(d, B, 16)
    assert 4 * 7 * 7 * m * 52 == 333971456
    print('fixed-q127 correctness-bounded input maxima (linear,ordinary):', maxima)
    family = 0
    for exponent in range(5, 41):
        d = 1 << exponent
        k = (exponent - 1) // 2  # a4, bounded terminal2or4
        lin = minimum_bits(lambda g: linear_bound(d, k, d * d, g))
        sq = minimum_bits(lambda g: square_bound(d, d * d, g))
        tr = minimum_bits(lambda g: tree_bound(d, d * d, g))
        assert lin[0] <= 4 * exponent + 40
        assert sq[0] <= 6 * exponent + 40
        assert tr[0] <= 6 * exponent + 40
        ratio = inventory(d, 4, 5, k)[0]
        assert 4 * sq[0] * sq[1] < ratio * lin[0] * lin[1]
        family += 1
    return family


if __name__ == '__main__':
    print('phase and bank-error fixtures:', phase_checks())
    print('signed radix256 exact decompositions:', digit_checks())
    print('linear tree (trace columns, public products, normalized rows):', tree_checks())
    print('polynomial-envelope bit profiles:', resource_checks())
    print('PASS: exact public algebra/cost bounds only; no security qualification.')
