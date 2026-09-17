"""Exact public transform checks and operation counts; not an HE benchmark.

No keys, ciphertexts, files, timing samples, or secret-dependent inputs are
generated. All arithmetic is at the three already certified auxiliary primes.
The plans use radix-two NTTs and a Rader convolution for the normal O_257
basis. O_3 and O_5 use explicit power-basis codelets. The integer ledger
uses first-product assignment instead of adding the first product to zero.
"""

import json
import random
from dataclasses import dataclass
from math import prod

from check_square_tower import check_prepared_transform_ledger


@dataclass
class Counts:
    mul: int = 0
    add: int = 0
    neg: int = 0

    def __add__(self, other):
        return Counts(self.mul + other.mul, self.add + other.add, self.neg + other.neg)

    def __mul__(self, factor):
        return Counts(self.mul * factor, self.add * factor, self.neg * factor)

    def as_dict(self):
        return {"fixed_multiplications": self.mul, "additions_or_subtractions": self.add,
                "negations": self.neg}


class Arithmetic:
    def __init__(self, prime):
        self.p = prime
        self.count = Counts()

    def mul(self, x, y):
        self.count.mul += 1
        return x * y % self.p

    def add(self, x, y):
        self.count.add += 1
        return (x + y) % self.p

    def sub(self, x, y):
        self.count.add += 1
        return (x - y) % self.p

    def neg(self, x):
        self.count.neg += 1
        return -x % self.p


class NTT:
    """Unnormalized transform; known unit butterflies skip multiplication."""

    def __init__(self, length, root, prime):
        assert length & (length - 1) == 0
        assert pow(root, length, prime) == 1
        assert length == 1 or pow(root, length // 2, prime) != 1
        self.n = length
        bits = length.bit_length() - 1
        self.reverse = [int(f"{j:0{bits}b}"[::-1], 2) for j in range(length)]
        self.stages = []
        span = 2
        while span <= length:
            self.stages.append((span, [pow(root, j * length // span, prime)
                                       for j in range(span // 2)]))
            span *= 2

    def run(self, values, arithmetic):
        assert len(values) == self.n
        result = [values[j] for j in self.reverse]
        for span, twiddles in self.stages:
            for start in range(0, self.n, span):
                for j, twiddle in enumerate(twiddles):
                    left = result[start + j]
                    right = result[start + j + span // 2]
                    if j:
                        right = arithmetic.mul(right, twiddle)
                    result[start + j] = arithmetic.add(left, right)
                    result[start + j + span // 2] = arithmetic.sub(left, right)
        return result


class NormalCyclotomic:
    def __init__(self, conductor, index_generator, primitive_root, prime, generator):
        self.n = conductor - 1
        self.r = conductor
        self.p = prime
        self.root = primitive_root
        self.indices = [pow(index_generator, j, conductor) for j in range(self.n)]
        assert set(self.indices) == set(range(1, conductor))
        root_ntt = pow(generator, (prime - 1) // self.n, prime)
        self.forward_ntt = NTT(self.n, root_ntt, prime)
        self.backward_ntt = NTT(self.n, pow(root_ntt, -1, prime), prime)
        # Forward input indices g^t, output indices g^(-s).
        h = [pow(primitive_root, self.indices[-s % self.n], prime) for s in range(self.n)]
        # Inverse kernel includes the missing constant-coordinate correction.
        inv_r = pow(conductor, -1, prime)
        k = [(pow(primitive_root, -self.indices[s], prime) - 1) * inv_r % prime
             for s in range(self.n)]
        inverse_n = pow(self.n, -1, prime)
        setup = Arithmetic(prime)
        self.kernels = [[v * inverse_n % prime for v in self.forward_ntt.run(kernel, setup)]
                        for kernel in (h, k)]

    def run(self, values, arithmetic, inverse=False):
        assert len(values) == self.n
        if inverse:
            reordered = [values[self.indices[-s % self.n] - 1] for s in range(self.n)]
        else:
            reordered = [values[i - 1] for i in self.indices]
        spectrum = self.forward_ntt.run(reordered, arithmetic)
        spectrum = [arithmetic.mul(x, y) for x, y in zip(spectrum, self.kernels[inverse])]
        convolved = self.backward_ntt.run(spectrum, arithmetic)
        result = [0] * self.n
        for s, value in enumerate(convolved):
            index = self.indices[s] if inverse else self.indices[-s % self.n]
            result[index - 1] = value
        return result


class Dyadic:
    def __init__(self, length, prime, generator):
        self.n = length
        self.p = prime
        self.root = pow(generator, (prime - 1) // (2 * length), prime)
        self.f = NTT(length, self.root * self.root % prime, prime)
        self.i = NTT(length, pow(self.root, -2, prime), prime)
        self.twists = [pow(self.root, j, prime) for j in range(length)]
        self.inverse_twists = [pow(self.root, -j, prime) * pow(length, -1, prime) % prime
                               for j in range(length)]

    def run(self, values, arithmetic, inverse=False):
        if inverse:
            result = self.i.run(values, arithmetic)
            return [arithmetic.mul(x, w) for x, w in zip(result, self.inverse_twists)]
        twisted = [values[0]] + [arithmetic.mul(x, w) for x, w in zip(values[1:], self.twists[1:])]
        return self.f.run(twisted, arithmetic)


class OddPower:
    def __init__(self, conductor, prime, generator):
        self.n = conductor - 1
        self.r = conductor
        self.p = prime
        self.root = pow(generator, (prime - 1) // conductor, prime)
        if conductor == 3:
            self.inverse_difference = pow((self.root - self.root * self.root) % prime, -1, prime)
        else:
            assert conductor == 5
            c1 = (self.root + pow(self.root, -1, prime)) % prime
            c2 = (self.root ** 2 + pow(self.root, -2, prime)) % prime
            delta = (c1 - c2) % prime
            s1 = (self.root - pow(self.root, -1, prime)) % prime
            s2 = (self.root ** 2 - pow(self.root, -2, prime)) % prime
            assert delta ** 2 % prime == 5
            assert (s1 ** 2 + s2 ** 2) % prime == prime - 5
            self.quarter = pow(4, -1, prime)
            self.forward_z = delta * self.quarter % prime
            self.inverse_z = pow(4 * delta, -1, prime)
            self.forward_ab = (s1 * pow(2, -1, prime) % prime, s2 * pow(2, -1, prime) % prime)
            self.inverse_ab = (-s1 * pow(10, -1, prime) % prime, -s2 * pow(10, -1, prime) % prime)
            self.forward_ab = (self.forward_ab[0], sum(self.forward_ab) % prime,
                               (self.forward_ab[1] - self.forward_ab[0]) % prime)
            self.inverse_ab = (self.inverse_ab[0], sum(self.inverse_ab) % prime,
                               (self.inverse_ab[1] - self.inverse_ab[0]) % prime)

    def run(self, values, arithmetic, inverse=False):
        if self.r == 3:
            if inverse:
                x1 = arithmetic.mul(arithmetic.sub(values[0], values[1]), self.inverse_difference)
                x0 = arithmetic.sub(values[0], arithmetic.mul(self.root, x1))
                return [x0, x1]
            t = arithmetic.mul(self.root, values[1])
            return [arithmetic.add(values[0], t), arithmetic.sub(arithmetic.sub(values[0], values[1]), t)]
        a = arithmetic
        if inverse:
            s1, s2 = a.add(values[0], values[3]), a.add(values[1], values[2])
            d1, d2 = a.sub(values[0], values[3]), a.sub(values[1], values[2])
            ca, cab, cba = self.inverse_ab
            u, v, w = a.mul(ca, a.sub(d1, d2)), a.mul(cab, d2), a.mul(cba, d1)
            h1, h2 = a.add(u, v), a.add(u, w)
            z = a.mul(self.inverse_z, a.sub(s1, s2))
            t = a.sub(h1, a.add(z, z))
            x0 = a.sub(a.add(a.mul(self.quarter, a.add(s1, s2)), h1), z)
            return [x0, a.add(h1, h1), a.add(t, h2), a.sub(t, h2)]
        x0, x1, x2, x3 = values
        t, d = a.add(x2, x3), a.sub(x2, x3)
        h = a.sub(x0, a.mul(self.quarter, a.add(x1, t)))
        z = a.mul(self.forward_z, a.sub(x1, t))
        e1, e2 = a.add(h, z), a.sub(h, z)
        ca, cab, cba = self.forward_ab
        u, v, w = a.mul(ca, a.sub(x1, d)), a.mul(cab, d), a.mul(cba, x1)
        o1, o2 = a.add(u, v), a.add(u, w)
        return [a.add(e1, o1), a.add(e2, o2), a.sub(e2, o2), a.sub(e1, o1)]


def expected_axis_counts(axis, inverse=False):
    n = axis.n
    if isinstance(axis, NormalCyclotomic):
        logarithm = n.bit_length() - 1
        return Counts(n * logarithm - n + 2, 2 * n * logarithm)
    if isinstance(axis, Dyadic):
        logarithm = n.bit_length() - 1
        return Counts(n * logarithm // 2 + int(inverse), n * logarithm)
    if axis.r == 3:
        return Counts(2, 2) if inverse else Counts(1, 3)
    return Counts(5, 16) if inverse else Counts(5, 14)


def tensor_run(values, axes, arithmetic, inverse=False):
    result = list(values)
    sizes = [axis.n for axis in axes]
    assert len(result) == prod(sizes)
    order = reversed(range(len(axes))) if inverse else range(len(axes))
    for axis_index in order:
        axis = axes[axis_index]
        stride = prod(sizes[axis_index + 1:])
        block = stride * axis.n
        for start in range(0, len(result), block):
            for offset in range(stride):
                indices = [start + offset + j * stride for j in range(axis.n)]
                transformed = axis.run([result[j] for j in indices], arithmetic, inverse)
                for j, value in zip(indices, transformed):
                    result[j] = value
    return result


def axis_direct(values, axis):
    p = axis.p
    if isinstance(axis, NormalCyclotomic):
        exponents, points = range(1, axis.r), range(1, axis.r)
    elif isinstance(axis, Dyadic):
        exponents, points = range(axis.n), range(1, 2 * axis.n, 2)
    else:
        exponents, points = range(axis.n), range(1, axis.r)
    return [sum(x * pow(axis.root, exponent * point, p) for x, exponent in zip(values, exponents) if x) % p
            for point in points]


LEDGER = {
    "tower": {"A": (48, 8, 192, 128), "B": (64, 8, 256, 64), "E": (4096, 256, 262144, 65536)},
    "six": {"A": (32, 4, 128, 128), "B": (32, 8, 256, 256), "C": (64, 8, 512, 512),
            "D": (768, 64, 24576, 24576), "H": (64, 8, 512, 512)},
}


def main():
    certified = check_prepared_transform_ledger()
    rng = random.Random(20260907)
    axis_checks, tensor_checks = 0, 0
    costs = {}
    for p, generator in zip(certified["auxiliary_primes"], (38, 14, 7)):
        e = NormalCyclotomic(257, 3, pow(generator, (p - 1) // 257, p), p, generator)
        dyadic = {n: Dyadic(n, p, generator) for n in (16, 32, 64, 128)}
        three, five = OddPower(3, p, generator), OddPower(5, p, generator)
        axes_to_check = [e, *dyadic.values(), three, five]
        for axis in axes_to_check:
            # Every axis basis vector is checked against independent direct evaluation.
            for basis_index in range(axis.n):
                vector = [int(j == basis_index) for j in range(axis.n)]
                arithmetic = Arithmetic(p)
                forward = axis.run(vector, arithmetic)
                assert forward == axis_direct(vector, axis)
                assert arithmetic.count == expected_axis_counts(axis)
                arithmetic = Arithmetic(p)
                assert axis.run(forward, arithmetic, True) == vector
                assert arithmetic.count == expected_axis_counts(axis, True)
                axis_checks += 1
        rings = {"E": [e], "A": [dyadic[128], e], "B": [dyadic[64], e],
                 "C": [dyadic[32], three, e], "D": [three, five, e], "H": [dyadic[16], three, e]}
        this_cost = {}
        for name, axes in rings.items():
            dimension = prod(axis.n for axis in axes)
            f = sum((expected_axis_counts(axis) * (dimension // axis.n) for axis in axes), Counts())
            i = sum((expected_axis_counts(axis, True) * (dimension // axis.n) for axis in axes), Counts())
            vector = [rng.randrange(p) for _ in range(dimension)]
            arithmetic = Arithmetic(p)
            transformed = tensor_run(vector, axes, arithmetic)
            assert arithmetic.count == f
            arithmetic = Arithmetic(p)
            assert tensor_run(transformed, axes, arithmetic, True) == vector
            assert arithmetic.count == i
            this_cost[name] = {"dimension": dimension, "forward": f, "inverse": i}
            tensor_checks += 1
        if costs:
            assert costs == this_cost
        costs = this_cost
    routes = {}
    for route, rows in LEDGER.items():
        online, prepared, mac, output_positions, hint_positions = Counts(), Counts(), 0, 0, 0
        for name, (nf, ni, nm, np) in rows.items():
            ring = costs[name]
            online += ring["forward"] * nf + ring["inverse"] * ni
            prepared += ring["forward"] * np
            mac += nm * ring["dimension"]
            output_positions += ni * ring["dimension"]
            hint_positions += np * ring["dimension"]
        twiddles = 131072 if route == "tower" else 0
        online += Counts(twiddles)
        routes[route] = {"online_transform_and_twiddle": online.as_dict(),
                         "hint_preparation": prepared.as_dict(), "scalar_macs": mac,
                         "online_multiplications_including_macs": online.mul + mac,
                         # Separate weighted groups add 2N seeds and 2N merges;
                         # those cancel when first products seed accumulators.
                         "online_additions_including_macs": online.add + mac - output_positions,
                         "inverse_coefficient_positions": output_positions,
                         "prepared_hint_coefficients": hint_positions,
                         "three_channel_hint_bytes_at_64_bits": hint_positions * 3 * 8,
                         "scope": "per auxiliary channel; coefficient maps, CRT, decomposition and memory separately charged"}
    print(json.dumps({"status": "PASS", "scope": "exact public transforms and scalar-operation ledger, not encrypted execution or runtime",
                      "axis_basis_forward_and_inverse_checks": axis_checks, "full_tensor_roundtrips": tensor_checks,
                      "rings": {name: {"dimension": item["dimension"], "forward": item["forward"].as_dict(),
                                         "inverse": item["inverse"].as_dict()} for name, item in costs.items()},
                      "routes": routes, "security_qualified": False, "he_backend_tested": False}, indent=2))


if __name__ == "__main__":
    main()
