"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

from functools import lru_cache

def poly_rem(a, b):
    while a and a.bit_length() >= b.bit_length():
        a ^= b << (a.bit_length() - b.bit_length())
    return a


def poly_gcd(a, b):
    while b:
        a, b = b, poly_rem(a, b)
    return a


class Field:
    def __init__(self, degree, modulus):
        self.d, self.modulus = degree, modulus
        assert modulus.bit_length() == degree + 1
        x = poly_rem(2, modulus)
        powers = [x]
        for _ in range(degree):
            powers.append(self.mul(powers[-1], powers[-1]))
        assert powers[-1] == x
        primes = [r for r in range(2, degree + 1)
                  if degree % r == 0 and all(r % j for j in range(2, r))]
        assert all(poly_gcd(powers[degree // r] ^ x, modulus) == 1
                   for r in primes), "Rabin irreducibility certificate failed"

    def mul(self, a, b):
        result = 0
        while b:
            if b & 1:
                result ^= a
            b >>= 1
            a <<= 1
            if a >> self.d:
                a ^= self.modulus
        return result


class Jets:
    def __init__(self, field, length):
        self.field, self.length = field, length
        self.a = (length - 1).bit_length()
        self.states = self.a + field.d

    def canonical(self, state):
        return state if state < self.a else self.a + (state - self.a) % self.field.d

    def add(self, x, y):
        return tuple(a ^ b for a, b in zip(x, y))

    def mul(self, x, y):
        out = [0] * self.length
        for i, a in enumerate(x):
            if a:
                for j, b in enumerate(y[:self.length - i]):
                    if b:
                        out[i + j] ^= self.field.mul(a, b)
        return tuple(out)

    def frobenius_formula(self, x, state):
        out = [0] * self.length
        for j in range((self.length - 1) // (1 << state) + 1):
            c = x[j]
            for _ in range(state % self.field.d):
                c = self.field.mul(c, c)
            out[j << state] = c
        return tuple(out)

    def ordinary_power(self, x, state):
        for _ in range(state):
            x = self.mul(x, x)
        return x

    def random(self, rng):
        return tuple(rng.randrange(1 << self.field.d) for _ in range(self.length))
