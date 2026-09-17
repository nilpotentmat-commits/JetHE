"""Exact binary extension-field routines extracted from the measured source."""

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

def power(x, exponent, field):
    out = 1
    while exponent:
        if exponent & 1:
            out = field.mul(out, x)
        exponent >>= 1
        x = field.mul(x, x)
    return out

class FastField:
    def __init__(self):
        self.d, self.order = 16, 65535
        base = Field(16, 0x1100B)
        generator = next(a for a in range(2, 50)
                         if all(power(a, self.order // p, base) != 1 for p in (3, 5, 17, 257)))
        self.logs, exponents = [0] * 65536, []
        x = 1
        for i in range(self.order):
            self.logs[x] = i
            exponents.append(x)
            x = base.mul(x, generator)
        assert x == 1 and len(set(exponents)) == self.order
        self.exponents = exponents + exponents
        self.frob8 = [0] + [exponents[(256 * self.logs[x]) % self.order] for x in range(1, 65536)]
        for a in (0, 1, 2, 19, 1023, 65535):
            for b in (0, 1, 3, 57, 65534):
                assert self.mul(a, b) == base.mul(a, b)

    def mul(self, a, b):
        return self.exponents[self.logs[a] + self.logs[b]] if a and b else 0

