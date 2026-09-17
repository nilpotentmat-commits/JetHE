"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

import random

def pack_digits(values, width):
    # Byte-aligned chunks avoid successive shifts of a growing integer.
    size = (width + 7) // 8
    return int.from_bytes(b''.join(x.to_bytes(size, 'little') for x in values), 'little'), size


def ring_packed(a, b, q):
    L = len(a)
    width = 2 * (q - 1).bit_length() + (256 * L - 1).bit_length() + 1
    av = [0] * (513 * L)
    bv = av.copy()
    for i in range(L):
        for v in range(1, 257):
            av[513 * i + v] = a[i][v - 1] % q
            bv[513 * i + v] = b[i][v - 1] % q
    pa, size = pack_digits(av, width)
    pb, size_b = pack_digits(bv, width)
    assert size == size_b
    raw = (pa * pb).to_bytes(1026 * L * size, 'little')
    folded = [[0] * 257 for _ in range(L)]
    for i in range(2 * L - 1):
        sign = 1 if i < L else -1
        for v in range(513):
            start = (513 * i + v) * size
            c = int.from_bytes(raw[start:start + size], 'little')
            assert c <= 256 * L * (q - 1) ** 2
            folded[i % L][v % 257] += sign * c
    return [[(row[v] - row[0]) % q for v in range(1, 257)] for row in folded]


def ring_power_basis_oracle(a, b, q):
    # Independent basis conversion and direct polynomial long reduction by Phi_257.
    L = len(a)
    def power_rows(x):
        return [[-r[255]] + [r[j - 1] - r[255] for j in range(1, 256)] for r in x]
    aa = [(i, j, c) for i, r in enumerate(power_rows(a)) for j, c in enumerate(r) if c]
    bb = [(i, j, c) for i, r in enumerate(power_rows(b)) for j, c in enumerate(r) if c]
    out = [[0] * 511 for _ in range(L)]
    for i, v, x in aa:
        for j, w, y in bb:
            out[(i + j) % L][v + w] += x * y * (1 if i + j < L else -1)
    for row in out:
        for j in range(510, 255, -1):
            c = row[j]
            if c:
                for v in range(257):
                    row[j - 256 + v] -= c
    return [[(r[j] - r[0]) % q for j in range(1, 256)] + [(-r[0]) % q] for r in out]


FIELD = 0x1100B


def binary_remainder(a, p):
    while a.bit_length() >= p.bit_length():
        a ^= p << (a.bit_length() - p.bit_length())
    return a


def binary_gcd(a, b):
    while b:
        a, b = b, binary_remainder(a, b)
    return a


def gf_mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a & 0x10000:
            a ^= FIELD
    return out


def jet_packed(a, b):
    L = len(a)
    av = [0] * (32 * L)
    bv = av.copy()
    for i in range(L):
        for v in range(16):
            av[32 * i + v] = (a[i] >> v) & 1
            bv[32 * i + v] = (b[i] >> v) & 1
    pa, size = pack_digits(av, (16 * L).bit_length())
    pb, _ = pack_digits(bv, (16 * L).bit_length())
    raw = (pa * pb).to_bytes(64 * L * size, 'little')
    out = []
    for i in range(L):
        c = 0
        for v in range(31):
            start = (32 * i + v) * size
            digit = int.from_bytes(raw[start:start + size], 'little')
            assert digit <= 16 * L
            c |= (digit & 1) << v
        out.append(binary_remainder(c, FIELD))
    return out


def jet_oracle(a, b):
    out = [0] * len(a)
    for i, x in enumerate(a):
        for j in range(len(a) - i):
            out[i + j] ^= gf_mul(x, b[j])
    return out


def zmul(a, b):
    c = 0
    while b:
        if b & 1:
            c ^= a
        a <<= 1
        b >>= 1
    return c


def yroot_product(roots):
    poly = [1]
    for root in roots:
        new = [0] * (len(poly) + 1)
        for j, c in enumerate(poly):
            new[j] ^= zmul(c, root)
            new[j + 1] ^= c
        poly = new
    return poly


def check():
    rng = random.Random(20260914)
    rings = []
    for L in (1, 2, 4, 8):
        for q in (3, 15, 17, 257, 65537):
            a = [[rng.randrange(q) for _ in range(256)] for _ in range(L)]
            b = [[rng.randrange(q) for _ in range(256)] for _ in range(L)]
            got = ring_packed(a, b, q)
            assert got == ring_power_basis_oracle(a, b, q), (L, q)
            rings.append({'L': L, 'q': q, 'kind': 'dense', 'coefficients': 256 * L})
    # All residues maximal stresses carry width; degree endpoints stress both folds.
    for L in (1, 8, 256):
        q = (1 << 61) - 1
        a = [[0] * 256 for _ in range(L)]
        b = [[0] * 256 for _ in range(L)]
        for i, v in ((0, 0), (0, 255), (L - 1, 0), (L - 1, 255)):
            a[i][v] = q - 1
            b[i][v] = q - 2
        assert ring_packed(a, b, q) == ring_power_basis_oracle(a, b, q)
        rings.append({'L': L, 'q': q, 'kind': 'boundary', 'coefficients': 256 * L})
    L, q = 4, 65537
    a = [[q - 1] * 256 for _ in range(L)]
    assert ring_packed(a, a, q) == ring_power_basis_oracle(a, a, q)
    rings.append({'L': L, 'q': q, 'kind': 'maximal', 'coefficients': 256 * L})
    # Rabin irreducibility test: 16 has only the prime divisor 2.
    x = 2
    for i in range(1, 17):
        x = gf_mul(x, x)
        if i == 8:
            assert binary_gcd(x ^ 2, FIELD) == 1
    assert x == 2
    jets = []
    for L in (1, 2, 4, 8, 16, 32, 64, 256):
        for rep in range(5):
            a = [rng.randrange(65536) for _ in range(L)]
            b = [rng.randrange(65536) for _ in range(L)]
            if rep == 0:
                a = b = [65535] * L
            assert jet_packed(a, b) == jet_oracle(a, b), (L, rep)
            jets.append({'L': L, 'replicate': rep})
    identities = []
    for r in range(6):
        degree = 1 << r
        psi = yroot_product(range(degree))
        e = yroot_product(a << 1 for a in range(degree))
        assert e == [c << (degree - j) for j, c in enumerate(psi)]
        identities.append({'r': r, 'degree': degree})
    return {'status': 'EXACT_ARITHMETIC_AND_CARLITZ_IDENTITIES_PASS',
            'ring_cases': rings, 'jet_cases': jets, 'carlitz_cases': identities,
            'field_polynomial': hex(FIELD), 'field_irreducibility_checked': True,
            'new_he_execution': False, 'timing_benchmark': False,
            'proof_scope': 'Finite exact arithmetic checks; asymptotic proof is in FAST_WORK_PROOF.md'}
