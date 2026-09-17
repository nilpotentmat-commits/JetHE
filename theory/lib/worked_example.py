"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

from __future__ import annotations
from math import comb
from random import Random
import json

L = 8


MASK = (1 << L) - 1


def binary_product(a: int, b: int) -> int:
    """Direct carry-free product, reduced modulo z^8."""
    result = 0
    for i in range(L):
        if (b >> i) & 1:
            result ^= a << i
    return result & MASK


def binary_hasse(a: int, order: int) -> int:
    """Use the binomial definition, independently of the index-bit rule."""
    return sum(
        (((a >> i) & 1) * (comb(i, order) % 2)) << (i - order)
        for i in range(order, L)
    )


def binary_horner(f: int, g: int) -> int:
    result = 0
    for i in reversed(range(L)):
        result = binary_product(result, g) ^ ((f >> i) & 1)
    return result


def binary_direct_state(f: int, g_powers: list[int], j: int) -> int:
    """Evaluate the residue-class definition of C_j directly."""
    r = 1 << j
    result = 0
    for i in range(L):
        if (f >> i) & 1:
            result ^= g_powers[(i // r) * r] << (i % r)
    return result & MASK


def field_product(a: int, b: int) -> int:
    """Exact multiplication in F_2[Y]/(Y^16+Y^12+Y^3+Y+1)."""
    result = 0
    for _ in range(16):
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & (1 << 16):
            a ^= 0x1100B
    return result


def poly_add(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b, strict=True)]


def poly_product(a: list[int], b: list[int]) -> list[int]:
    result = [0] * L
    for i in range(L):
        for j in range(L - i):
            result[i + j] ^= field_product(a[i], b[j])
    return result


def poly_hasse(a: list[int], order: int) -> list[int]:
    result = [0] * L
    for i in range(order, L):
        if comb(i, order) % 2:
            result[i - order] = a[i]
    return result


def poly_horner(f: list[int], g: list[int]) -> list[int]:
    result = [0] * L
    for coefficient in reversed(f):
        result = poly_product(result, g)
        result[0] ^= coefficient
    return result


def main() -> None:
    # Rabin irreducibility criterion: degree 16 has only prime divisor 2.
    def remainder(a: int, b: int) -> int:
        while a.bit_length() >= b.bit_length():
            a ^= b << (a.bit_length() - b.bit_length())
        return a

    def gcd(a: int, b: int) -> int:
        while b:
            a, b = b, remainder(a, b)
        return a

    x_power = 2
    for degree in range(1, 17):
        x_power = field_product(x_power, x_power)
        if degree == 8:
            assert gcd(x_power ^ 2, 0x1100B) == 1
    assert x_power == 2
    binary_cases = 0
    for a in range(256):
        selected = sum(((a >> i) & 1) << (i - 2) for i in (2, 3, 6, 7))
        assert binary_hasse(a, 2) == selected

    for g in range(0, 256, 2):
        powers = [1]
        for _ in range(7):
            powers.append(binary_product(powers[-1], g))
        for f in range(256):
            state = f
            assert state == binary_direct_state(f, powers, 3)
            for j in (2, 1, 0):
                r = 1 << j
                derivative = binary_hasse(state, r)
                if r == 2:
                    even_part = state & 0b00110011
                    replacement = even_part ^ binary_product(powers[2], derivative)
                state ^= binary_product(powers[r] ^ (1 << r), derivative)
                assert state == binary_direct_state(f, powers, j)
                if r == 2:
                    assert state == replacement
            assert state == binary_horner(f, g)
            binary_cases += 1

    # Intermediate coefficients generally differ from f's coefficients.
    f, g = 1 << 4, 1 << 2  # f=z^4, g=z^2
    g4 = binary_product(binary_product(g, g), binary_product(g, g))
    c2 = f ^ binary_product(g4 ^ (1 << 4), binary_hasse(f, 4))
    assert c2 == 0 and c2 != f

    rng = Random(20260916)
    extension_cases = 128
    for _ in range(extension_cases):
        f = [rng.randrange(1 << 16) for _ in range(L)]
        g = [0] + [rng.randrange(1 << 16) for _ in range(L - 1)]
        powers = [[1] + [0] * 7]
        for _ in range(7):
            powers.append(poly_product(powers[-1], g))
        state = f[:]
        for j in (2, 1, 0):
            r = 1 << j
            derivative = poly_hasse(state, r)
            if r == 2:
                assert derivative == [state[2], state[3], 0, 0, state[6], state[7], 0, 0]
                even_part = [state[i] if i in (0, 1, 4, 5) else 0 for i in range(L)]
                replacement = poly_add(even_part, poly_product(powers[2], derivative))
            multiplier = powers[r][:]
            multiplier[r] ^= 1
            state = poly_add(state, poly_product(multiplier, derivative))
            direct = [0] * L
            for i in range(L):
                for degree in range(L - i % r):
                    direct[degree + i % r] ^= field_product(f[i], powers[(i // r) * r][degree])
            assert state == direct
            if r == 2:
                assert state == replacement
        assert state == poly_horner(f, g)

    print(json.dumps({
        "status": "PASS",
        "length": L,
        "binary_hasse_inputs_exhausted": 256,
        "binary_composition_pairs_exhausted": binary_cases,
        "extension_field_composition_cases": extension_cases,
        "extension_field_polynomial": "0x1100b",
        "extension_field_polynomial_irreducible": True,
        "random_seed": 20260916,
        "states_checked_per_pair": ["C2", "C1", "C0"],
        "independent_comparisons": ["binomial Hasse definition", "residue-class state formula", "Horner composition"],
        "intermediate_coefficient_counterexample": "f=z^4, g=z^2 gives C2=0 modulo z^8",
        "scope": "finite plaintext arithmetic; no HE run, security claim or general proof",
    }, indent=2))
