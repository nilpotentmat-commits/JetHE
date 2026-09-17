"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

import json
from math import comb
from random import Random
from field_jets import Field, Jets

E = 256


MASK = (1 << E) - 1


def power(field, value, exponent):
    result = 1
    while exponent:
        if exponent & 1:
            result = field.mul(result, value)
        value = field.mul(value, value)
        exponent >>= 1
    return result


def apply_matrix(rows, value):
    return sum(((row & value).bit_count() & 1) << i for i, row in enumerate(rows))


def inverse_matrix(rows):
    augmented = [row | (1 << (E + i)) for i, row in enumerate(rows)]
    for i in range(E):
        pivot = next(j for j in range(i, E) if (augmented[j] >> i) & 1)
        augmented[i], augmented[pivot] = augmented[pivot], augmented[i]
        for j in range(E):
            if j != i and (augmented[j] >> i) & 1:
                augmented[j] ^= augmented[i]
    assert all(row & MASK == 1 << i for i, row in enumerate(augmented))
    return [row >> E for row in augmented]


def setup():
    field = Field(16, 0x1100B)
    beta = next(root for candidate in range(2, 65536)
                if (root := power(field, candidate, 255)) != 1)
    assert power(field, beta, 257) == 1
    seen, representatives = set(), []
    for candidate in range(1, 257):
        if candidate not in seen:
            representatives.append(candidate)
            orbit, value = [], candidate
            while value not in orbit:
                orbit.append(value)
                value = 2 * value % 257
            assert len(orbit) == 16 and value == candidate
            assert seen.isdisjoint(orbit)
            seen.update(orbit)
    assert len(representatives) == 16 and len(seen) == 256
    roots = [power(field, beta, r) for r in representatives]
    columns = [0] * E
    for lane, root in enumerate(roots):
        value = root
        for j in range(E):
            columns[j] |= value << (16 * lane)
            value = field.mul(value, root)
    rows = [sum(((col >> i) & 1) << j for j, col in enumerate(columns))
            for i in range(E)]
    inverse = inverse_matrix(rows)
    for j, col in enumerate(columns):
        assert apply_matrix(rows, 1 << j) == col
        assert apply_matrix(inverse, col) == 1 << j
        assert apply_matrix(rows, apply_matrix(inverse, 1 << j)) == 1 << j
    return field, beta, representatives, roots, rows, inverse


def butterfly(values):
    result = list(values)
    length = len(values)
    assert length > 0 and length & (length - 1) == 0
    count, stride = 0, 1
    while stride < length:
        for base in range(0, length, 2 * stride):
            for i in range(base, base + stride):
                result[i] ^= result[i + stride]
                count += 1
        stride *= 2
    assert count == length * (length.bit_length() - 1) // 2
    return result, count


def decode(values, rows):
    shifted, _ = butterfly(values)
    return [apply_matrix(rows, value) for value in shifted]


def encode(values, inverse):
    return butterfly([apply_matrix(inverse, value) for value in values])[0]


def e_mul(x, y):
    # Independent cyclic multiplication in b, using b^257=1 and
    # 1=b+...+b^256 over F2. Input bit j-1 represents b^j.
    left, right, raw = x << 1, y << 1, 0
    while right:
        lowest = right & -right
        raw ^= left << (lowest.bit_length() - 1)
        right ^= lowest
    full_mask = (1 << 257) - 1
    reduced = (raw & full_mask) ^ (raw >> 257)
    if reduced & 1:
        reduced ^= full_mask
    return reduced >> 1


def tensor_mul(x, y):
    out, length = [0] * len(x), len(x)
    for i, a in enumerate(x):
        for j, b in enumerate(y):
            out[(i + j) % length] ^= e_mul(a, b)
    return out


def univariate_to_tensor(value, length):
    out = []
    full_mask = (1 << 257) - 1
    for r in range(length):
        block = 0
        for n in range(E):
            if (value >> (r + length * n)) & 1:
                block |= 1 << ((r + length * n) % 257)
        if block & 1:
            block ^= full_mask
        out.append(block >> 1)
    return out


def tensor_to_univariate(values):
    value, length = 0, len(values)
    full_mask = (1 << 257) - 1
    for r, row in enumerate(values):
        missing = (r - length) % 257
        block = row << 1
        if missing and (block >> missing) & 1:
            block ^= full_mask
        assert not (block >> missing) & 1
        for n in range(E):
            if (block >> ((r + length * n) % 257)) & 1:
                value |= 1 << (r + length * n)
    return value


def main():
    rng = Random(20260907)
    field, beta, reps, roots, rows, inverse = setup()
    axis_cases = tensor_cases = products = hasse_cases = 0
    for length in (1, 2, 4, 8, 16, 256):
        for r in range(length):
            basis = [0] * length
            basis[r] = 1
            actual, _ = butterfly(basis)
            expected = [comb(r, j) % 2 if j <= r else 0 for j in range(length)]
            assert actual == expected and butterfly(actual)[0] == basis
            axis_cases += 1
        for _ in range(3):
            values = [rng.getrandbits(E) for _ in range(length)]
            assert encode(decode(values, rows), inverse) == values
            univariate = rng.getrandbits(E * length)
            assert tensor_to_univariate(univariate_to_tensor(univariate, length)) == univariate
            assert univariate_to_tensor(tensor_to_univariate(values), length) == values
            tensor_cases += 1
        # Direct sparse univariate Hasse oracle, independently evaluated from
        # the explicit X^k coefficients and field powers at all 16 roots.
        exponents = sorted(rng.sample(range(E * length), 8))
        univariate = sum(1 << k for k in exponents)
        actual = decode(univariate_to_tensor(univariate, length), rows)
        for lane, root in enumerate(roots):
            powers = [1]
            for _ in range(256):
                powers.append(field.mul(powers[-1], root))
            for j in range(length):
                expected = unscaled = 0
                for k in exponents:
                    if k & j == j:
                        expected ^= powers[k % 257]
                        unscaled ^= powers[(k - j) % 257]
                assert (actual[j] >> (16 * lane)) & 65535 == expected
                assert field.mul(expected, powers[-j % 257]) == unscaled
                hasse_cases += 1
        if length <= 8:
            jets = Jets(field, length)
            for _ in range(3):
                x, y = [[rng.getrandbits(E) for _ in range(length)] for _ in range(2)]
                dx, dy, dp = decode(x, rows), decode(y, rows), decode(tensor_mul(x, y), rows)
                for lane in range(16):
                    extract = lambda z: tuple((v >> (16 * lane)) & 65535 for v in z)
                    assert jets.mul(extract(dx), extract(dy)) == extract(dp)
                products += 1
    # L512 includes r255 with missing exponent zero: exercise the
    # conversion's pure-permutation branch as well as its broadcast branch.
    assert (255 - 512) % 257 == 0
    extra = [rng.getrandbits(E) for _ in range(512)]
    assert univariate_to_tensor(tensor_to_univariate(extra), 512) == extra
    extra_univariate = rng.getrandbits(E * 512)
    assert tensor_to_univariate(univariate_to_tensor(extra_univariate, 512)) == extra_univariate
    forward_xors = sum(row.bit_count() - 1 for row in rows)
    inverse_xors = sum(row.bit_count() - 1 for row in inverse)
    assert 0 <= forward_xors <= E * (E - 1) and 0 <= inverse_xors <= E * (E - 1)
    print(json.dumps({
        "scope": "public plaintext codec and logical XOR counts; no encrypted execution",
        "field_modulus": hex(field.modulus), "order257_root": beta,
        "doubling_orbit_representatives": reps, "CRT_basis_cases": 256,
        "Taylor_axis_basis_cases": axis_cases, "tensor_and_univariate_roundtrips": tensor_cases,
        "full_lane_multiplicativity_cases": products,
        "direct_sparse_Hasse_coefficient_cases": hasse_cases,
        "Hasse_inverse_scaling_checked": True,
        "L512_both_basis_conversion_branches_checked": True,
        "CRT_matrix_XORs": forward_xors, "inverse_CRT_matrix_XORs": inverse_xors,
        "two_dense_matrices_bytes": 2 * E * E // 8,
        "L256": {"butterfly_E_additions": 1024, "butterfly_bit_XORs": 262144,
                 "decode_logical_XORs": 256 * forward_xors + 262144,
                 "encode_logical_XORs": 256 * inverse_xors + 262144},
        "runtime_or_security_result": False,
    }, indent=2))
