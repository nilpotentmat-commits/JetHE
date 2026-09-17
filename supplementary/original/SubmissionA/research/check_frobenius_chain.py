"""Public algebra and conditional inventory/noise checks, not HE execution."""

from collections import defaultdict
import json
from random import Random

from check_frobenius_compiler import Jets
from check_tensor_codec import decode, setup


def add_term(out, index, value):
    out[index] += value


def clean(value):
    return {index: coefficient for index, coefficient in value.items() if coefficient}


def multiply(left, right, length, prime):
    result = defaultdict(int)
    for (i, b), x in left.items():
        for (j, c), y in right.items():
            exponent = i + j
            signed = x * y * (-1 if exponent >= length else 1)
            field_index = (b + c) % prime
            if field_index:
                add_term(result, (exponent % length, field_index), signed)
            else:
                for k in range(1, prime):
                    add_term(result, (exponent % length, k), -signed)
    return clean(result)


def sigma(value, prime, order=1):
    multiplier = pow(2, order, prime)
    return {(i, b * multiplier % prime): c for (i, b), c in value.items()}


def psi(value, length, prime):
    result = defaultdict(int)
    for (i, b), coefficient in value.items():
        add_term(result, (2 * i % length, 2 * b % prime),
                 coefficient * (-1 if 2 * i >= length else 1))
    return clean(result)


def embed(value, source_length, target_length):
    assert target_length % source_length == 0
    stride = target_length // source_length
    return {(i * stride, b): c for (i, b), c in value.items()}


def shift(value, exponent, length):
    return {((i + exponent) % length, b): c * (-1 if i + exponent >= length else 1)
            for (i, b), c in value.items()}


def step(value, length, floor, prime):
    if length == floor:
        return psi(value, floor, prime)
    output_length = length // 2
    rank = length // floor
    out = defaultdict(int)
    for r in range(rank):
        block = {(i // rank, b): c for (i, b), c in value.items() if i % rank == r}
        mapped = shift(embed(psi(block, floor, prime), floor, output_length), r, output_length)
        for index, coefficient in mapped.items():
            out[index] += coefficient
    return clean(out)


def direct_compressed(value, length, prime):
    result = defaultdict(int)
    for (i, b), coefficient in value.items():
        add_term(result, (i % (length // 2), 2 * b % prime),
                 coefficient * (-1 if i >= length // 2 else 1))
    return clean(result)


def binary(value, length):
    out = [0] * length
    for (i, b), coefficient in value.items():
        if coefficient % 2:
            out[i] ^= 1 << (b - 1)
    return out


def main():
    rng = Random(20260908)
    basis_cases = module_cases = 0
    for length in (128, 64, 32):
        counts = defaultdict(int)
        for i in range(length):
            for b in range(1, 257):
                source = {(i, b): 1}
                actual = step(source, length, 32, 257)
                expected = (direct_compressed(source, length, 257) if length > 32
                            else psi(source, length, 257))
                assert actual == expected
                if length == 32:
                    assert actual and all(j % 2 == 0 for j, _ in actual)
                for index, coefficient in actual.items():
                    counts[index] += abs(coefficient)
                basis_cases += 1
        assert max(counts.values()) == 2
        assert len(counts) == length * 256 // 2

    # Arbitrary signed polynomials, not cryptographic secrets: verify the
    # E-semilinear hint payload identity and block reuse over the integers.
    prime, floor = 5, 4
    for _ in range(12):
        symbol = {(i, b): rng.randrange(-3, 4) for i in range(floor) for b in range(1, prime)}
        payloads = [psi(shift(symbol, i, floor), floor, prime) for i in range(floor)]
        assert all(i % 2 == 0 for payload in payloads for i, _ in payload)
        for length in (16, 8, 4):
            rank = length // floor
            mask = {(i, b): rng.randrange(-3, 4) for i in range(length) for b in range(1, prime)}
            actual = step(multiply(mask, embed(symbol, floor, length), length, prime), length, floor, prime)
            expected = defaultdict(int)
            output_length = max(length // 2, floor)
            for r in range(rank):
                image = defaultdict(int)
                for i in range(floor):
                    coefficient = {(0, b): mask[(r + rank * i, b)] for b in range(1, prime)}
                    contribution = multiply(sigma(coefficient, prime), payloads[i], floor, prime)
                    for index, value in contribution.items():
                        image[index] += value
                mapped = shift(embed(clean(image), floor, output_length), r, output_length)
                for index, value in mapped.items():
                    expected[index] += value
            assert actual == clean(expected)
            module_cases += 1
    # Full-carrier hint errors overlap even though deterministic map images
    # interleave: the repeated error 1+t overlaps its shifted copy at t.
    overlap = defaultdict(int, {(0, 1): 1, (1, 1): 1})
    for index, value in shift({(0, 1): 1, (1, 1): 1}, 1, 4).items():
        overlap[index] += value
    assert overlap[(1, 1)] == 2

    # Independently decode a full 65536-bit random root input into 16 jets.
    # Subsequent references use ordinary truncated-polynomial multiplication.
    field, _, _, _, rows, _ = setup()
    root = {(i, b): rng.randrange(2) for i in range(256) for b in range(1, 257)}
    root_decoded = decode(binary(root, 256), rows)
    references = [tuple((v >> (16 * lane)) & 65535 for v in root_decoded) for lane in range(16)]
    jets = Jets(field, 256)
    current = direct_compressed(root, 256, 257)
    current_length = 128
    decoded_cases = 0
    for order in range(1, 24):
        if 2 <= order <= 8:
            current = step(current, current_length, 32, 257)
            current_length = max(current_length // 2, 32)
        if order == 8:
            constant_state = dict(current)
            assert all(not row for row in binary(current, 32)[1:])
        if order > 8:
            current = sigma(constant_state, 257, order - 8)
        decoded = decode(binary(embed(current, current_length, 256), 256), rows)
        for lane in range(16):
            references[lane] = jets.mul(references[lane], references[lane])
            assert tuple((v >> (16 * lane)) & 65535 for v in decoded) == references[lane]
            decoded_cases += 1
    # Later-bank images have only even dyadic coefficients; an odd coefficient
    # annihilates every actual payload. This does not prove an attack.
    # The nonzero length32 basis images above certify the entire image
    # subspace, rather than testing a vector annihilated by cancellation.

    N, g, bound = 65536, 16, 1 << 48
    lam = 511 * g * 128 * 20
    internal, outputs = [], []
    for order in range(1, 9):
        increment = 832 if order == 1 else 64 if order in (2, 3) else 32
        bound = 2 * bound + 1 + increment * lam
        internal.append(bound)
        returned = bound + (128 if order == 1 else 64 if order == 2 else 32) * lam
        outputs.append(returned)
        if order >= 3:
            assert returned == (1 << order) * ((1 << 48) + 1 + 444 * lam) - 1
        assert (1 << 127) - 3 - 4 * returned > 0
    outputs.extend([outputs[-1]] * 15)
    repeated_bound = 1 << 48
    repeated_outputs = []
    for order in range(1, 9):
        repeated_bound = 2 * repeated_bound + 1 + 960 * lam
        assert repeated_bound == (1 << order) * (1 << 48) + ((1 << order) - 1) * (1 + 960 * lam)
        repeated_outputs.append(repeated_bound + (256 * lam if order < 8 else 0))
    retained_eighth = repeated_bound - 128 * lam
    repeated_outputs.extend([retained_eighth + 128 * lam] * 15)
    assert max(repeated_outputs) == 256 * (1 << 48) + 255 + 244800 * lam
    assert all((1 << 127) - 3 - 4 * b > 0 for b in repeated_outputs)
    ledger = []
    for maximum, requested in ((3, 3), (8, 8), (8, 23)):
        new = (8 * maximum + 11 + 2 * requested) * g * N
        repeated = (21 * maximum + 2 * (maximum - 1) + 2 * (requested - maximum)) * g * N
        ledger.append({"orders": requested, "new_hint_coefficients": new,
                       "full_return_control_hint_coefficients": repeated})
    assert ledger[-1]["new_hint_coefficients"] == 121 * g * N
    assert ledger[-1]["full_return_control_hint_coefficients"] == 212 * g * N
    assert 4 + 64 + 7 * 32 + 23 == 315
    print(json.dumps({
        "scope": "public integer/plaintext algebra and conditional counts, no HE or security certificate",
        "integral_basis_columns": basis_cases, "semilinear_module_cases": module_cases,
        "full_profile_lane_order_checks": decoded_cases,
        "minimum_carrier_and_independent_key_dimension": 8192,
        "later_payload_odd_projection_zero": True,
        "internal_noise_bounds": internal, "largest_returned_noise_bound": outputs[-1],
        "largest_full_return_control_noise_bound": max(repeated_outputs),
        "inventory": ledger, "full_orbit_hint_rows": 315 * g,
        "full_orbit_independent_public_keys": 12,
        "comparison_is_not_an_optimality_or_runtime_result": True,
    }, indent=2))


if __name__ == "__main__":
    main()
