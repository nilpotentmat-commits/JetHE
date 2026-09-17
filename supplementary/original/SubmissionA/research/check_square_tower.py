"""Deterministic algebra checks, not an HE benchmark or security test.

The reference multiplies in the binary cyclotomic tensor quotient. The tower
uses coefficient splits, a separate normal-basis Frobenius permutation, and
compressed interleaving. No external packages, keys, or files are used.
"""

import json
import random
from fractions import Fraction
from itertools import product
from math import comb, gcd, isqrt


def floor_fraction(value):
    return value.numerator // value.denominator


def parity_round(value, alpha):
    """Nearest integer to alpha*value of the same parity; ties go upward."""
    parity = value % 2
    return parity + 2 * floor_fraction((alpha * value - parity + 1) / 2)


def switched_noise_bound(bound, q, target_q, secret_row_norm):
    alpha = Fraction(target_q, q)
    return floor_fraction(alpha * bound + (1 - alpha) / 2 + Fraction(1 + secret_row_norm, 2))


def check_scalar_modulus_switch():
    """Exhaustive toy phase tests, not an RLWE or encrypted execution test."""
    cases = 0
    for q in [17, 31, 43]:
        for target_q in [5, 9, 13]:
            alpha = Fraction(target_q, q)
            for secret in range(-2, 3):
                for c0 in range(-(q // 2), q // 2 + 1):
                    for c1 in range(-(q // 2), q // 2 + 1):
                        phase = (c0 + c1 * secret + q // 2) % q - q // 2
                        mu = phase % 2
                        noise = (phase - mu) // 2
                        quotient = (c0 + c1 * secret - phase) // q
                        d0, d1 = parity_round(c0, alpha), parity_round(c1, alpha)
                        assert abs(d0 - alpha * c0) <= 1 and (d0 - c0) % 2 == 0
                        assert abs(d1 - alpha * c1) <= 1 and (d1 - c1) % 2 == 0
                        lifted = d0 + d1 * secret - target_q * quotient
                        assert (lifted - mu) % 2 == 0
                        bound = switched_noise_bound(abs(noise), q, target_q, abs(secret))
                        assert abs((lifted - mu) // 2) <= bound
                        if 2 * (1 + 2 * bound) < target_q:
                            centered = (d0 + d1 * secret + target_q // 2) % target_q - target_q // 2
                            assert centered == lifted and centered % 2 == mu
                        cases += 1
    return cases


def check_tunnel_inventory():
    # Exact dimensions/ranks for integral power-basis transport. No CRT is used.
    conductors = [512, 256 * 3, 64 * 15, 255, 32 * 15, 128 * 3, 512]

    def phi(n):
        return sum(gcd(a, n) == 1 for a in range(1, n + 1))

    ranks = [phi(a) // phi(gcd(a, b)) for a, b in zip(conductors, conductors[1:])]
    dimensions = [256 * phi(c) for c in conductors[1:]]
    assert ranks == [2, 4, 32, 16, 4, 2]
    assert dimensions == [65536, 65536, 32768, 32768, 32768, 65536]
    assert next(k for k in range(1, 257) if pow(2, k, 257) == 1) == 16
    assert all(((1 << 16) - 1) % p == 0 for p in [3, 5, 17])
    for r in range(256):
        i, j, ell, h = r % 2, (r // 2) % 4, (r // 8) % 16, r // 128
        assert (2 * r) % 256 == 2 * (i + 2 * j + 8 * ell)
        assert h in [0, 1]
    hint_coefficients = 2 * sum(r * n for r, n in zip(ranks, dimensions))
    assert hint_coefficients == 4456448
    return {
        "scope": "dimensions, ranks and symbolic basis indices; no security inference",
        "source_common_ranks": ranks,
        "target_dimensions": dimensions,
        "hint_coefficients_per_gadget_digit": hint_coefficients,
        "ratio_to_tower_under_equal_gadgets": hint_coefficients / 737280,
        "basis_indices_checked": 256,
        "crt_splitting_required": False,
    }


def tunnel_basis_step(stage, index):
    """Map one tensor basis index (dyadic,b,z3,z5,z17), with its sign."""
    a, b, c, d, f = index
    if stage == 1:
        return (a // 2, b, a % 2, 0, 0), 1
    if stage == 2:
        return (a // 4, b, c, a % 4, 0), 1
    if stage == 3:
        return (0, b, c, d, a % 16), (-1 if a >= 16 else 1)
    if stage == 4:
        return (f, b, c, d, 0), 1
    if stage == 5:
        return (4 * a + d, b, c, 0, 0), 1
    if stage == 6:
        return (4 * a + 2 * c, (2 * b) % 257, 0, 0, 0), 1
    raise ValueError("Unknown tunnel stage")


def tunnel_step(stage, values):
    result = {}
    for index, value in values.items():
        target, sign = tunnel_basis_step(stage, index)
        result[target] = result.get(target, 0) + sign * value
    return {index: value for index, value in result.items() if value}


def check_integral_tunnel(rng):
    # Every signed integer basis column, including the full E automorphism.
    for a in range(256):
        for b in range(1, 257):
            index, sign = (a, b, 0, 0, 0), 1
            for stage in range(1, 7):
                index, new_sign = tunnel_basis_step(stage, index)
                sign *= new_sign
            assert index == (2 * (a % 128), (2 * b) % 257, 0, 0, 0)
            assert sign == (-1 if a >= 128 else 1)
    # Actual full-dimension signed vectors, not just symbolic index identities.
    source = {(a, b, 0, 0, 0): rng.randrange(-7, 8)
              for a in range(256) for b in range(1, 257)}
    expected = {}
    for (a, b, _, _, _), value in source.items():
        out = (2 * (a % 128), (2 * b) % 257, 0, 0, 0)
        expected[out] = expected.get(out, 0) + (-value if a >= 128 else value)
    expected = {index: value for index, value in expected.items() if value}
    actual = source
    for stage in range(1, 7):
        bound = max(map(abs, actual.values())) * (2 if stage == 3 else 1)
        actual = tunnel_step(stage, actual)
        assert max(map(abs, actual.values())) <= bound
    assert actual == expected
    # Exact induced infinity norms: enumerate all dyadic/auxiliary basis columns
    # at each interface. E is independently permuted, so one b coordinate suffices.
    shapes = [(256, 1, 1, 1), (128, 2, 1, 1), (32, 2, 4, 1),
              (1, 2, 4, 16), (16, 2, 4, 1), (64, 2, 1, 1)]
    stage_norms, suffix_norms = [], []
    for start, (a_size, c_size, d_size, f_size) in enumerate(shapes, 1):
        stage_rows, suffix_rows = {}, {}
        for a in range(a_size):
            for c in range(c_size):
                for d in range(d_size):
                    for f in range(f_size):
                        index = (a, 1, c, d, f)
                        first, _ = tunnel_basis_step(start, index)
                        stage_rows[first] = stage_rows.get(first, 0) + 1
                        for stage in range(start, 7):
                            index, _ = tunnel_basis_step(stage, index)
                        suffix_rows[index] = suffix_rows.get(index, 0) + 1
        stage_norms.append(max(stage_rows.values()))
        suffix_norms.append(max(suffix_rows.values()))
    assert stage_norms == [1, 1, 2, 1, 1, 1]
    assert suffix_norms == [2, 2, 2, 1, 1, 1]
    ranks = [2, 4, 32, 16, 4, 2]
    common_gains = [511 * 128, 511 * 32 * 3, 511 * 3 * 7,
                    511 * 3 * 7, 511 * 16 * 3, 511 * 64]
    increments = [r * gain for r, gain in zip(ranks, common_gains)]
    propagation = [2, 2, 1, 1, 1, 1]
    noise_factor = sum(x * w for x, w in zip(increments, propagation))
    assert noise_factor == 1332688 == 2608 * 511
    output_bound = 2 * (1 << 48) + 1 + noise_factor * 16 * 128 * 39
    assert output_bound == 563056397877249
    return {
        "scope": "exact integral maps and declared deterministic noise envelopes",
        "basis_columns_checked": 65536,
        "signed_full_dimension_vectors_checked": 1,
        "stage_operator_norms": stage_norms,
        "suffix_operator_norms_including_stage": suffix_norms,
        "common_ring_multiplication_gains": common_gains,
        "switching_factors_before_propagation": increments,
        "switching_factor_after_propagation": noise_factor,
        "input_noise_gain": 2,
        "binary_reencoding_bound": 1,
        "example_output_bound": str(output_bound),
        "crt_lift_gap": "eliminated by integral power-basis maps",
    }


def check_floor_frontier():
    # Security floors here are hypotheses, never inferred security estimates.
    rows = []
    for floor, leaf_length in [(4096, 32), (8192, 64), (16384, 128), (32768, 256)]:
        item = inventory(256, 256, leaf_length)
        depth = item["tower_depth"]
        down_lengths = [256 >> (i + 1) for i in range(depth)]
        factor = 511 * (5 * sum(down_lengths) + leaf_length + 256)
        key_rows = 16 * (3 * depth + leaf_length + 1) + 2 * depth + 3
        pk_error_coordinates = 2 * 65536 + 2 * 256 * sum(down_lengths) + floor
        all_error_coordinates = item["total_hint_coefficients"] * 16 // 2 + pk_error_coordinates
        shared_hints = item["total_hint_coefficients"] - 2 * 256 * sum(down_lengths)
        shared_factor = 511 * ((9 * 65536 // 2 - 6 * floor) // 256)
        shared_rows = 16 * (2 * depth + leaf_length + 1) + depth + 3
        shared_pk_positions = 2 * 65536 + 256 * sum(down_lengths) + floor
        shared_error_positions = shared_hints * 16 // 2 + shared_pk_positions
        rows.append({
            "declared_floor": floor,
            "tower_depth": depth,
            "tower_hint_coefficients_per_digit": item["total_hint_coefficients"],
            "tower_switching_factor": factor,
            "six_to_tower_hint_ratio": 4456448 / item["total_hint_coefficients"],
            "all_public_key_rows_at_g16": key_rows,
            "error_coefficient_positions_at_g16": all_error_coordinates,
            "shared_return_hint_coefficients_per_digit": shared_hints,
            "shared_return_switching_factor": shared_factor,
            "six_to_shared_return_hint_ratio": 4456448 / shared_hints,
            "shared_return_all_public_key_rows_at_g16": shared_rows,
            "shared_return_error_positions_at_g16": shared_error_positions,
            "target_coefficient_call_proxy_per_gN": 1 + 2 * depth + floor / 256,
            "floor_security_qualified": False,
        })
    assert [x["tower_hint_coefficients_per_digit"] for x in rows] == [737280, 1474560, 4521984, 16908288]
    assert rows[0]["tower_switching_factor"] == 1408 * 511
    assert rows[0]["error_coefficient_positions_at_g16"] == 6148096
    assert rows[1]["tower_hint_coefficients_per_digit"] < 4456448 < rows[2]["tower_hint_coefficients_per_digit"]
    assert [x["shared_return_hint_coefficients_per_digit"] for x in rows] == [622592, 1376256, 4456448, 16908288]
    assert rows[0]["shared_return_switching_factor"] == 1056 * 511
    assert rows[0]["shared_return_all_public_key_rows_at_g16"] == 630
    assert rows[0]["shared_return_error_positions_at_g16"] == 5173248
    return rows


def cbd20_from_word(word):
    """Exact finite-law map from40 ideal bits, not an entropy source."""
    assert 0 <= word < (1 << 40)
    return (word & ((1 << 20) - 1)).bit_count() - (word >> 20).bit_count()


def ternary_from_pairs(pairs):
    """Ideal unbiased rejection map; None denotes exhausted candidate pairs."""
    for pair in pairs:
        assert 0 <= pair < 4
        if pair < 3:
            return pair - 1
    return None


def check_exact_leaf_law(rng):
    probabilities = [comb(40, 20 + value) for value in range(-20, 21)]
    assert sum(probabilities) == 1 << 40
    assert sum(value * mass for value, mass in zip(range(-20, 21), probabilities)) == 0
    assert sum(value * value * mass for value, mass in zip(range(-20, 21), probabilities)) == 10 * (1 << 40)
    assert Fraction(probabilities[0] + probabilities[-1], 1 << 40) == Fraction(1, 1 << 39)
    assert cbd20_from_word((1 << 20) - 1) == 20
    assert cbd20_from_word(((1 << 20) - 1) << 20) == -20
    assert all(-20 <= cbd20_from_word(rng.getrandbits(40)) <= 20 for _ in range(1000))
    rejection_counts = {None: 0, -1: 0, 0: 0, 1: 0}
    for pairs in product(range(4), repeat=3):
        rejection_counts[ternary_from_pairs(pairs)] += 1
    assert rejection_counts == {None: 1, -1: 21, 0: 21, 1: 21}

    # Exact coefficient pairings versus independent cyclic convolution. Every
    # nonzero output coordinate has a unimodular difference-chain pairing.
    pairing_checks = 0
    for prime in (3, 5, 17, 257):
        mask = [0] + [rng.randrange(-20, 21) for _ in range(prime - 1)]
        secret = [0] + [rng.randrange(-1, 2) for _ in range(prime - 1)]
        cyclic = [0] * prime
        for i in range(1, prime):
            for j in range(1, prime):
                cyclic[(i + j) % prime] += mask[i] * secret[j]
        for d in range(1, prime):
            transformed_mask = [mask[(d - j) % prime] - mask[-j % prime]
                                for j in range(1, prime)]
            assert sum(a * s for a, s in zip(transformed_mask, secret[1:])) == cyclic[d] - cyclic[0]
            ordered_secret = [secret[(k * d) % prime] for k in range(1, prime)]
            differences = [ordered_secret[k + 1] - ordered_secret[k]
                           for k in range(prime - 2)] + [-ordered_secret[-1]]
            recovered = [0] * (prime - 1)
            running_sum = 0
            for k in range(prime - 2, -1, -1):
                running_sum -= differences[k]
                recovered[k] = running_sum
            assert recovered == ordered_secret
            pairing_checks += 1
    assert pairing_checks == 278

    profiles = []
    n_root, e, g, digit_bound, beta = 65536, 256, 16, 128, 20
    root_gain = 256 * 511
    assert beta * (2 * root_gain + 1) == 5232660
    q = (1 << 127) - 1
    for m, k, public_rows, public_coordinates in ((4096, 3, 630, 5173248), (8192, 2, 1109, 11198464)):
        hint_coefficients = g * (6 * n_root - 8 * m + 4 * m * m // e)
        stage_secret_coordinates = 2 * n_root + sum(n_root >> (i + 1) for i in range(k)) + m
        assert hint_coefficients // 2 + stage_secret_coordinates == public_coordinates
        support_bits = 40 * public_coordinates
        square_bound = 2 * (1 << 48) + 1 + ((9 * n_root // 2 - 6 * m) // e) * 511 * g * digit_bound * beta
        assert square_bound == {4096: 562972056092673, 8192: 562970046758913}[m]
        ternary_abort = Fraction(stage_secret_coordinates + 2 * n_root, 1 << 192)
        mask_abort = Fraction(public_coordinates, 1 << 254)
        assert ternary_abort < Fraction(1, 1 << 173)
        assert mask_abort < Fraction(1, 1 << 230)
        assert next(j for j in range(1, 17) if pow(q, j, 2 * m // e * 257) == 1) == 16
        final_switch = root_gain * g * digit_bound * beta
        aligned_right = (1 << 28) + final_switch
        product_bound = root_gain * (square_bound + aligned_right + 2 * square_bound * aligned_right) + (root_gain + 1) // 2 + 2 * final_switch
        assert q - 2 - 4 * product_bound > 0
        profiles.append({
            "leaf_dimension": m, "leaf_rows": (2 * m // e) * g + 1,
            "all_public_rows": public_rows, "public_error_coordinates": public_coordinates,
            "error_sampling_ideal_bits": support_bits,
            "stage_secret_coordinates": stage_secret_coordinates,
            "hint_coefficients": hint_coefficients,
            "packed_127_bit_hint_bytes_excluding_every_other_cost": hint_coefficients * 127 // 8,
            "square_output_bound": str(square_bound),
            "common_input_square_product_hint_coefficients": hint_coefficients + 6 * g * n_root,
            "common_input_square_product_bound": str(product_bound),
            "all_error_support_overflow_probability": 0,
            "ternary_abort_bound_with_two_root_ephemerals": str(ternary_abort),
            "public_mask_abort_bound": str(mask_abort),
            "security_128_qualified": False,
        })
    return {"scope": "exact finite laws, arithmetic and scalar-marginal map; no encrypted backend",
            "error_law": "CBD20", "secret_law": "uniform ternary", "error_variance": 10,
            "coefficient_pairing_checks": pairing_checks, "ternary_three_pair_exhaustive_inputs": 64,
            "profiles": profiles, "cryptographic_entropy_source_audited": False}


def check_prepared_transform_ledger():
    # Lucas primality certificates: complete p-1 factorization plus a primitive
    # root witness. Trial division is cheap for these <=31-bit factor primes.
    certificates = [
        (1152921504002872321, 38, [(2, 10), (3, 2), (5, 1), (17, 1), (47, 1), (257, 1), (2617, 1), (46559, 1)]),
        (1152921503566671361, 14, [(2, 9), (3, 1), (5, 1), (17, 1), (191, 1), (257, 1), (179896663, 1)]),
        (1152921503264686081, 7, [(2, 14), (3, 1), (5, 1), (17, 1), (257, 1), (1073758207, 1)]),
    ]
    conductor = 512 * 255 * 257
    modulus_product = 1
    for prime, generator, factors in certificates:
        factored = 1
        for factor, exponent in factors:
            assert factor >= 2 and all(factor % divisor for divisor in range(2, isqrt(factor) + 1))
            factored *= factor**exponent
            assert gcd(pow(generator, (prime - 1) // factor, prime) - 1, prime) == 1
        assert factored == prime - 1
        assert pow(generator, prime - 1, prime) == 1
        assert (prime - 1) % conductor == 0 and prime.bit_length() == 60
        # A concrete primitive root of the full common conductor.
        root = pow(generator, (prime - 1) // conductor, prime)
        assert pow(root, conductor, prime) == 1
        assert all(pow(root, conductor // factor, prime) != 1 for factor in (2, 3, 5, 17, 257))
        modulus_product *= prime
    q = (1 << 127) - 1
    j_kappa_max = max(r * 16 * gain for r, gain in zip(
        (2, 4, 32, 16, 4, 2), (65408, 49056, 10731, 10731, 24528, 32704)))
    assert j_kappa_max == 5494272
    reconstruction_threshold = j_kappa_max * 128 * (q - 1)
    assert reconstruction_threshold == 703266816 * (q - 1)
    assert reconstruction_threshold.bit_length() == 157 and modulus_product > reconstruction_threshold
    # Each entry: common dimension, digit forwards, output inverses, vector
    # MACs, one-time prepared-hint forwards. Equal policy on BOTH routes.
    tower = [(32768, 48, 8, 192, 128), (16384, 64, 8, 256, 64), (256, 4096, 256, 262144, 65536)]
    six = [(32768, 32, 4, 128, 128), (16384, 32, 8, 256, 256),
           (16384, 64, 8, 512, 512), (2048, 768, 64, 24576, 24576), (8192, 64, 8, 512, 512)]
    volumes = {name: [sum(row[0] * row[col] for row in table) for col in range(1, 5)]
               for name, table in (("tower", tower), ("six", six))}
    n, g = 65536, 16
    assert volumes["tower"] == [7 * g * n // 2, 7 * n, 74 * g * n, 1376256 * g]
    assert volumes["six"] == [9 * g * n // 2, 9 * n, 68 * g * n, 4456448 * g]
    return {"scope": "exact prepared-transform counts and auxiliary-prime existence, not timing",
            "auxiliary_primes": [row[0] for row in certificates],
            "primality_certificates_checked": 3, "conductor": conductor,
            "reconstruction_threshold_bits": 157, "product_bits": modulus_product.bit_length(),
            "coefficient_volumes_per_prime": volumes,
            "tower_extra_twiddle_multiplications_per_prime": 2 * n,
            "actual_transform_backend_executed": False}


def check_leaf_geometry():
    # Exact Gram identities and game inventory, not a hardness estimate.
    for prime in [3, 5, 17, 257]:
        degree = prime - 1
        for column in [0, 1]:
            gram_inverse_product = sum(
                (prime * (t == 0) - 1) * ((t == column) + 1)
                for t in range(degree)
            )
            assert gram_inverse_product == prime * (column == 0)
        assert prime - degree == 1
    q = (1 << 127) - 1
    inverse_two = (q + 1) // 2
    for mask, secret, error in [(0, 1, -39), (7, -1, 39), (q - 1, 0, 1)]:
        value = (-mask * secret + 2 * error) % q
        assert (inverse_two * value) % q == (-(inverse_two * mask) * secret + error) % q
    # Lucas-Lehmer is an exact primality test for the prime exponent127.
    assert all(127 % p for p in range(2, 12))
    residue = 4
    for _ in range(125):
        residue = (residue * residue - 2) % q
    assert residue == 0
    leaf_order = next(k for k in range(1, 8225) if pow(q, k, 8224) == 1)
    assert leaf_order == 16
    return {
        "scope": "exact basis geometry, modulus arithmetic and leaf game inventory",
        "cyclotomic_conductor": 8224,
        "degree": 4096,
        "q": str(q),
        "q_prime_lucas_lehmer": True,
        "joint_leaf_rows_with_public_key": 513,
        "gram_eigenvalues": [16, 4112],
        "gram_eigenvalue_ratio": 257,
        "coefficient_functional_squared_norm": "2/4112",
        "ciphertext_modulus_residue_degree": 16,
        "prime_ideal_components": 256,
        "invertible_row_scaling_removes_factor_two_from_error": True,
        "reference_envelope_itself_specifies_secret_law": False,
        "finite_law_candidate_checked_separately": True,
        "encrypted_backend_sampler_verified": False,
        "security_128_qualified": False,
        "projection_count_is_attack_evidence": False,
    }


def normal_to_standard(value, prime):
    degree = prime - 1
    low = (value & ((1 << (degree - 1)) - 1)) << 1
    return low ^ (((1 << degree) - 1) if value >> (degree - 1) else 0)


def standard_to_normal(value, prime):
    degree = prime - 1
    constant = value & 1
    return ((value >> 1) ^ (constant * ((1 << (degree - 1)) - 1))) | (
        constant << (degree - 1)
    )


def coefficient_product(left, right, prime):
    """Schoolbook binary polynomial product, reduced by Phi_prime."""
    left = normal_to_standard(left, prime)
    right = normal_to_standard(right, prime)
    product = 0
    while right:
        if right & 1:
            product ^= left
        right >>= 1
        left <<= 1
    modulus = (1 << prime) - 1
    degree = prime - 1
    while product.bit_length() > degree:
        product ^= modulus << (product.bit_length() - prime)
    return standard_to_normal(product, prime)


def reference_product(left, right, prime):
    length = len(left)
    result = [0] * length
    for i, x in enumerate(left):
        for j, y in enumerate(right):
            result[(i + j) % length] ^= coefficient_product(x, y, prime)
    return result


def frobenius_permutation(value, prime):
    result = 0
    for j in range(prime - 1):
        if (value >> j) & 1:
            result ^= 1 << ((2 * (j + 1) % prime) - 1)
    return result


def compressed_square(values, prime, stop_length):
    length = len(values)
    if length < 2 or length & (length - 1):
        raise ValueError("A compressed-square input needs power-of-two length >= 2")
    if stop_length < 2 or stop_length & (stop_length - 1):
        raise ValueError("The leaf length must be a power of two >= 2")
    if length <= stop_length:
        result = [0] * (length // 2)
        for i, value in enumerate(values):
            result[i % len(result)] ^= frobenius_permutation(value, prime)
        return result
    even = compressed_square(values[::2], prime, stop_length)
    odd = compressed_square(values[1::2], prime, stop_length)
    return [value for pair in zip(even, odd) for value in pair]


def embed_even(values):
    return [value for x in values for value in (x, 0)]


def inventory(length, degree, stop_length, digits=1):
    if length % stop_length or (length // stop_length) & (length // stop_length - 1):
        raise ValueError("Invalid tower split")
    depth = (length // stop_length).bit_length() - 1
    targets = [degree * (length >> (i + 1)) for i in range(depth)]
    leaf_target = degree * stop_length // 2
    components = {
        "downward_hint_coefficients": 4 * digits * sum(targets),
        "leaf_hint_coefficients": 2 * digits * stop_length * leaf_target,
        "upward_hint_coefficients": 2 * digits * sum(targets),
        "final_hint_coefficients": 2 * digits * degree * length,
    }
    total = sum(components.values())
    direct = 2 * digits * length * degree * length
    return {
        "L": length,
        "E_degree": degree,
        "leaf_input_L": stop_length,
        "tower_depth": depth,
        "leaf_calls": 1 << depth,
        "minimum_output_dimension": leaf_target,
        **components,
        "total_hint_coefficients": total,
        "direct_full_ring_hint_coefficients": direct,
        "equal_gadget_ratio": direct / total,
    }


def main():
    rng = random.Random(20260907)
    cases = 0
    # Exhaust all binary tensor messages at small dimensions.
    for prime, length in [(3, 2), (3, 4), (5, 2)]:
        degree = prime - 1
        for packed in range(1 << (degree * length)):
            message = [(packed >> (degree * i)) & ((1 << degree) - 1) for i in range(length)]
            expected = reference_product(message, message, prime)
            for stop in [2, length]:
                actual = embed_even(compressed_square(message, prime, stop))
                assert actual == expected, (prime, length, packed, stop)
                cases += 1
    # Full coefficient ring and principal L=256 profile; direct multiplication
    # is independent of the recursively applied square permutation.
    for prime, length in [(7, 16), (17, 32), (257, 16), (257, 256)]:
        degree = prime - 1
        message = [rng.getrandbits(degree) for _ in range(length)]
        expected = reference_product(message, message, prime)
        for stop in [2, min(8, length), min(32, length), length]:
            actual = embed_even(compressed_square(message, prime, stop))
            assert actual == expected, (prime, length, stop)
            cases += 1
    # Exact signed integer error vectors: interleaving neither adds nor cancels
    # coordinates and therefore has norm max. This is not a sampler tail test.
    for width in [1, 2, 16, 4096]:
        left = [rng.randrange(-1000, 1001) for _ in range(width)]
        right = [rng.randrange(-1000, 1001) for _ in range(width)]
        merged = [value for pair in zip(left, right) for value in pair]
        assert max(map(abs, merged)) == max(max(map(abs, left)), max(map(abs, right)))
    profile = inventory(256, 256, 32)
    assert profile["total_hint_coefficients"] == 737280
    assert profile["direct_full_ring_hint_coefficients"] == 33554432
    assert profile["minimum_output_dimension"] == 4096
    # Exact sufficient noise certificate in the stated unscaled BGV interface.
    # These are proposed phase-class bounds, not sampled execution radii.
    q = (1 << 127) - 1
    digits, digit_bound, row_bound = 16, 128, 39
    root_gain = 256 * 511
    switch_factor = digits * digit_bound * row_bound
    down = [2 * switch_factor * (length * 511) for length in [128, 64, 32]]
    up = [switch_factor * (length * 511) for length in [128, 64, 32]]
    leaf = 32 * switch_factor * 511
    final = switch_factor * root_gain
    left_noise, right_noise = 1 << 48, 1 << 28
    tower_noise = 2 * left_noise + 2 * sum(down) + 1 + leaf + sum(up) + final

    def product_noise(left, right):
        # Independent output key: linear AND quadratic source-secret banks.
        return root_gain * (left + right + 2 * left * right) + (root_gain + 1) // 2 + 2 * final

    tower_product_noise = product_noise(tower_noise, right_noise)
    ordinary_square_noise = product_noise(left_noise, left_noise)
    ordinary_product_noise = product_noise(ordinary_square_noise, right_noise)
    assert 2 * (1 + 2 * tower_product_noise) < q
    assert 2 * (1 + 2 * ordinary_square_noise) < q
    assert 2 * (1 + 2 * ordinary_product_noise) >= q
    # This valid-phase example also demonstrates an actual wrap, not merely
    # failure of the conservative bound. It is not a random-ciphertext test.
    raw_ordinary = (2 * left_noise) ** 2 * (2 * right_noise)
    assert raw_ordinary == q + 1
    assert raw_ordinary % q == 1
    raw_tower = (2 * left_noise) * (2 * right_noise)
    assert raw_tower == 1 << 78 and raw_tower < q // 2 and raw_tower % 2 == 0
    admission = {
        "scope": "conditional phase-class correctness; no security qualification",
        "q": str(q),
        "gadget_digits": digits,
        "digit_bound": digit_bound,
        "row_error_bound": row_bound,
        "input_noise_D": str(left_noise),
        "input_noise_C": str(right_noise),
        "tower_output_noise_bound": str(tower_noise),
        "tower_then_product_noise_bound": str(tower_product_noise),
        "ordinary_square_noise_bound": str(ordinary_square_noise),
        "ordinary_then_product_noise_bound": str(ordinary_product_noise),
        "tower_then_product_admitted": True,
        "ordinary_square_alone_admitted": True,
        "ordinary_then_product_bound_admitted": False,
        "explicit_ordinary_zero_message_wrap_residue": raw_ordinary % q,
        "explicit_tower_zero_message_phase": str(raw_tower),
    }
    # Stronger ordinary comparator: switch BOTH common-key linear inputs,
    # retain the raw degree-three ciphertext, then switch once to a new key.
    target_q, target_digits, secret_row_norm = (1 << 89) - 1, 12, 131072
    switched_left = switched_noise_bound(left_noise, q, target_q, secret_row_norm)
    switched_right = switched_noise_bound(right_noise, q, target_q, secret_row_norm)
    assert (switched_left, switched_right) == (66560, 65537)

    def raw_product_noise(left, right):
        return root_gain * (left + right + 2 * left * right) + (root_gain + 1) // 2

    raw_square = raw_product_noise(switched_left, switched_left)
    raw_product = raw_product_noise(raw_square, switched_right)
    lazy_switch_increment = 3 * target_digits * root_gain * digit_bound * row_bound
    lazy_noise = raw_product + lazy_switch_increment
    assert raw_square == 1159108291526528
    assert lazy_noise == 19874890487897648731160192
    margin = target_q - 2 - 4 * lazy_noise
    assert margin == 539470457691099542524921341 and margin > 0
    lazy_hints = 6 * target_digits * 65536
    tower_product_hints = inventory(256, 256, 32, digits)["total_hint_coefficients"] + 4 * digits * 65536
    aligned_right = right_noise + final
    aligned_tower_noise = product_noise(tower_noise, aligned_right)
    assert aligned_right == 10716971008
    assert aligned_tower_noise == 1578617946643973195170808266368
    assert q - 2 - 4 * aligned_tower_noise > 0
    assert lazy_hints == 4718592 and tower_product_hints == 15990784
    common_input_tower_hints = tower_product_hints + 2 * digits * 65536
    assert common_input_tower_hints == 18087936
    # All-public-key tower instantiation: count shared rows once, not per call.
    tower_vertices = 2 * 3 + 3
    tower_rows_with_pks = digits * (3 * 3 + 32 + 1) + tower_vertices
    assert tower_rows_with_pks == 681
    modulus_comparator = {
        "scope": "derived conditional correctness and inventory; no timing/security claim",
        "input_contract": "X,C initially share a source key at q",
        "target_q": str(target_q),
        "target_gadget_digits": target_digits,
        "secret_multiplication_row_norm_bound": secret_row_norm,
        "switched_input_noise_bounds": [switched_left, switched_right],
        "raw_square_noise_bound": str(raw_square),
        "raw_degree_three_noise_bound": str(raw_product),
        "final_three_bank_noise_increment": lazy_switch_increment,
        "final_noise_bound": str(lazy_noise),
        "strict_decoding_margin": str(margin),
        "hint_coefficients_at_89_bits": lazy_hints,
        "max_ciphertext_components": 4,
        "straightforward_product_live_ring_buffers_excluding_scratch": 9,
        "tower_plus_product_hint_coefficients_at_127_bits": tower_product_hints,
        "tower_common_input_hint_coefficients_at_127_bits": common_input_tower_hints,
        "tower_common_input_final_noise_bound": str(aligned_tower_noise),
        "tower_all_public_keys_joint_rows": tower_rows_with_pks,
        "ordinary_route_admitted": True,
        "tower_common_input_route_admitted": True,
        "fixed_modulus_example_establishes_optimized_efficiency_advantage": False,
    }
    shared_square_noise = 2 * left_noise + 1 + 1056 * 511 * switch_factor
    shared_common_input_noise = product_noise(shared_square_noise, aligned_right)
    shared_common_input_hints = 622592 * digits + 6 * digits * 65536
    assert shared_common_input_hints == 16252928
    assert q - 2 - 4 * shared_common_input_noise > 0
    modulus_comparator.update({
        "optimized_shared_return_square_noise_bound": str(shared_square_noise),
        "optimized_shared_return_common_input_noise_bound": str(shared_common_input_noise),
        "optimized_shared_return_common_input_hint_coefficients_at_127_bits": shared_common_input_hints,
        "ordinary_hint_inventory_still_smaller_after_tower_optimization": lazy_hints < shared_common_input_hints,
    })
    print(json.dumps({
        "status": "PASS",
        "scope": "deterministic plaintext algebra, phase bounds and integer inventory only",
        "square_equalities_checked": cases,
        "interleaving_norm_cases": 4,
        "seed": 20260907,
        "profile": profile,
        "conditional_admission_example": admission,
        "scalar_parity_switch_cases": check_scalar_modulus_switch(),
        "modulus_switched_lazy_comparator": modulus_comparator,
        "factored_tunnel_inventory": check_tunnel_inventory(),
        "integral_tunnel_checks": check_integral_tunnel(rng),
        "conditional_floor_frontier": check_floor_frontier(),
        "leaf_geometry_and_game": check_leaf_geometry(),
        "exact_finite_law_candidate": check_exact_leaf_law(rng),
        "prepared_transform_ledger": check_prepared_transform_ledger(),
        "not_tested": ["encrypted implementation", "actual sampler/backend correspondence", "security", "runtime comparison", "novelty"],
    }, indent=2))


if __name__ == "__main__":
    main()
