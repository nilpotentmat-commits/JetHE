"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

from bisect import bisect_right
from fractions import Fraction as Q
from itertools import product
from math import isqrt

def synthesize(parameter, prepared, radix_bits):
    """Integer-only version of the Gaussian no-drop substitution."""
    levels = (parameter - 1).bit_length()
    length, tail = 1 << levels, levels - prepared
    assert parameter >= 256 and 1 <= prepared <= levels
    kappa, products = 511 * length, (1 << prepared) - 1
    fresh = (2 * kappa * parameter + 1) * parameter
    delta0 = kappa * (1 << (radix_bits - 1)) * parameter
    carry = (kappa + 1) // 2
    slope = 1 + kappa * (1 + 2 * fresh)
    prefix = (fresh + products * kappa * (2 * fresh + 2 * fresh**2)
              + (products * kappa + 1) // 2)
    power = slope**tail
    geometric = sum(slope**j for j in range(tail))
    constant = power * prefix + (kappa * fresh + carry + 1) * geometric
    linear = delta0 * (2 * power + (slope + 2) * geometric)
    exponent = 2 * (8 * (constant + linear + 1) - 1).bit_length()
    gadget = (exponent + radix_bits) // radix_bits + 1
    delta = delta0 * gadget
    bound = prefix + 2 * delta
    comparisons = 1
    assert bound >= fresh and (1 << exponent) > 2 + 4 * bound
    for _ in range(tail):
        transported = bound + delta
        raw = kappa * (transported + fresh + 2 * transported * fresh) + carry
        next_bound = bound + 3 * delta + raw + 1
        assert next_bound == (slope * bound + kappa * fresh + carry + 1
                              + (slope + 2) * delta)
        assert next_bound >= max(fresh, transported, raw, bound + delta)
        assert (1 << exponent) > 2 + 4 * next_bound
        comparisons += 1
        bound = next_bound
    assert bound == constant + linear * gadget
    assert exponent >= 12 and (1 << exponent) > 2 * 256 * length
    banks = [2] + [2 * (1 << j) + 3 for j in reversed(range(tail))]
    rows = gadget * sum(banks)
    assert rows == gadget * ((1 << (tail + 1)) + 3 * tail)
    inputs, public_keys, secrets = 2 * products + 1 + tail, tail + 1, 2 * tail + 2
    gaussian = secrets + inputs + rows + public_keys + 2 * inputs
    assert gaussian == rows + 3 * tail + 3 + 3 * inputs
    uniform = rows + public_keys
    assert uniform == rows + tail + 1
    return dict(parameter=parameter, length=length, prepared=prepared, tail=tail,
                radix_bits=radix_bits, modulus_bits=exponent+1, gadget=gadget,
                hint_rows=rows, inputs=inputs, gaussian_polynomials=gaussian,
                uniform_polynomials=uniform, admitted_states=comparisons)


def admission_and_inventory():
    cases, states, examples = 0, 0, []
    parameters = (256, 257, 511, 512, 513, 1024, 4095, 4096, 65536)
    for parameter in parameters:
        levels = (parameter - 1).bit_length()
        # Integer evaluation of ceil(d/2 + log2(d+1)), capped by d.
        target = (1 << levels) * (levels + 1)**2
        balanced = min(levels, ((target - 1).bit_length() + 1) // 2)
        for prepared in range(1, levels+1):
            for radix_bits in (1, 4, 48):
                row = synthesize(parameter, prepared, radix_bits)
                cases += 1
                states += row['admitted_states']
                if parameter in (256, 1024, 65536) and prepared == balanced and radix_bits == 48:
                    examples.append(row)
    assert len(examples) == 3 and examples[0]['prepared'] == 8
    return dict(parameter_cases=cases, admitted_complete_states=states,
                balanced_examples=examples, prime_search=False,
                finite_checks_not_asymptotic_proof=True)


def cdf_thresholds(weights, bits):
    assert weights and all(w >= 0 for w in weights) and sum(weights) > 0
    total, cumulative, thresholds = sum(weights), 0, []
    for weight in weights:
        cumulative += weight
        thresholds.append(((1 << bits) * cumulative) // total)
    assert thresholds[-1] == 1 << bits
    return thresholds


def rounded_cdf_checks():
    cases, draws = 0, 0
    for length in range(1, 6):
        for weights in product(range(4), repeat=length):
            if not sum(weights):
                continue
            for bits in (2, 4, 8):
                scale = 1 << bits
                thresholds = cdf_thresholds(weights, bits)
                counts = [0] * length
                for value in range(scale):
                    counts[bisect_right(thresholds, value)] += 1
                assert counts == [b-a for a, b in zip([0]+thresholds[:-1], thresholds)]
                variation = sum((abs(Q(n, scale)-Q(w, sum(weights)))
                                 for n, w in zip(counts, weights)), Q(0)) / 2
                assert variation <= Q(length, scale)
                assert all(n == 0 for n, w in zip(counts, weights) if w == 0)
                cases += 1
                draws += scale
    tables = sum(j+1 for j in range(1, 257))
    assert tables == 33152
    table_examples = []
    for parameter in (256, 257, 1024):
        levels = (parameter - 1).bit_length()
        root = isqrt(parameter * levels**2)
        width = root + int(root**2 != parameter * levels**2) + 1
        precision = 8 * levels**2
        table_examples.append(dict(parameter=parameter, scalar_tables=tables,
                                   offsets_per_table=2*width+1,
                                   threshold_width_bits=precision+1,
                                   raw_threshold_bits=tables*(2*width+1)*(precision+1)))
    return dict(exhaustive_weight_laws=cases, enumerated_uniform_inputs=draws,
                variation_bound='support_size / 2^precision',
                reference_table_examples=table_examples, tables_constructed=False,
                gaussian_weights_computed=False, sampling_randomness_used=False)
