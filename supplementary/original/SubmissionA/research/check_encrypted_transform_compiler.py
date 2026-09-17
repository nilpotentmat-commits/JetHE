"""Public sparse-transform and Galois-layout checks, not HE execution.

The circuit consumes arbitrary extension-field coefficients on the monomial
basis. Every public sparse map is actually applied as masked cyclic pulls.
No cryptographic keys, performance measurements or security estimates exist.
"""

from itertools import product
from math import gcd, prod
from random import Random
import json

from check_frobenius_compiler import Field
from check_private_composition import value, power, compose, prepared_inner


def subspaces(basis, field):
    polys, points = [[0, 1]], [0]
    for beta in basis:
        old = polys[-1]
        delta = value(old, beta, field)
        assert delta, "The public subspace basis must be independent"
        new = [0] * (2 * len(old) - 1)
        for i, c in enumerate(old):
            new[2 * i] ^= field.mul(c, c)
            new[i] ^= field.mul(delta, c)
        polys.append(new)
        points += [x ^ beta for x in points]
    return polys, points


def sparse_map(size, entries):
    diagonals = {}
    for out, inp, scalar in entries:
        if scalar:
            shift = (inp - out) % size
            diagonals.setdefault(shift, [0] * size)[out] ^= scalar
    return {d: v for d, v in diagonals.items() if any(v)}


def apply_map(diagonals, vector, field):
    out, size = [0] * len(vector), len(vector)
    for shift, weights in diagonals.items():
        for i, w in enumerate(weights):
            out[i] ^= field.mul(w, vector[(i + shift) % size])
    return out


def circuit(basis, field, affine=0, inverse=False):
    polys, points = subspaces(basis, field)
    size, layers = len(points), []
    for s in reversed(range(len(basis))):
        half, poly = 1 << s, polys[s]
        low_terms = [(i, c) for i, c in enumerate(poly[:-1]) if c]
        assert len(low_terms) <= s
        assert all(i & (i - 1) == 0 and i <= half // 2 for i, _ in low_terms)
        q_terms = [(i, i, 1) for i in range(size)]
        r_terms = list(q_terms)
        butterflies = []
        for start in range(0, size, 2 * half):
            alpha = affine ^ points[start]
            c, delta = value(poly, alpha, field), value(poly, basis[s], field)
            for degree, coefficient in low_terms:
                # Q=h+high_half(p*h); T^2=0 because deg(p)<=half/2.
                for i in range(degree):
                    q_terms.append((start + half + i,
                                    start + 2 * half + i - degree, coefficient))
                # R=l+low_half(p*Q).
                for i in range(degree, half):
                    r_terms.append((start + i, start + half + i - degree, coefficient))
            inv_delta = power(delta, (1 << field.d) - 2, field)
            ratio = field.mul(c, inv_delta)
            for i in range(half):
                lo, hi = start + i, start + half + i
                if inverse:
                    butterflies.extend([(lo, lo, 1 ^ ratio), (lo, hi, ratio),
                                        (hi, lo, inv_delta), (hi, hi, inv_delta)])
                else:
                    butterflies.extend([(lo, lo, 1), (lo, hi, c),
                                        (hi, lo, 1), (hi, hi, c ^ delta)])
        q_map, r_map = sparse_map(size, q_terms), sparse_map(size, r_terms)
        butterfly = sparse_map(size, butterflies)
        if inverse:
            layers[0:0] = [butterfly, r_map, q_map]
        else:
            layers.extend([q_map, r_map, butterfly])
    return layers, [affine ^ x for x in points]


def run(layers, vector, field):
    for layer in layers:
        vector = apply_map(layer, vector, field)
    return vector


def structured_composition(f, g, field):
    """Both-private recurrence using explicit padded transforms, no interpolation oracle."""
    length, children = len(f), [[c] for c in f]
    for inner in reversed(prepared_inner(g, field)):
        n, half, parents = len(inner), len(inner) // 2, []
        basis = [1 << i for i in range(n.bit_length() - 1)]
        forward, _ = circuit(basis, field)
        inverse, _ = circuit(basis, field, inverse=True)
        # Both channels can share the odd child's forward transform.
        odd_inner = inner[1::2] + [0] * half
        even_inner = inner[2::2] + [0] * (half + 1)
        odd_values, even_values = run(forward, odd_inner, field), run(forward, even_inner, field)
        branches = length // n
        for t in range(branches):
            odd_child = children[t + branches]
            values = run(forward, odd_child + [0] * half, field)
            odd_product = run(inverse, [field.mul(a, b) for a, b in zip(values, odd_values)], field)
            even_product = run(inverse, [field.mul(a, b) for a, b in zip(values, even_values)], field)
            parent = [0] * n
            for i, c in enumerate(children[t]):
                parent[2 * i] ^= c
            for i in range(half):
                parent[2 * i + 1] ^= odd_product[i]
            for i in range(half - 1):
                parent[2 * i + 2] ^= even_product[i]
            parents.append(parent)
        children = parents
    return children[0]


def adjacent_bit_swap(vector, bit):
    """A three-diagonal public permutation, used to expose all wiring costs."""
    entries = []
    for out in range(len(vector)):
        different = ((out >> bit) ^ (out >> (bit + 1))) & 1
        inp = out ^ ((3 << bit) if different else 0)
        entries.append((out, inp, 1))
    return sparse_map(len(vector), entries)


def extract_odd(vector, j, field):
    """Move index bit j to the top and flip it: odd children occupy low half."""
    out, ell = list(vector), len(vector).bit_length() - 1
    for bit in range(j, ell - 1):
        out = apply_map(adjacent_bit_swap(out, bit), out, field)
    half = len(out) // 2
    return out[half:] + out[:half]


def interleaved_composition(f, g, field):
    """One length-L coefficient-slot state, with all sparse wiring executed."""
    length, ell, state = len(f), len(f).bit_length() - 1, list(f)
    for j in reversed(range(ell)):
        r, n = 1 << j, length >> j
        basis = [1 << i for i in range(n.bit_length() - 1)]
        forward, _ = circuit(basis, field)
        inverse, _ = circuit(basis, field, inverse=True)

        def lift(layers):
            return [{d * r: [weights[i // r] for i in range(length)]
                     for d, weights in layer.items()} for layer in layers]

        inner = list(g[:n])
        for _ in range(j):
            inner = [field.mul(c, c) for c in inner]
        prepared = extract_odd(state, j, field)
        odd_child = prepared[:length // 2] + [0] * (length // 2)
        values = run(lift(forward), odd_child, field)
        odd_coefficients, even_coefficients = [0] * length, [0] * length
        for t in range(r):
            for i, c in enumerate(inner[1::2]):
                odd_coefficients[t + r * i] = c
            for i, c in enumerate(inner[2::2]):
                even_coefficients[t + r * i] = c
        odd_values = run(lift(forward), odd_coefficients, field)
        even_values = run(lift(forward), even_coefficients, field)
        odd_product = run(lift(inverse), [field.mul(a, b) for a, b in zip(values, odd_values)], field)
        even_product = run(lift(inverse), [field.mul(a, b) for a, b in zip(values, even_values)], field)
        combined = [0] * length
        for row in range(length // 2):
            combined[row + length // 2] = odd_product[row]
            if row >= r:
                combined[row] = even_product[row - r]
        for bit in reversed(range(j, ell - 1)):
            combined = apply_map(adjacent_bit_swap(combined, bit), combined, field)
        state = [a ^ (b if not i & r else 0) for i, (a, b) in enumerate(zip(combined, state))]
    return state


def coset_checks():
    conductor, aa, bb, cc = 65535, 43691, 33136, 65281
    assert pow(aa, 2, conductor) == 1
    assert pow(bb, 8, conductor) == pow(2, 4, conductor)
    assert pow(cc, 128, conductor) == pow(2, 8, conductor)
    reps = {(a, b, c): pow(aa, a, conductor) * pow(bb, b, conductor)
            * pow(cc, c, conductor) % conductor
            for a, b, c in product(range(2), range(8), range(128))}
    units = {r * pow(2, e, conductor) % conductor for r in reps.values() for e in range(16)}
    assert len(units) == 32768 and all(gcd(u, conductor) == 1 for u in units)
    cases = 0
    # Every logical shift, every position: exact representatives, not only cosets.
    for shift in range(256):
        epsilon, t = divmod(shift, 128)
        for a, b, c in reps:
            carry = int(c + t >= 128)
            exponent = (pow(aa, (epsilon + carry) % 2, conductor)
                        * pow(cc, t, conductor) * pow(2, 8 * carry, conductor)) % conductor
            destination = (128 * a + c + shift) % 256
            target = reps[(destination // 128, b, destination % 128)]
            assert reps[(a, b, c)] * exponent % conductor == target
            cases += 1
    return cases


def tensor_mul(x, y, primes):
    basis = list(product(*(range(1, p) for p in primes)))
    index, out = {b: i for i, b in enumerate(basis)}, [0] * len(basis)
    for i, xi in enumerate(x):
        for j, yj in enumerate(y):
            choices = []
            for a, b, p in zip(basis[i], basis[j], primes):
                e = (a + b) % p
                choices.append([(e, 1)] if e else [(k, -1) for k in range(1, p)])
            for expansion in product(*choices):
                out[index[tuple(e for e, _ in expansion)]] += xi * yj * prod(s for _, s in expansion)
    return out


def tensor_auto(x, exponent, primes):
    basis = list(product(*(range(1, p) for p in primes)))
    index, out = {b: i for i, b in enumerate(basis)}, [0] * len(basis)
    for b, v in zip(basis, x):
        out[index[tuple(a * exponent % p for a, p in zip(b, primes))]] = v
    return out


def weighted_phase_checks(rng):
    """Small exact integer phase identities; vectors are not generated HE keys."""
    primes, m, kappa, cases = (3, 5), 8, 21, 0
    for terms in (1, 2, 4):
        for _ in range(8):
            mu = [rng.randrange(2) for _ in range(m)]
            err = [rng.randrange(-3, 4) for _ in range(m)]
            phase = [a + 2 * b for a, b in zip(mu, err)]
            witness = [rng.randrange(-1, 2) for _ in range(m)]
            c1 = [rng.randrange(-2, 3) for _ in range(m)]
            c0 = [a - b for a, b in zip(phase, tensor_mul(c1, witness, primes))]
            image, source_image, row_total = [0] * m, [0] * m, [0] * m
            for _ in range(terms):
                a = [rng.randrange(2) for _ in range(m)]
                sigma = rng.choice((1, 2, 4, 7, 8, 11, 13, 14))
                mapped = tensor_mul(a, tensor_auto(phase, sigma, primes), primes)
                clean = tensor_mul(a, tensor_auto(mu, sigma, primes), primes)
                # One exact digit and weighted payload; g=1 in this formal fixture.
                digit = tensor_auto(c1, sigma, primes)
                row = [rng.randrange(-2, 3) for _ in range(m)]
                payload = tensor_mul(a, tensor_auto(witness, sigma, primes), primes)
                row_phase = [x + 2 * e for x, e in zip(payload, row)]
                public_part = tensor_mul(a, tensor_auto(c0, sigma, primes), primes)
                external_part = tensor_mul(digit, row_phase, primes)
                gadget_error = tensor_mul(digit, row, primes)
                assert [x + y for x, y in zip(public_part, external_part)] == [x + 2 * e for x, e in zip(mapped, gadget_error)]
                image = [u + v + 2 * e for u, v, e in zip(image, mapped, gadget_error)]
                source_image = [u + v for u, v in zip(source_image, clean)]
                row_total = [u + v for u, v in zip(row_total, gadget_error)]
            canonical = [x % 2 for x in source_image]
            actual_error = [(a - b) // 2 for a, b in zip(image, canonical)]
            envelope = terms * kappa * 3 + terms * kappa * 2 * 2 + (terms * kappa + 1) // 2
            assert max(map(abs, actual_error)) <= envelope
            modulus = 4 * envelope + 3
            centered = [((x + modulus // 2) % modulus) - modulus // 2 for x in image]
            assert [x % 2 for x in centered] == canonical
            cases += 1
    return cases


def main():
    rng = Random(2026090809)
    fixtures, basis_columns, wire_cases, composition_cases = 0, 0, 0, 0
    for degree, modulus in ((2, 0b111), (4, 0b10011), (16, 0x1100B)):
        field = Field(degree, modulus)
        for b in range(1, min(degree, 8) + 1):
            basis = [1 << i for i in range(b)]
            for affine in (0, (1 << degree) - 1):
                forward, points = circuit(basis, field, affine)
                inverse, _ = circuit(basis, field, affine, True)
                assert sum(d != 0 for layer in forward for d in layer) <= b * (b + 1)
                assert sum(map(len, forward)) <= b * b + 4 * b
                for _ in range(2):
                    coefficients = [rng.randrange(1 << degree) for _ in points]
                    evaluated = run(forward, coefficients, field)
                    assert evaluated == [value(coefficients, x, field) for x in points]
                    assert run(inverse, evaluated, field) == coefficients
                    fixtures += 1
                if affine == 0 and b <= 5:
                    for index in range(1 << b):
                        column = [int(i == index) for i in range(1 << b)]
                        assert run(forward, column, field) == [power(x, index, field) for x in points]
                        basis_columns += 1
            for j in range(b):
                vector = [rng.randrange(1 << degree) for _ in range(1 << b)]
                prepared = extract_odd(vector, j, field)
                r, n = 1 << j, (1 << b) >> j
                for t in range(r):
                    for i in range(n // 2):
                        assert prepared[t + r * i] == vector[t + r + 2 * r * i]
                        assert prepared[(1 << (b - 1)) + t + r * i] == vector[t + 2 * r * i]
                wire_cases += 1
            coefficients = [rng.randrange(1 << degree) for _ in range(1 << b)]
            inner = [0] + [rng.randrange(1 << degree) for _ in range((1 << b) - 1)]
            assert structured_composition(coefficients, inner, field) == compose(coefficients, inner, 1 << b, field)
            assert interleaved_composition(coefficients, inner, field) == compose(coefficients, inner, 1 << b, field)
            composition_cases += 1
    print(json.dumps({
        "status": "PASS_PUBLIC_ALGEBRA_ONLY", "forward_inverse_fixtures": fixtures,
        "basis_columns": basis_columns, "wiring_fixtures": wire_cases,
        "composition_fixtures": composition_cases, "exact_galois_rotation_cases": coset_checks(),
        "weighted_map_phase_fixtures": weighted_phase_checks(rng),
        "L256_transform_upper_bounds": {"logical_nonidentity_shifts": 72,
                                        "logical_diagonal_terms": 96,
                                        "physical_weighted_automorphism_terms": 168,
                                        "fresh_destination_stages": 24},
        "exact_field_carrier": {"conductor": 65535, "dimension": 32768,
                                "slots": 2048, "hypercube": [2, 8, 128]},
        "structured_whole_program_upper_bounds": {
            "distinct_weighted_banks": sum(4 * b * b + 20 * b - 3 for b in range(1, 9)),
            "hint_coefficients_over_g_mB": 3024,
            "independent_keys": 1 + sum(8 * b + 1 for b in range(1, 9)),
            "physical_product_calls": 30,
            "public_phase_only": True},
        "scope": "No HE execution, timings, optimized whole-program comparison or security admission"
    }, indent=2))


if __name__ == "__main__":
    main()
