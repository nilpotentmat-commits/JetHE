"""One-carrier shared-kernel composition and its integral Hasse transport.

Deterministic public algebra only. No keys, ciphertexts, benchmarks or security
estimates are generated. The comparison uses the same full-series specification
as check_private_composition.py, not only terminal constant coefficients.
"""

import json
from random import Random

from check_frobenius_compiler import Field
from check_private_composition import compose, mul, value, interpolate, prepared_inner
from check_square_bit_frontier import convolution, digits
from check_frobenius_chain import multiply as tensor_multiply
from check_square_bit_frontier import plus as sparse_plus, norm as sparse_norm


def hasse(x, r):
    out = [0] * len(x)
    for i, c in enumerate(x):
        if i & r:
            out[i - r] = c
    return out


def mixed_hasse(x, mask):
    out = [0] * len(x)
    for i, c in enumerate(x):
        if i & mask == mask:
            out[i - mask] = c
    return out


def translate_one(x):
    """Coefficients of f(t+1) in characteristic two; involutory Pascal map."""
    out, step = list(x), 1
    while step < len(x):
        for i in range(len(x)):
            if not i & step:
                out[i] ^= out[i + step]
        step *= 2
    return out


def frobenius(x, j, field):
    out = [0] * len(x)
    for i, c in enumerate(x[:len(x) >> j]):
        for _ in range(j):
            c = field.mul(c, c)
        out[i << j] = c
    return out


def native_compose(f, g, field, check_states=False):
    length, current = len(f), list(f)
    ell = length.bit_length() - 1
    assert len(g) == length and g[0] == 0 and 1 << ell == length
    for j in reversed(range(ell)):
        r = 1 << j
        odd = hasse(current, r)
        assert hasse(odd, r) == [0] * length
        # No binomial coefficient growth or hidden coefficient Frobenius.
        assert translate_one(hasse(translate_one(current), r)) == odd
        prepared = frobenius(g, j, field)
        prepared[r] ^= 1  # g^(2^j)+z^(2^j), owner-local preparation
        update = mul(prepared, odd, length, field)
        current = [a ^ b for a, b in zip(current, update)]
        if check_states:
            n = length // r
            inner = [frobenius(g, j, field)[r * i] for i in range(n)]
            expected = [0] * length
            for t in range(r):
                result = compose(f[t::r], inner, n, field)
                for i, c in enumerate(result):
                    expected[t + r * i] = c
            assert current == expected
    return current


def prepared_prefix_compose(f, g, field, prefix):
    length, ell = len(f), len(f).bit_length() - 1
    assert 0 <= prefix <= ell
    stride = 1 << (ell - prefix)
    nodes = [mixed_hasse(f, a * stride) for a in range(1 << prefix)]
    products = 0
    for j in reversed(range(ell - prefix, ell)):
        half = len(nodes) // 2
        u = frobenius(g, j, field)
        u[1 << j] ^= 1
        nodes = [[a ^ b for a, b in zip(nodes[t], mul(u, nodes[t + half], length, field))]
                 for t in range(half)]
        products += half
    assert len(nodes) == 1
    current = nodes[0]
    for j in reversed(range(ell - prefix)):
        u = frobenius(g, j, field)
        u[1 << j] ^= 1
        current = [a ^ b for a, b in zip(current, mul(u, hasse(current, 1 << j), length, field))]
        products += 1
    assert products == (1 << prefix) - 1 + ell - prefix
    return current


def sparse_conventional_compose(f, g, field):
    """Even/odd factorization control, with both operands still variable."""
    length, children, occupancy = len(f), [[c] for c in f], []
    for inner in reversed(prepared_inner(g, field)):
        n, half, parents = len(inner), len(inner) // 2, []
        branches = length // n
        occupancy.append(branches * ((n - 1) + max(n - 3, 0)))
        for t in range(branches):
            odd_child = children[t + branches]
            odd_values = [field.mul(value(inner[1::2], x, field), value(odd_child, x, field))
                          for x in range(n - 1)]
            odd_product = interpolate(odd_values, half, field)
            if half > 1:
                even_values = [field.mul(value(inner[2::2], x, field), value(odd_child[:half - 1], x, field))
                               for x in range(n - 3)]
                even_product = interpolate(even_values, half - 1, field)
            else:
                even_product = []
            parent = [0] * n
            for i, c in enumerate(children[t]):
                parent[2 * i] ^= c
            for i, c in enumerate(odd_product):
                parent[2 * i + 1] ^= c
            for i, c in enumerate(even_product):
                parent[2 * i + 2] ^= c
            parents.append(parent)
        children = parents
    return children[0], occupancy


def plus(a, b):
    return [x + y for x, y in zip(a, b)]


def phase_checks(rng):
    identities = 0
    for length in (2, 4, 8, 16, 32):
        for j in range(length.bit_length() - 1):
            r, rank = 1 << j, 2 << j
            for _ in range(4):
                # Scalar-coefficient negacyclic test; E multiplication constant
                # is proved separately in the existing tensor-basis analysis.
                x = [rng.randrange(-20, 21) for _ in range(length)]
                source = [rng.randrange(-3, 4) for _ in range(length)]
                common = [rng.randrange(-3, 4) if i % rank == 0 else 0
                          for i in range(length)]
                assert hasse(convolution(x, common), r) == convolution(hasse(x, r), common)
                reconstruction, error = [0] * length, [0] * length
                for u in range(rank):
                    monomial = [int(i == u) for i in range(length)]
                    payload = hasse(convolution(monomial, source), r)
                    scalar = [0] * length
                    for i in range(0, length, rank):
                        scalar[i] = x[i + u]
                    reconstruction = plus(reconstruction, convolution(scalar, payload))
                    decomposition = [digits(v, 8) for v in scalar]
                    digit = [v[0] for v in decomposition]
                    row_error = [rng.randrange(-2, 3) for _ in range(length)]
                    error = plus(error, convolution(digit, row_error))
                assert reconstruction == hasse(convolution(x, source), r)
                assert max(map(abs, error)) <= length * 128 * 2
                identities += 1
    return identities


def bounds(length, b, B0, fresh, beta=20, prefix=0):
    ell, g = length.bit_length() - 1, (b + 7) // 8
    kappa, lam = 511 * length, 511 * g * 128 * beta
    B, stages = B0, []
    for j in reversed(range(ell)):
        prepared_level = j >= ell - prefix
        inside = B if prepared_level else B + length * lam
        B = (B + (2 if prepared_level else 3) * length * lam
             + kappa * ((1 + 2 * fresh) * inside + fresh)
             + (kappa + 1) // 2 + 1)
        stages.append(B)
    return B, stages, g


def tensor_phase_checks(rng):
    count = 0
    for prime, length in ((3, 4), (5, 8), (17, 8), (257, 32)):
        basis = [(i, k) for i in range(length) for k in range(1, prime)]
        kappa = (2 * prime - 3) * length
        for j in range(length.bit_length() - 1):
            r = 1 << j
            chosen = rng.sample(basis, min(12, len(basis)))
            mu = {a: rng.randrange(2) for a in chosen}
            original_error = {a: rng.randrange(-7, 8) for a in chosen}
            u = {a: rng.randrange(2) for a in chosen}
            fresh_error = {a: rng.randrange(-3, 4) for a in chosen}
            hmu = {(i - r, k): c for (i, k), c in mu.items() if i & r}
            he = {(i - r, k): c for (i, k), c in original_error.items() if i & r}
            # Three independent bounded aggregate switch errors model H,
            # alignment and the TWO relinearization banks (last bound doubled).
            eta_h = {a: rng.randrange(-2, 3) for a in chosen}
            eta_i = {a: rng.randrange(-2, 3) for a in chosen}
            eta_r = {a: rng.randrange(-4, 5) for a in chosen}
            hphase = sparse_plus(hmu, sparse_plus(he, eta_h), 2)
            uphase = sparse_plus(u, fresh_error, 2)
            raw = tensor_multiply(hphase, uphase, length, prime)
            raw = sparse_plus(raw, eta_r, 2)
            total = sparse_plus(raw, sparse_plus(mu, sparse_plus(original_error, eta_i), 2))
            target_raw = sparse_plus(mu, tensor_multiply(hmu, u, length, prime))
            target = {a: c % 2 for a, c in target_raw.items() if c % 2}
            residual = sparse_plus(total, target, -1)
            assert all(c % 2 == 0 for c in residual.values())
            error = {a: c // 2 for a, c in residual.items()}
            # Replace L*lambda by the aggregate per-bank allowance 2.
            bound = 7 + 3 * 2 + kappa * ((1 + 2 * 3) * (7 + 2) + 3) + (kappa + 1) // 2 + 1
            assert sparse_norm(error) <= bound
            count += 1
            # Prefix fusion relinearizes A+U*B once, without Hasse/alignment.
            bphase = sparse_plus(hmu, he, 2)
            prefix_raw = tensor_multiply(bphase, uphase, length, prime)
            prefix_raw = sparse_plus(prefix_raw, sparse_plus(mu, original_error, 2))
            prefix_raw = sparse_plus(prefix_raw, eta_r, 2)
            prefix_residual = sparse_plus(prefix_raw, target, -1)
            assert all(c % 2 == 0 for c in prefix_residual.values())
            prefix_bound = 7 + 2 * 2 + kappa * ((1 + 2 * 3) * 7 + 3) + (kappa + 1) // 2 + 1
            assert sparse_norm({a: c // 2 for a, c in prefix_residual.items()}) <= prefix_bound
            count += 1
    return count


def main():
    rng, cases, columns, prefix_cases, sparse_cases = Random(20260908), 0, 0, 0, 0
    sparse_L256 = []
    for degree, modulus, lengths in ((1, 3, (2, 4, 8, 16)),
                                    (4, 0b10011, (2, 4, 8, 16, 32)),
                                    (16, 0x1100B, (2, 4, 8, 16, 32, 64, 256))):
        field = Field(degree, modulus)
        for length in lengths:
            trials = 1 if length == 256 else 3
            for trial in range(trials):
                f = [rng.randrange(1 << degree) for _ in range(length)]
                g = [0] + [rng.randrange(1 << degree) for _ in range(length - 1)]
                if trial == 1:
                    g = [0] * length
                if trial == 2:
                    g = [0, 1] + [0] * (length - 2)
                result = native_compose(f, g, field, length <= 16)
                assert result == compose(f, g, length, field)
                if trial == 0:
                    prefixes = range(length.bit_length()) if length <= 32 else (1, 2, 4)
                    for prefix in prefixes:
                        assert prepared_prefix_compose(f, g, field, prefix) == result
                        prefix_cases += 1
                    if length - 1 <= 1 << degree:
                        sparse, occupancy = sparse_conventional_compose(f, g, field)
                        assert sparse == result
                        sparse_cases += 1
                        if length == 256:
                            sparse_L256 = occupancy
                cases += 1
            for j in range(length.bit_length() - 1):
                for i in range(length):
                    x = [int(k == i) for k in range(length)]
                    assert translate_one(hasse(translate_one(x), 1 << j)) == hasse(x, 1 << j)
                    columns += 1
    identities = phase_checks(rng)
    tensor_cases = tensor_phase_checks(rng)
    length, ell, m = 256, 8, 65536
    inventory = sum(4 * (1 << j) + 6 for j in range(ell))
    assert inventory == 4 * (length - 1) + 6 * ell == 1068
    # One bounded unscaled correctness envelope, not a security-matched modulus.
    for b in range(64, 1025):
        B, stages, gadget_digits = bounds(length, b, 1 << 20, 1 << 20)
        q = (1 << b) - 1
        if q > 2 + 4 * B and q % 257:
            break
    else:
        raise AssertionError("No admitted correctness envelope in bounded search")
    assert all(q > 2 + 4 * x for x in stages)
    frontier = []
    for prefix in range(ell + 1):
        tail = ell - prefix
        hints = 4 * ((length >> prefix) - 1) + 6 * ell - 2 * prefix
        for frontier_b in range(64, 1025):
            final, _, frontier_g = bounds(length, frontier_b, 1 << 20, 1 << 20, prefix=prefix)
            if (1 << frontier_b) - 1 > 2 + 4 * final and ((1 << frontier_b) - 1) % 257:
                break
        frontier.append({"prepared_prefix": prefix, "products": (1 << prefix) - 1 + ell - prefix,
                         "Hasse_maps": ell - prefix, "f_inputs": 1 << prefix, "g_inputs": ell,
                         "hint_coefficients_per_gm": hints, "correctness_only_b": frontier_b,
                         "paired_external_products_per_g": 2 * ((1 << prefix) - 1) + 2 * ((1 << tail) - 1) + 3 * tail,
                         "coefficient_decompositions_per_m": 2 * ((1 << prefix) - 1) + 4 * tail,
                         "correctness_only_g": frontier_g,
                         "hint_bits": hints * frontier_g * m * frontier_b})
    assert frontier[1]["hint_coefficients_per_gm"] == 554
    assert frontier[4]["hint_coefficients_per_gm"] == 100 and frontier[4]["products"] == 19
    assert frontier[4]["paired_external_products_per_g"] == 72
    assert frontier[4]["coefficient_decompositions_per_m"] == 46
    assert frontier[8]["hint_coefficients_per_gm"] == 32 and frontier[8]["products"] == 255
    assert sparse_L256 == [128, 256, 384, 448, 480, 496, 504, 508]
    conventional_calls = [(16 * x + 4095) // 4096 for x in sparse_L256]
    assert conventional_calls == [1, 1, 2, 2, 2, 2, 2, 2] and sum(conventional_calls) == 14
    print(json.dumps({"status": "PASS_PUBLIC_ALGEBRA_ONLY", "composition_cases": cases,
                      "translation_basis_columns": columns, "integral_transport_fixtures": identities,
                      "complete_tensor_phase_fixtures": tensor_cases,
                      "prepared_prefix_composition_cases": prefix_cases,
                      "sparse_conventional_cases": sparse_cases,
                      "L256_sparse_conventional_occupancy": sparse_L256,
                      "sixteen_job_conventional_calls_by_level": conventional_calls,
                      "L256_native_products": 8, "L256_Hasse_maps": 8,
                      "hint_coefficients_per_gm": inventory,
                      "correctness_only_profile": {"b": b, "g": gadget_digits,
                                                   "B_final": B, "q": q,
                                                   "hint_coefficients": inventory * gadget_digits * m},
                      "prepared_prefix_frontier": frontier,
                      "HE_execution": False, "security_qualification": False}, indent=2))


if __name__ == "__main__":
    main()
