"""Public algebra/layout checks, NOT HE execution, timing or security evidence.

Bernstein's characteristic-two recursion is checked against independent Horner
composition. A second evaluator uses explicitly batched evaluation/interpolation
maps with one slotwise-product layer per precision level. Private-input circuit
schedules depend only on public lengths, never on observed coefficient zeros.
"""

from functools import lru_cache
import json
from random import Random

from check_frobenius_compiler import Field


def mul(a, b, n, field):
    out = [0] * n
    for i, x in enumerate(a[:n]):
        for j, y in enumerate(b[:n - i]):
            out[i + j] ^= field.mul(x, y)
    return out


def compose(f, g, n, field):
    out = [0] * n
    for coefficient in reversed(f):
        out = mul(out, g, n, field)
        out[0] ^= coefficient
    return out


def value(f, x, field):
    out = 0
    for coefficient in reversed(f):
        out = field.mul(out, x) ^ coefficient
    return out


def power(x, exponent, field):
    out = 1
    while exponent:
        if exponent & 1:
            out = field.mul(out, x)
        exponent >>= 1
        x = field.mul(x, x)
    return out


@lru_cache(None)
def interpolation_basis(size, field):
    """Public Lagrange matrix, independent of either private input."""
    assert size <= 1 << field.d
    points = list(range(size))
    polynomial = [1]
    for x in points:
        polynomial = mul(polynomial, [x, 1], len(polynomial) + 1, field)
    basis = []
    for x in points:
        quotient = [0] * size
        quotient[-1] = polynomial[-1]
        for i in range(size - 2, -1, -1):
            quotient[i] = polynomial[i + 1] ^ field.mul(x, quotient[i + 1])
        assert polynomial[0] ^ field.mul(x, quotient[0]) == 0
        denominator = value(quotient, x, field)
        assert denominator
        inverse = power(denominator, (1 << field.d) - 2, field)
        assert field.mul(denominator, inverse) == 1
        basis.append(tuple(field.mul(c, inverse) for c in quotient))
    return tuple(basis)


def interpolate(values, n, field):
    out = [0] * n
    for v, basis in zip(values, interpolation_basis(len(values), field)):
        for i in range(n):
            out[i] ^= field.mul(v, basis[i])
    return out


def prepared_inner(g, field):
    states = [list(g)]
    while len(states[-1]) > 2:
        old = states[-1]
        states.append([field.mul(c, c) for c in old[:len(old) // 2]])
    return states


def bottom_up(f, g, field, packed=False, check_nodes=False):
    length = len(f)
    assert len(g) == length and length >= 2 and length & (length - 1) == 0
    assert g[0] == 0
    states = prepared_inner(g, field)
    children = [[c] for c in f]
    receipt = []
    for j in reversed(range(len(states))):
        inner = states[j]
        n, r = len(inner), 1 << j
        assert len(children) == 2 * r
        parents = []
        left_slots, right_slots = [], []
        if packed:
            points = list(range(2 * n - 1))
            inner_values = [value(inner, x, field) for x in points]
            for t in range(r):
                odd = children[t + r]
                # U_j: evaluation of odd child at x^2; a PUBLIC linear map.
                left_slots.extend(value(odd, field.mul(x, x), field) for x in points)
                right_slots.extend(inner_values)
            assert len(left_slots) == 2 * length - r
            # The sole nonlinear packed layer at this level.
            products = [field.mul(a, b) for a, b in zip(left_slots, right_slots)]
        for t in range(r):
            even = [0] * n
            for i, c in enumerate(children[t]):
                even[2 * i] = c
            if packed:
                start = t * (2 * n - 1)
                product = interpolate(products[start:start + 2 * n - 1], n, field)
            else:
                odd = [0] * n
                for i, c in enumerate(children[t + r]):
                    odd[2 * i] = c
                product = mul(inner, odd, n, field)
            parent = [a ^ b for a, b in zip(even, product)]
            if check_nodes:
                assert parent == compose(f[t::r], inner, n, field)
            parents.append(parent)
        children = parents
        receipt.append({"depth_j": j, "precision": n, "branches": r,
                        "coefficient_slots": r * n,
                        "product_slots": r * (2 * n - 1),
                        "private_product_layers": 1})
    return children[0], receipt


def recover_prefix(h, g, field):
    """Recipient-local triangular recovery, permitted only when it knows g."""
    length = len(g)
    valuation = next((i for i in range(1, length) if g[i]), length)
    count = (length + valuation - 1) // valuation
    residual = list(h)
    monomial = [1] + [0] * (length - 1)
    answer = []
    for i in range(count):
        leading = i * valuation
        denominator = monomial[leading]
        assert denominator
        coefficient = field.mul(residual[leading],
                                power(denominator, (1 << field.d) - 2, field))
        answer.append(coefficient)
        residual = [a ^ field.mul(coefficient, b) for a, b in zip(residual, monomial)]
        monomial = mul(monomial, g, length, field)
    assert residual == [0] * length
    return answer


def main():
    rng = Random(20260908)
    cases = 0
    profiles = []
    # Degree certificates are checked by the reused Field constructor.
    for degree, modulus, lengths, repetitions in (
            (1, 0b11, (2, 4, 8), 8),
            (4, 0b10011, (2, 4, 8), 8),
            (16, 0x1100B, (2, 4, 8, 16, 32, 64, 256), 1)):
        field = Field(degree, modulus)
        for length in lengths:
            for trial in range(repetitions):
                f = [rng.randrange(1 << degree) for _ in range(length)]
                g = [0] + [rng.randrange(1 << degree) for _ in range(length - 1)]
                if trial == 0 and length <= 8:
                    g = [0] * length  # zero/high-valuation inputs cannot prune schedule
                expected = compose(f, g, length, field)
                got, receipt = bottom_up(f, g, field, check_nodes=length <= 16)
                assert got == expected
                prefix = recover_prefix(expected, g, field)
                assert prefix == f[:len(prefix)]
                assert sum(x["branches"] for x in receipt) == length - 1
                assert len(receipt) == (length.bit_length() - 1)
                if 2 * length - 1 <= 1 << degree:
                    batched, packed_receipt = bottom_up(f, g, field, packed=True)
                    assert batched == expected and packed_receipt == receipt
                    if length == 256:
                        profiles = packed_receipt
                cases += 1
    # Exact terminal-leakage collisions, with known valuation two.
    field = Field(4, 0b10011)
    g = [0, 0, 3, 4, 0, 7, 0, 1]
    f = list(range(8))
    changed = f[:4] + [c ^ 9 for c in f[4:]]
    assert compose(f, g, 8, field) == compose(changed, g, 8, field)
    assert recover_prefix(compose(f, g, 8, field), g, field) == f[:4]
    # Deterministic input-independent occupancy and capacity arithmetic.
    assert [p["product_slots"] for p in profiles] == [384, 448, 480, 496, 504, 508, 510, 511]
    assert sum(p["product_slots"] for p in profiles) == 3841
    assert 4096 // 511 == 8 and 4096 // 256 == 16
    print(json.dumps({"status": "PASS_PUBLIC_ALGEBRA_ONLY", "composition_cases": cases,
                      "L256_levels": profiles, "L256_slot_products": 3841,
                      "F65536_interpolation_points_needed": 511,
                      "HE_execution": False, "security_qualification": False}, indent=2))


if __name__ == "__main__":
    main()
