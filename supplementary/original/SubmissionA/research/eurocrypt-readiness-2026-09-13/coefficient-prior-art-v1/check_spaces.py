"""Exact public function-space checks; no HE, timing comparison or security test."""
from pathlib import Path
from hashlib import sha256
from time import perf_counter
import importlib.util
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
IMPORTED = ROOT / 'fixed-field-count-audit-v1/boolean_screen.py'
spec = importlib.util.spec_from_file_location('coefficient_boolean', IMPORTED)
boolean = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boolean)


def zmul(a, b, length):
    result = 0
    while b:
        bit = b & -b
        result ^= a << (bit.bit_length()-1)
        b ^= bit
    return result & ((1 << length)-1)


def root_extend(poly, root, length):
    result = [0] * (len(poly)+1)
    for i, coefficient in enumerate(poly):
        result[i] ^= zmul(coefficient, root, length)
        result[i+1] ^= coefficient
    return result


def evaluate(poly, g, length):
    value = 0
    for coefficient in reversed(poly):
        value = zmul(value, g, length) ^ coefficient
    return value


def symbolic(poly, powers, length):
    result = [set() for _ in range(length)]
    for i, coefficient in enumerate(poly):
        while coefficient:
            low = coefficient & -coefficient
            shift = low.bit_length()-1
            for j in range(length-shift):
                result[j+shift].symmetric_difference_update(powers[i][j])
            coefficient ^= low
    return result


def flatten_shift(coords, shift, length):
    return {(j+shift, mask) for j in range(length-shift) for mask in coords[j]}


def truth(length, powers, expected_ring, expected_scalar, newton):
    assignments = 1 << (length-1)
    values = [[0]*assignments for _ in range(length)]
    coefficient_checks = 0
    for a in range(assignments):
        g = a << 1
        value = 1
        for i in range(length):
            values[i][a] = value
            for j in range(length):
                actual = sum((a & mask) == mask for mask in powers[i][j]) & 1
                assert actual == (value >> j) & 1, ('truth', length, a, i, j)
                coefficient_checks += 1
            value = zmul(value, g, length)
    ring_vectors, scalar_vectors = [], []
    limit = (1 << length)-1
    for i in range(1, length):
        for shift in range(length):
            ring_vectors.append(sum(((v << shift) & limit) << (a*length)
                                    for a, v in enumerate(values[i])))
        for j in range(1, length):
            scalar_vectors.append(sum(((v >> j) & 1) << a
                                      for a, v in enumerate(values[i])))
    assert boolean.binary_rank(ring_vectors) == expected_ring
    assert boolean.binary_rank(scalar_vectors) == expected_scalar
    valuation_checks = 0
    for i, nu, poly in newton:
        for a in range(assignments):
            v = evaluate(poly, a << 1, length)
            assert not (v & ((1 << min(nu, length))-1))
            valuation_checks += 1
        if nu < length:
            v = evaluate(poly, i << 1, length)
            assert (v & -v).bit_length()-1 == nu
    return dict(assignments=assignments, coefficient_values=coefficient_checks,
                valuation_values=valuation_checks, ring_rank=expected_ring,
                scalar_rank=expected_scalar)


def case(length):
    powers, occurrences = boolean.powers(length)
    scalar_rows = [row for group in powers[1:] for row in group[1:]]
    scalar_rank = boolean.rank(scalar_rows)
    ring_rows = [flatten_shift(group, shift, length)
                 for group in powers[1:] for shift in range(length)]
    ring_rank = boolean.rank(ring_rows)
    projected = [{mask for j, mask in row if j == length-1} for row in ring_rows]
    assert boolean.rank(projected) == scalar_rank
    assert ring_rank <= (length-1)*scalar_rank and scalar_rank <= ring_rank
    nu = lambda i: 2*i-i.bit_count()
    dimension = sum(max(0, length-nu(i)) for i in range(1, length+1))
    assert dimension == ring_rank, ('centered Newton count', length)
    poly, newton, basis = [1], [], []
    for i in range(1, length+1):
        poly = root_extend(poly, (i-1) << 1, length)
        newton.append((i, nu(i), poly))
        if nu(i) >= length:
            # The monic null polynomial is below degree L except at L=2.
            if i < length:
                assert all(not row for row in symbolic(poly, powers, length))
            break
        coords = symbolic(poly, powers, length)
        assert all(not row for row in coords[:nu(i)])
        for shift in range(length-nu(i)):
            basis.append(flatten_shift(coords, shift, length))
    assert len(basis) == dimension
    assert boolean.rank(basis) == dimension
    assert boolean.rank(ring_rows+basis) == dimension
    detail = truth(length, powers, ring_rank, scalar_rank, newton) if length <= 8 else None
    if length >= 4 and length % 2 == 0:
        square = powers[2]
        assert not square[length-1] and any(square)
        shifted = flatten_shift(square, length-3, length)
        assert {mask for j, mask in shifted if j == length-1} == {1}
    return dict(length=length, centered_ring_dimension=ring_rank,
                scalar_dimension=scalar_rank, projection_kernel_dimension=ring_rank-scalar_rank,
                newton_basis_functions=len(basis), monic_null_degree=newton[-1][0],
                symbolic_occurrences=occurrences, exhaustive=detail)


def family_difference():
    length = 16
    e2 = [1]
    for root in (0, 2, 4, 6):
        e2 = root_extend(e2, root, length)
    t2 = [0, 2, 1]
    t3 = [0]*5
    for i, c in enumerate(t2):
        t3[2*i] ^= zmul(c, c, length)
        t3[i] ^= c << 3
    assert e2 == [0, (1 << 4) | (1 << 5), (1 << 2) | (1 << 3) | (1 << 4), 0, 1]
    assert t3 == [0, 1 << 4, (1 << 2) | (1 << 3), 0, 1]
    assert evaluate(e2, 4, length) == 0
    assert evaluate(t3, 4, length) == (1 << 7) | (1 << 8)
    return dict(length=length, E2=e2, T3=t3, input=4, E2_output=0, T3_output=384)


def main():
    target = HERE/'check.json'
    assert not target.exists(), 'Preserve an earlier run; no overwrite'
    started = perf_counter()
    sources = [HERE/'PLAN.md', HERE/'PROOF.md', Path(__file__).resolve(), IMPORTED,
               ROOT/'checkpoint-v37/manuscript/appendices/fixed-field-carrier-bound.tex']
    bindings = {}
    for path in sources:
        raw = path.read_bytes()
        bindings[path.relative_to(ROOT).as_posix()] = dict(bytes=len(raw), sha256=sha256(raw).hexdigest())
    rows = []
    for length in (2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 24, 32):
        row = case(length)
        rows.append(row)
        print(json.dumps(row), flush=True)
    record = dict(status='COEFFICIENT_PROJECTION_CHECK_PASS', results=rows,
                  family_difference=family_difference(), source_bindings=bindings,
                  wall_seconds=perf_counter()-started, new_he_execution=False,
                  new_security_execution=False, exact_general_scalar_rank_proved=False,
                  novelty_established=False)
    target.write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'status':record['status'], 'wall_seconds':record['wall_seconds']}), flush=True)


if __name__ == '__main__':
    main()
