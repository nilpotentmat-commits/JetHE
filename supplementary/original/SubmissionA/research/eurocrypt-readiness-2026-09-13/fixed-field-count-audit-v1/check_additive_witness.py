"""Independent public algebra checks for PROOF.md; no HE or security experiment."""
from pathlib import Path
from time import perf_counter
from hashlib import sha256
import argparse
import json
import random
import boolean_screen as boolean

HERE = Path(__file__).resolve().parent


def zmul(a, b, length):
    result = 0
    while b:
        low = b & -b
        result ^= a << (low.bit_length() - 1)
        b ^= low
    return result & ((1 << length) - 1)


def ymul(a, b, length):
    result = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[i+j] ^= zmul(x, y, length)
    return result


def yeval(polynomial, value, length):
    result = 0
    for coefficient in reversed(polynomial):
        result = zmul(result, value, length) ^ coefficient
    return result


def additive_polynomials(max_r, length):
    direct = []
    recursive = [0, 1]
    for r in range(max_r + 1):
        product = [1]
        for root in range(1 << r):
            product = ymul(product, [root << 1, 1], length)
        assert product == recursive, ('root-product/recurrence', r, length)
        assert len(product) == (1 << r) + 1 and product[0] == 0
        assert all(i & (i-1) == 0 for i, c in enumerate(product) if c)
        direct.append(product)
        if r < max_r:
            factor = yeval(recursive, 1 << (r+1), length)
            square = ymul(recursive, recursive, length)
            for i, coefficient in enumerate(recursive):
                square[i] ^= zmul(coefficient, factor, length)
            recursive = square
    return direct


def symbolic_evaluate(polynomial, powers, length):
    result = [set() for _ in range(length)]
    for i, coefficient in enumerate(polynomial):
        while coefficient:
            low = coefficient & -coefficient
            shift = low.bit_length()-1
            for j in range(length-shift):
                result[j+shift].symmetric_difference_update(powers[i][j])
            coefficient ^= low
    return result


def witness_polynomials(length):
    d = length.bit_length()-1
    assert length == 1 << d and d >= 3
    rmax = d-3
    base = 1 << rmax
    additive = additive_polynomials(rmax, length)
    witnesses = []
    for i in range(base, 2*base):
        product = [1]
        for r in range(rmax+1):
            if (i >> r) & 1:
                product = ymul(product, additive[r], length)
        assert len(product) == i+1 and product[0] == 0
        witnesses.append((i, 2*i-i.bit_count(), product))
    return rmax, witnesses


def symbolic_check(length):
    powers, terms = boolean.powers(length)
    rmax, witnesses = witness_polynomials(length)
    selected = []
    triangular = 0
    for i, valuation, polynomial in witnesses:
        values = symbolic_evaluate(polynomial, powers, length)
        assert all(not row for row in values[:valuation])
        lower_marker = sum(1 << r for r in range(rmax) if (i >> r) & 1)
        for j, row in enumerate(values[valuation:]):
            highest_bit = 1 << (rmax+j)
            assert highest_bit < 1 << (length-1)
            assert all(mask < highest_bit << 1 for mask in row)
            assert {mask for mask in row if mask & highest_bit} == {highest_bit | lower_marker}
            selected.append(row)
            triangular += 1
    predicted = (5*length*length + 4*(length.bit_length())*length)//64
    assert triangular == predicted
    assert boolean.rank(selected) == predicted
    # Membership is explicit: each selected row was formed only by fixed
    # z-polynomial combinations of the original coefficient functions.
    original_rank = boolean.rank(row for group in powers[1:] for row in group[1:])
    assert predicted <= original_rank
    return dict(length=length, independent_functions=predicted,
                full_boolean_rank=original_rank, symbolic_occurrences=terms)


def point_checks(length, assignments):
    rmax, witnesses = witness_polynomials(length)
    checks = 0
    for g in assignments:
        assert g & 1 == 0 and g.bit_length() <= length
        for i, valuation, polynomial in witnesses:
            value = yeval(polynomial, g, length)
            assert value & ((1 << valuation)-1) == 0
            for j in (0, (length-valuation-1)//2, length-valuation-1):
                v = rmax+1+j
                changed = yeval(polynomial, g ^ (1 << v), length)
                derivative = ((value ^ changed) >> (valuation+j)) & 1
                marker = 1
                for r in range(rmax):
                    if (i >> r) & 1:
                        marker &= (g >> (r+1)) & 1
                assert derivative == marker, ('highest-variable derivative', length, i, j)
                checks += 1
    return dict(length=length, assignments=len(assignments), derivative_checks=checks)


def balanced_k(d):
    # 2^k >= 2^(d/2)*(d+1), squared to avoid floating-point decisions.
    return next(k for k in range(d+1) if (1 << (2*k)) >= (1 << d)*(d+1)**2) if (1 << d) >= (d+1)**2 else d


def count_table():
    rows = []
    for d in range(8, 65):
        length = 1 << d
        k = balanced_k(d)
        tau = d-k
        dimension = (5*length*length + 4*(d+1)*length)//64
        calls = (dimension+32*length-1)//(32*length)
        inputs = (dimension+16*length-1)//(16*length)+1
        row = dict(d=d, length=length, k=k, tau=tau,
                   native_products=(1 << k)-1+tau,
                   native_inputs=(1 << (k+1))-1+tau,
                   native_depth=tau+1,
                   old_field_linear_applies=length <= 65536,
                   old_binary_linear_applies=length*length <= 65536,
                   boolean_dimension_lower_bound=dimension,
                   fixed_field_calls_lower_bound=calls,
                   fixed_field_inputs_lower_bound=inputs)
        rows.append(row)
    assert rows[0]['k'] == 8 and rows[0]['native_products'] == 255
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    assert not args.output.exists(), 'Preserve the previous execution'
    started = perf_counter()
    sources = {name: sha256((HERE/name).read_bytes()).hexdigest()
               for name in ('PROOF.md', 'boolean_screen.py', Path(__file__).name)}
    symbolic = []
    for length in (8, 16, 32, 64):
        row = symbolic_check(length)
        symbolic.append(row)
        print(json.dumps(row), flush=True)
    randomizer = random.Random(20260914)
    points = [point_checks(8, [a << 1 for a in range(1 << 7)])]
    for length in (16, 32, 64, 128, 256):
        assignments = [0, 2, (1 << length)-2]
        assignments += [randomizer.getrandbits(length-1) << 1 for _ in range(16)]
        points.append(point_checks(length, assignments))
        print(json.dumps(points[-1]), flush=True)
    record = dict(status='FIXED_FIELD_ADDITIVE_WITNESS_CHECK_PASS',
                  source_hashes_before_execution=sources,
                  symbolic=symbolic, point_checks=points, count_table=count_table(),
                  elapsed_seconds=perf_counter()-started, new_he_execution=False,
                  new_security_attack=False, security_bits=None,
                  scope='Finite public verification supporting the general proof; no rank extrapolation or latency inference.')
    for name, digest in sources.items():
        assert sha256((HERE/name).read_bytes()).hexdigest() == digest
    args.output.write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in record.items() if k not in ('count_table', 'source_hashes_before_execution')}))


if __name__ == '__main__':
    main()
