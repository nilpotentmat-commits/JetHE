"""Recompute public finite algebra and bind records; never rerun HE or estimators."""
from pathlib import Path
from hashlib import sha256
import json
import random
import boolean_screen as boolean
import check_additive_witness as additive

HERE = Path(__file__).resolve().parent


def read(name):
    return json.loads((HERE/name).read_text(encoding='utf-8'))


def main():
    recorded = read('additive-witness-check.json')
    assert recorded['status'] == 'FIXED_FIELD_ADDITIVE_WITNESS_CHECK_PASS'
    for name, digest in recorded['source_hashes_before_execution'].items():
        assert sha256((HERE/name).read_bytes()).hexdigest() == digest, name
    # These diagnostic scripts were originally inline. This reproduces their
    # mathematical outputs, without claiming this reader was their executed source.
    degree_rows = []
    pivot_rows = []
    boolean_rows = []
    for length in (2, 4, 8, 16, 32, 64):
        powers, terms = boolean.powers(length)
        nonzero = [row for group in powers[1:] for row in group[1:] if row]
        dimension = boolean.rank(nonzero)
        table = None
        if length <= 8:
            tr, checks = boolean.truth_table_check(length, powers)
            assert tr == dimension
            table = dict(rank=tr, coefficient_values=checks)
        boolean_rows.append(dict(length=length, nonzero_rows=len(nonzero),
                                 dimension=dimension, large_field_dimension=(length*length-1)//3,
                                 symbolic_occurrences=terms, truth_table=table))
        if length < 8:
            continue
        degree_rows.append(dict(length=length, rank_by_monomial_degree={
            str(degree): boolean.rank({mask for mask in row if mask.bit_count() <= degree}
                                     for row in nonzero)
            for degree in range(1, 7)}))
        basis = {}
        accepted = {}
        for i in range(1, length, 2):
            for j in range(1, length):
                value = set(powers[i][j])
                while value:
                    pivot = max(value)
                    if pivot in basis:
                        value.symmetric_difference_update(basis[pivot])
                    else:
                        basis[pivot] = value
                        accepted.setdefault(str(i), []).append(j)
                        break
        proposed = [powers[1][j] for j in range(1, length)]
        proposed += [powers[i][j] for i in range(3, length//2, 2)
                     for j in range(2*i-2, length)]
        pivot_rows.append(dict(L=length, rank=len(basis),
                               proposed_subfamily_rank=boolean.rank(proposed),
                               proposed_subfamily_rows=len(proposed), accepted=accepted))
        if length == 16:
            # Explicit retained failure of the j>=2i-2 candidate.
            assert powers[5][8] == powers[3][6] ^ powers[1][2]
    assert boolean_rows == read('boolean-screen.json')['results']
    assert degree_rows == read('degree-screen.json')['results']
    assert pivot_rows == read('pivot-screen.json')
    symbolic = [additive.symbolic_check(length) for length in (8, 16, 32, 64)]
    assert symbolic == recorded['symbolic']
    randomizer = random.Random(20260914)
    points = [additive.point_checks(8, [a << 1 for a in range(1 << 7)])]
    for length in (16, 32, 64, 128, 256):
        assignments = [0, 2, (1 << length)-2]
        assignments += [randomizer.getrandbits(length-1) << 1 for _ in range(16)]
        points.append(additive.point_checks(length, assignments))
    assert points == recorded['point_checks']
    counts = additive.count_table()
    assert counts == recorded['count_table']
    assert sum(row['derivative_checks'] for row in points) == 3918
    assert [(r['L'],r['proposed_subfamily_rank'],r['proposed_subfamily_rows'])
            for r in pivot_rows] == [(8,11,11),(16,38,39),(32,140,143),(64,534,543)]
    assert [r['d'] for r in counts if r['old_binary_linear_applies']] == [8]
    assert [r['d'] for r in counts if r['old_field_linear_applies']] == list(range(8,17))
    first = next(r for r in counts if r['fixed_field_calls_lower_bound'] > r['native_products']
                 and r['fixed_field_inputs_lower_bound'] > r['native_inputs'])
    assert first['d'] == 28
    names = ['PLAN.md', 'PROOF.md', 'RESULTS.md', 'REPRODUCE.md', 'SOURCES.md',
             'boolean_screen.py', 'check_additive_witness.py', Path(__file__).name,
             'boolean-screen.json', 'degree-screen.json', 'pivot-screen.json',
             'additive-witness-check.json', 'execution.json']
    bindings = {name: dict(bytes=(HERE/name).stat().st_size,
                           sha256=sha256((HERE/name).read_bytes()).hexdigest()) for name in names}
    result = dict(status='FIXED_FIELD_PUBLIC_ALGEBRA_READBACK_PASS', files=bindings,
                  symbolic_witness_dimensions=[r['independent_functions'] for r in symbolic],
                  boolean_ranks=[r['dimension'] for r in boolean_rows],
                  derivative_checks=3918, schedule_points=len(counts),
                  first_inspected_strict_count_tradeoff=first,
                  failed_candidate_preserved=True, original_pivot_outer_exit_known=False,
                  new_he_execution=False, new_estimator_execution=False, new_attack_method=False,
                  exact_asymptotic_rank_claimed=False, total_runtime_separation_claimed=False,
                  security_bits=None)
    (HERE/'verification.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('files','first_inspected_strict_count_tradeoff')}))


if __name__ == '__main__':
    main()
