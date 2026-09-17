"""Analytical prepared single-W0 adaptation of the accepted real-65537 control.

No HE, sampler, backend measurement, map regeneration, or security estimate.
Outputs are exclusive. Existing source/evidence files are read only.
"""
import argparse
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from math import gcd, log2
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parent
ROOT = RESEARCH.parents[1]
SLM = RESEARCH / 'structured-linear-maps-2026-09-13'
sys.path.insert(0, str(SLM / 'scripts'))
import real_subfield_complete_cost_v1 as compiler
import acyclic_reuse_bounds_v1 as reuse
from real_subfield_resources_v1 import liveness, first_unit

N = 32768
SOURCE = SLM / 'evidence/real-complete-v1/analysis-v1.json'
SEARCH = dict(q_bits='each integer from terminal recurrence floor to floor+512 inclusive',
              P_bits='sorted unique {128,196,floor(q_bits/4),floor(q_bits/2),q_bits}',
              ordinary_digits=[1, 2, 4, 8, 16], diagonal_digits=[2, 4, 8, 16],
              objective=['raw_public_bytes', 'public_row_evaluations', 'q_bits',
                         'P_bits', 'ordinary_digits', 'diagonal_digits'],
              scope='Finite grid minimum, not a global optimum; fixed before any timing.')


def sources():
    data = json.loads(SOURCE.read_text())
    old = next(r for r in data['records'] if r['conductor'] == 65537 and r['threshold'] == 32769)
    gp, sp, mp = (ROOT / old[k].replace('\\', '/') for k in
                  ('graph_path', 'map_summary_path', 'old_maps_path'))
    return old, json.loads(gp.read_text()), json.loads(sp.read_text()), mp, [SOURCE, gp, sp, mp]


def recipes(stage, kind, source, carriers):
    rows = [[] for _ in range(carriers)]
    for out, i, name in stage['templates'][kind]:
        rows[out].append([source, i, name])
    return rows


def graph(original):
    stages = original['stages']
    assert [s['j'] for s in stages] == list(range(7, -1, -1))
    ops = [dict(node='f', op='input', args=[], key=0, carriers=2)]
    for s in stages:
        ops.append(dict(node=f"inner:{s['j']}", op='input', args=[], key=0,
                        carriers=s['product_carriers']))
    ops.append(dict(node='odd:7', op='input', args=[], key=0, carriers=1))
    keys = {o['node']: 0 for o in ops}
    previous, key = 'f', 0
    for s in stages:
        j, count = s['j'], s['product_carriers']
        odd = f'odd:{j}'
        if j != 7:
            key += 1
            ops.append(dict(node=odd, op='linear', args=[previous], key=key,
                            carriers=count, recipes=recipes(s, 'outer', previous, count)))
            keys[odd] = key
        key += 1
        product = f'field:{j}'
        ops.append(dict(node=product, op='field_product', args=[odd, f'inner:{j}'],
                        key=key, carriers=count, source_keys=[keys[odd], 0]))
        keys[product] = key
        if j:
            key += 1
            rows = recipes(s, 'return', product, 2)
            for out, row in enumerate(recipes(s, 'bypass', previous, 2)):
                rows[out].extend(row)
            node = f'return:{j}'
            ops.append(dict(node=node, op='linear', args=[product, previous], key=key,
                            carriers=2, recipes=rows))
            keys[node] = key
            previous = node
    terminal = recipes(stages[-1], 'return', 'field:0', 2)
    for out, row in enumerate(recipes(stages[-1], 'bypass', previous, 2)):
        terminal[out].extend(row)
    return dict(program='prepared-single-W0-terminal-v1', conductor=65537, operations=ops,
                outputs=[dict(products='field:0', bypass=previous)], terminal_recipes=terminal,
                stages=deepcopy(stages), job_count=16, length=256, physical_slot_count=2048,
                physical_degree=N, slot_degree=16, owner_public_keys=1,
                policy='All 8 inner arrays and first outer odd prepared by owner; last return public after decryption.')


def signed_contract(G, summary, C):
    used = sorted({name for o in G['operations'] if o['op'] == 'linear'
                   for row in o['recipes'] for a, i, name in row})
    H = (7 * (180 + (2 * len(used) * N * N - 1).bit_length()) + 9) // 10
    gains = {}
    for name in used:
        d = summary[name]['diagonals']
        gain = min(2 * N * d, N * reuse.csqrt(8 * d * H))
        gains[name] = dict(diagonals=d, gain=gain, randomize=gain < 2 * N * d)
    for o in G['operations']:
        if o['op'] != 'linear':
            continue
        for out, recipe in enumerate(o['recipes']):
            terms = Counter()
            for a, i, name in recipe:
                terms[a, i] += gains[name]['gain']
            C[o['node']][out]['inputs'] = [[a, i, gain] for (a, i), gain in sorted(terms.items())]
            C[o['node']][out]['carry'] = (sum(terms.values()) + 1) // 2
    bits = sum(v['diagonals'] for v in gains.values() if v['randomize'])
    return dict(H=H, map_count=len(used), gains=gains, unbiased_bits=bits,
                stored_sign_bytes=(bits + 7) // 8, tail_union_bits=180,
                scope='Reused public signed-lift concentration lemma; randomized setup independent of error sources; no fixed sign vector certified.')


def terminal_floor(record, G, par):
    C, c1 = record['symbolic_contract'], record['geometry']['C1']
    values = {}
    for o in G['operations']:
        k, args = o['op'], o['args']
        if k == 'input':
            out = [par['fresh']] * o['carriers']
        elif k == 'linear':
            out = [sum(A * values[a][i] for a, i, A in row['inputs']) for row in C[o['node']]]
        elif k == 'field_product':
            out = [c1 * (a + b) for a, b in zip(values[args[0]], values[args[1]])]
        else:
            raise ValueError(k)
        values[o['node']] = out
    maximum = max(x for row in values.values() for x in row)
    lower = 4 * maximum + 2
    return dict(q_lower=lower, q_bits=lower.bit_length(), largest_node=maximum,
                scope='Necessary only for the selected sufficient recurrence, not actual HE noise or a compiler lower bound.')


def evaluate(record, G, loads, par, qb, pb, g, gd, keep=False):
    cap, C = record['geometry'], record['symbolic_contract']
    q, P = 1 << (qb - 1), 1 << (pb - 1)
    D = reuse.digits((1 << qb) - 1, g)
    Dd = reuse.digits(((1 << qb) - 1) * ((1 << pb) - 1), gd)
    factor = 2 * par['H'] * par['multiplier_variance_factor']
    K, U, V, c1 = (cap[k] for k in ('K', 'U', 'V', 'C1'))
    values, states = {}, []
    for o in G['operations']:
        kind, args = o['op'], o['args']
        if kind == 'input':
            out = [par['fresh']] * o['carriers']
        elif kind == 'linear':
            out = []
            for index, row in enumerate(C[o['node']]):
                variance = loads[o['node']][index]['masses']
                assert variance['trace'] == 0
                J = reuse.csqrt(factor * gd * Dd * Dd * variance['diagonal'])
                out.append(sum(A * values[a][i] for a, i, A in row['inputs']) + row['carry']
                           + (2 * J + (1 + U) * P) // (2 * P))
        elif kind == 'field_product':
            t = len(set(o['source_keys'])) + 1
            J = reuse.csqrt(factor * g * D * D * t)
            out = []
            for a, b in zip(values[args[0]], values[args[1]]):
                x, y = 2 * a + 1, 2 * b + 1
                out.append((q * P * (c1 * (x + y) + 3 + t * U + V)
                            + K * x * y * P + 2 * J * q) // (2 * q * P))
        else:
            raise ValueError(kind)
        if any(4 * v >= q - 1 for v in out):
            return dict(admitted=False, first_failure=o['node'])
        values[o['node']] = out
        if keep:
            states.append(dict(node=o['node'], bounds=out))
    result = dict(admitted=True, q_bits=qb, P_bits=pb, ordinary_digits=g, diagonal_digits=gd)
    if keep:
        result.update(bounds=states, terminal_ciphertext_bounds={node: values[node]
                      for output in G['outputs'] for node in output.values()})
    return result


def row_counts(inv, qb, pb, g, gd):
    rows = g * inv['ordinary_payload_families'] + gd * inv['modes']['diagonal']['payload_families']
    return dict(evaluation_rows=rows, primitive_rows=rows + 1,
                raw_public_bytes=2 * N * ((qb + 7) // 8 + rows * ((qb + pb + 7) // 8)),
                public_row_evaluations=g * inv['ordinary_switch_evaluations']
                + gd * inv['modes']['diagonal']['switch_evaluations'])


def search(record, G, loads, par):
    floor = terminal_floor(record, G, par)
    best, count, admitted, digest, per_q = None, 0, 0, sha256(), []
    inv = record['inventory']
    for qb in range(floor['q_bits'], floor['q_bits'] + 513):
        local = None
        for pb in sorted({128, 196, qb // 4, qb // 2, qb}):
            for g in SEARCH['ordinary_digits']:
                for gd in SEARCH['diagonal_digits']:
                    result = evaluate(record, G, loads, par, qb, pb, g, gd)
                    row = dict(q_bits=qb, P_bits=pb, ordinary_digits=g, diagonal_digits=gd)
                    row.update(result)
                    count += 1
                    if result['admitted']:
                        admitted += 1
                        row.update(row_counts(inv, qb, pb, g, gd))
                        score = tuple(row[k] for k in SEARCH['objective'])
                        if best is None or score < best[0]:
                            best = score, row
                        if local is None or score < local[0]:
                            local = score, row
                    digest.update(json.dumps(row, sort_keys=True, separators=(',', ':')).encode())
        if local:
            per_q.append(local[1])
    if best is None:
        raise AssertionError('No admitted policy in fixed finite grid')
    selected = best[1]
    selected.update(evaluate(record, G, loads, par, *(selected[k] for k in
                    ('q_bits', 'P_bits', 'ordinary_digits', 'diagonal_digits')), keep=True))
    return dict(domain=SEARCH, floor=floor, tested=count, admitted=admitted,
                decision_stream_sha256=digest.hexdigest(), best_per_q=per_q, selected=selected)


def resources(record, G, summary, selected, signs, par):
    inv, cap = record['inventory'], record['geometry']
    qb, pb, g, gd = (selected[k] for k in ('q_bits', 'P_bits', 'ordinary_digits', 'diagonal_digits'))
    qbytes, Mbytes = (qb + 7) // 8, (qb + pb + 7) // 8
    peak, counts = liveness(G)
    keys = {o['node']: o['key'] for o in G['operations']}
    banks = {(b['source_main_key'], b['target_main_key']): b for b in inv['banks']}
    masks, scratch, decompositions = set(), 0, 0
    for pos, o in enumerate(G['operations']):
        stage = 0
        if o['op'] == 'linear':
            for row in o['recipes']:
                for a, i, name in row:
                    masks.add((name, banks[keys[a], o['key']]['specification']['cut']))
            for b in inv['banks']:
                babies = sum(n for p, n in b['baby_uses'] if p == pos)
                giants = sum(n for p, out, n in b['giant_uses'] if p == pos)
                stage += (2 * babies + 2 * giants + babies * gd) * N * Mbytes
                decompositions += babies + giants
        scratch = max(scratch, stage)
    mask_count = sum(summary[name]['diagonals'] for name, cut in masks)
    vectors = selected['primitive_rows'] + inv['independent_secrets'] + 3 * inv['owner_ciphertexts']
    terminal_edges = sum(summary[name]['edges'] for row in G['terminal_recipes'] for a, i, name in row)
    owner_edges = sum(summary[name]['edges'] for s in G['stages'] for out, i, name in s['templates']['inner'])
    owner_edges += sum(summary[name]['edges'] for out, i, name in G['stages'][0]['templates']['outer'])
    products = inv['field_ciphertext_products']
    q, P = first_unit(qb, 65537), first_unit(pb, 65537)
    # A distinct-key tensor has 4 raw component products; the sole same-key
    # product can use 3 with one cross-term combination. Both are safe explicit schedules.
    raw_tensors = sum(o['carriers'] * (3 if len(set(o['source_keys'])) == 1 else 4)
                      for o in G['operations'] if o['op'] == 'field_product')
    errors = cap['per_ideal_secret_tail_log2_upper']
    union = 2.0 ** -180 + 2.0 ** -180 + vectors * 2.0 ** cap['source_distance_log2_upper']
    union += inv['independent_secrets'] * sum(2.0 ** v for v in errors.values())
    assert union < 2.0 ** -160
    return dict(
        root_public_keys=1, owner_ciphertexts=29, owner_gaussian_vectors=87,
        owner_input_bytes=29 * 2 * N * qbytes, terminal_output_ciphertexts=6,
        terminal_output_bytes=6 * 2 * N * qbytes,
        terminal_result_field_elements=4096, terminal_result_binary_bytes=8192,
        public_rows=dict(**row_counts(inv, qb, pb, g, gd), root_row_bytes=2 * N * qbytes,
                         evaluation_row_bytes=2 * N * Mbytes),
        sources=dict(vectors=vectors, secrets=inv['independent_secrets'],
                     row_errors=selected['primitive_rows'], fresh_encryption_vectors=87,
                     scalar_draws=vectors * N, uniform_bits=vectors * cap['random_bits_per_source'],
                     base_pass_weight_evaluations=vectors * N * cap['maximum_scalar_outcomes'],
                     precision_scope='Base pass only; adaptive CDF precision escalation and its arithmetic remain separately charged.'),
        public_uniform_rows=dict(coordinates=selected['primitive_rows'] * N,
                                 rejection_limit_per_coordinate=256,
                                 uniform_random_bits_upper=256 * N * (qb + selected['evaluation_rows'] * (qb + pb)),
                                 abort_probability_upper=selected['primitive_rows'] * N * 2.0 ** -256),
        correctness_failure_union_log2_upper=log2(union),
        correctness_scope='Fixed public program/owner data independent of protected bank errors; include signed-lift, Gaussian tails, secret event and finite-source coupling. No adaptive-key-visible correctness claim.',
        masks=dict(adjusted_map_cut_pairs=len(masks), diagonal_instances_upper=mask_count,
                   compact_binary_cache_bytes_upper=mask_count * N // 8,
                   expanded_modqP_cache_bytes_upper=mask_count * N * Mbytes,
                   sign_bytes=signs['stored_sign_bytes'],
                   scope='Cache alternatives, not simultaneously required; no equality dedup inferred from support.'),
        liveness=dict(graph_ciphertext_peak=peak, count_at_each_node=counts,
                      graph_payload_bytes_upper=peak * 2 * N * qbytes,
                      materialize_all_linear_workspace_bytes_upper=scratch,
                      scope='Logical graph values plus separate sufficient overallocated linear workspace; no RSS or backend scratch estimate.'),
        operations=dict(owner_ring_products_q=58,
                        setup_row_mask_ring_products=selected['primitive_rows'],
                        setup_ordinary_product_payload_ring_products=8,
                        setup_automorphism_payloads=inv['modes']['diagonal']['payload_families'],
                        online_field_ciphertext_products=products,
                        online_raw_tensor_component_ring_products=raw_tensors,
                        online_switch_row_component_ring_products=2 * selected['public_row_evaluations'],
                        online_mask_component_ring_products=2 * inv['ciphertext_by_plaintext_products'],
                        online_switch_calls=inv['ordinary_switch_evaluations'] + inv['modes']['diagonal']['switch_evaluations'],
                        online_linear_decompositions_allocate_all=decompositions,
                        owner_sparse_map_field_multiplications_upper=owner_edges,
                        owner_sparse_map_field_additions_upper=owner_edges,
                        terminal_sparse_map_field_multiplications_upper=terminal_edges,
                        terminal_sparse_map_field_additions_upper=terminal_edges,
                        public_owner_encodes=29, terminal_public_decodes=6,
                        transform_scope='Counts are ring-operation/kernel calls, not NTT counts. No implemented real-period receiver transform exists; charge C_mul(N,b), C_decomp(N,b,g), C_encode and C_decode with their actual modulus. Tensor products require the exact integer/scaled product kernel, not fieldwise or mod-q multiplication.'),
        moduli=dict(example_q=q, example_P=P, coprime_to_2m=gcd(q * P, 2 * 65537) == 1,
                    scope='Explicit odd integers inside sufficient intervals, not backend-selected primes or security-qualified parameters.'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.parent != HERE or not output.name.startswith('prepared_w0_'):
        parser.error('output must be a prepared_w0_* file in the isolated revision folder')
    if output.exists():
        parser.error('output already exists')
    old, original, summary, maps, paths = sources()
    paths += [Path(__file__), SLM / 'scripts/real_subfield_complete_cost_v1.py',
              SLM / 'scripts/acyclic_reuse_bounds_v1.py', SLM / 'scripts/real_subfield_resources_v1.py',
              SLM / 'scripts/joint_inner_cache_and_placement_v1.py',
              SLM / 'comparison/REAL_COMPLETE_CONTROL_V1.md']
    before = {p.relative_to(ROOT).as_posix(): compiler.bind(p) for p in paths}
    G = graph(original)
    C, inv = compiler.compile_graph(G, summary, 32769)
    assert inv['owner_ciphertexts'] == 29 and inv['output_ciphertexts'] == 6
    assert inv['field_ciphertext_products'] == 26
    assert inv['ordinary_payload_families'] == 23 and inv['ordinary_switch_evaluations'] == 77
    assert inv['independent_secrets'] == 44 and len(inv['banks']) == 21
    assert inv['modes']['trace']['payload_families'] == 0
    signed = signed_contract(G, summary, C)
    rec = dict(geometry=compiler.geometry(False), inventory=inv,
               symbolic_contract=C, threshold=32769)
    loads, dependencies = reuse.contract(rec, G, summary)
    par = reuse.parameters(rec, G)
    print(json.dumps(dict(stage='search', graph_nodes=len(G['operations']),
                          ordinary_families=23, map_families=inv['modes']['diagonal']['payload_families'])), flush=True)
    result = search(rec, G, loads, par)
    costs = resources(rec, G, summary, result['selected'], signed, par)
    after = {p.relative_to(ROOT).as_posix(): compiler.bind(p) for p in paths}
    assert before == after
    used = {name for o in G['operations'] if o['op'] == 'linear' for row in o['recipes'] for a, i, name in row}
    result = dict(status='ANALYTICAL_PREPARED_W0_CONTROL_COMPUTED', graph=G, **rec,
                  parameters=par, signed_lifts=signed, variance_loads=loads,
                  no_self_dependency_checks=dependencies, search=result, resources=costs,
                  used_encrypted_map_names=sorted(used),
                  minimum_direct_route_patch=dict(affected_maps=['product-2', 'product-3'],
                      intersection_with_this_program=sorted(used & {'product-2', 'product-3'}), applicable=False),
                  bindings_before=before, bindings_after=after,
                  scope=['Analytical single prepared W0, terminal full4096 coefficient output.',
                         'No fresh HE, source sampling, security qualification, receiver backend or timing.',
                         'No final encrypted return, q0 copy or continued-workload cost is imposed.',
                         'Terminal plaintext product and bypass values are visible to the secret-key recipient.'])
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, separators=(',', ':'))
    print(json.dumps(dict(status=result['status'], output=output.name,
                          selected={k: v for k, v in result['search']['selected'].items()
                                    if k not in ('bounds', 'terminal_ciphertext_bounds')},
                          resources=costs)), flush=True)


if __name__ == '__main__':
    main()
