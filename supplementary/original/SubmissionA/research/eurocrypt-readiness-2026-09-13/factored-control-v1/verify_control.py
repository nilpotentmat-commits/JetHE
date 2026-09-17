"""Rebuild public graphs, independently check selected rational bounds, cost.

The exhaustive grid is recorded by compile_control.py; this does not replay it.
"""
from fractions import Fraction
from hashlib import sha256
import json
from math import isqrt, log2
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import compile_control as trial

HERE, ROOT, N = trial.HERE, trial.ROOT, 32768


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def ceil_sqrt(x):
    x = Fraction(x)
    a = isqrt(x.numerator // x.denominator)
    return a + int(a*a < x)


def digit_bound(modulus, count):
    if count==1:
        return (modulus-1)//2
    b = (modulus.bit_length()+count-1)//count
    while True:
        radix = 2**b
        covered = sum((radix//2-1)*radix**j for j in range(count))
        if covered >= modulus//2:
            return radix//2
        b += 1


def rational_bounds(row):
    chosen = row['search']['selected']
    qb, pb, g, gd = (chosen[k] for k in ('q_bits','P_bits','ordinary_digits','diagonal_digits'))
    q, P = 2**(qb-1), 2**(pb-1)
    D, Dd = digit_bound(2**qb-1, g), digit_bound((2**qb-1)*(2**pb-1), gd)
    cap, C, par = row['record']['geometry'], row['record']['symbolic_contract'], row['source_parameters']
    factor = 2*par['H']*par['multiplier_variance_factor']
    expected = {x['node']:x['bounds'] for x in chosen['bounds']}
    values, checked, margin = {}, 0, q
    for op in row['graph']['operations']:
        if op['op']=='input':
            bounds = [par['fresh']]*op['carriers']
        elif op['op']=='linear':
            bounds = []
            for i, contract in enumerate(C[op['node']]):
                mass = row['linear_variance_contract'][op['node']][i]['masses']
                assert mass['trace']==0
                J = ceil_sqrt(factor*gd*Dd**2*mass['diagonal'])
                expr = sum(A*values[a][k] for a,k,A in contract['inputs'])+contract['carry']
                expr += Fraction(J,P)+Fraction(1+cap['U'],2)
                bounds.append(expr.numerator//expr.denominator)
        else:
            assert op['op']=='field_product'
            t = len(set(op['source_keys']))+1
            J = ceil_sqrt(factor*g*D**2*t)
            bounds = []
            a, b = (values[x] for x in op['args'])
            for x,y in zip(a,b):
                expr = Fraction(cap['C1']*(2*x+2*y+2)+3+t*cap['U']+cap['V'],2)
                expr += Fraction(cap['K']*(2*x+1)*(2*y+1),2*q)+Fraction(J,P)
                bounds.append(expr.numerator//expr.denominator)
        assert bounds==expected[op['node']], op['node']
        assert all(4*b < q-1 for b in bounds)
        margin = min(margin, *(q-1-4*b for b in bounds))
        checked += len(bounds)
        values[op['node']] = bounds
    assert chosen['terminal_ciphertext_bounds']=={
        node:values[node] for output in row['graph']['outputs'] for node in output.values()}
    return dict(exact_state_bounds=checked, minimum_strict_margin=str(margin),
                selected_rational_recurrence_pass=True)


def costs(row):
    inv, graph, cap = row['record']['inventory'], row['graph'], row['record']['geometry']
    chosen = row['search']['selected']
    qb, pb, g, gd = (chosen[k] for k in ('q_bits','P_bits','ordinary_digits','diagonal_digits'))
    owner, outputs = inv['owner_ciphertexts'], inv['output_ciphertexts']
    secrets, rows = inv['independent_secrets'], chosen['primitive_rows']
    setup_sources, fresh_sources = secrets+rows, 3*owner
    sources = setup_sources+fresh_sources
    qbytes, Mbytes = (qb+7)//8, (qb+pb+7)//8
    raw = 2*N*(qbytes+(rows-1)*Mbytes)
    assert raw==chosen['raw_public_bytes']
    ordinary, linear = inv['ordinary_switch_evaluations'], inv['modes']['diagonal']['switch_evaluations']
    products = inv['field_ciphertext_products']
    tensor = sum(op['carriers']*(3 if len(set(op['source_keys']))==1 else 4)
                 for op in graph['operations'] if op['op']=='field_product')
    linear_out = sum(op['carriers'] for op in graph['operations'] if op['op']=='linear')
    row_products = 2*chosen['public_row_evaluations']
    mask_products = 2*inv['ciphertext_by_plaintext_products']
    vector_allowance = 8*(ordinary+linear+products+linear_out)
    keys = {op['node']:op['key'] for op in graph['operations']}
    banks = {(b['source_main_key'],b['target_main_key']):b for b in inv['banks']}
    masks, workspace = set(), 0
    for pos, op in enumerate(graph['operations']):
        if op['op']!='linear':
            continue
        for recipe in op['recipes']:
            for a,i,name in recipe:
                masks.add((name,banks[keys[a],op['key']]['specification']['cut']))
        stage = 0
        for bank in inv['banks']:
            babies = sum(v for p,v in bank['baby_uses'] if p==pos)
            giants = sum(v for p,o,v in bank['giant_uses'] if p==pos)
            stage += (2*babies+2*giants+babies*gd)*N*Mbytes
        workspace = max(workspace,stage)
    mask_count = sum(row['map_summary'][name]['diagonals'] for name,cut in masks)
    mask_entries = sum(row['map_summary'][name]['edges'] for name,cut in masks)
    peak, _ = trial.analysis.liveness(graph)
    # Full dyadic union includes owner-ephemeral energy as well as secret tails.
    union = Fraction(2,2**180)+Fraction(sources,2**228)
    union += secrets*(Fraction(1,2**235)+Fraction(1,2**183)+Fraction(1,2**634))
    union += Fraction(owner,2**634)+Fraction(rows*N,2**256)
    assert union < Fraction(1,2**160)
    return dict(q_bits=qb,P_bits=pb,ordinary_digits=g,diagonal_digits=gd,
        raw_public_bytes=raw, owner_ciphertexts=owner, owner_input_bytes=2*N*qbytes*owner,
        terminal_ciphertexts=outputs, terminal_output_bytes=2*N*qbytes*outputs,
        source_setup_vectors=setup_sources, source_owner_vectors=fresh_sources,
        source_total_vectors=sources, source_ideal_bits=sources*(256*(N+1)+1),
        source_os_bytes=sources*(32*(N+1)+1),
        source_law='FINITE_GRID_LATENT_GAUSSIAN_CDF256_CAP96_GLOBAL_SIGN_V1',
        source_table_bytes=2383552, source_tables=257,
        source_event_transfer_from_old=f'({setup_sources}+{fresh_sources}K)*2^-227',
        source_scope='Common ideal-law analysis; table source within 2^-228 per vector. No vectors sampled here. Twice the event bound for distinguishing gaps.',
        full_failure_union=dict(numerator=str(union.numerator),denominator=str(union.denominator),
                                log2_upper=log2(union),below_2_minus160=True),
        independent_secrets=secrets, map_payload_families=inv['modes']['diagonal']['payload_families'],
        primitive_rows=rows, public_row_evaluations=chosen['public_row_evaluations'],
        masks=dict(adjusted_map_cut_pairs=len(masks),instances=mask_count,
                   compact_binary_bytes=mask_count*N//8, optional_expanded_bytes=mask_count*N*Mbytes,
                   field_entry_writes_upper=mask_entries, full_encodes_upper=mask_count,
                   binary_automorphisms_upper=mask_count, zero_vector_initializations=mask_count,
                   sign_bits=row['signs']['unbiased_bits'],sign_bytes=row['signs']['stored_sign_bytes']),
        memory=dict(logical_ciphertext_peak=peak, logical_ciphertext_bytes=peak*2*N*qbytes,
                    allocate_all_linear_workspace_bytes_upper=workspace,
                    capped_secret_coefficient_bytes=secrets*N,
                    scope='Add actual kernel/codec/source/plan/scratch and chosen row/mask storage; no RSS.'),
        setup=dict(root_uniform_rows_q=1,evaluation_uniform_rows_M=rows-1,
                   uniform_coordinate_abort_bound=f'{rows}*32768*2^-256',
                   uniform_random_bits_upper=256*N*(qb+(rows-1)*(qb+pb)),
                   ring_products_q=1,ring_products_M=rows-1,small_secret_products=8,
                   small_automorphisms=inv['modes']['diagonal']['payload_families'],vector_operations_M=4*rows),
        owner=dict(full_encodes=owner,ring_products_q=2*owner,vector_operations_q=4*owner,
                   plaintext_zero_field_writes=29*2048, f_coefficient_copies=4096,
                   serialized_slot_elements=owner*2048,
                   **row['field_work']['owner']),
        evaluation=dict(raw_tensor_products_q_squared=tensor,scaled_tensor_rounds=tensor,
            row_component_products_M=row_products,mask_component_products_M=mask_products,
            total_ring_products_M=row_products+mask_products,
            ordinary_decompositions_q=ordinary,linear_decompositions_M=linear,
            divide_P_vector_rounds=2*(products+linear_out),automorphisms_M=2*linear,
            vector_operations_M_upper=row_products+mask_products+vector_allowance+inv['ciphertext_by_plaintext_products'],
            field_ciphertext_products=products,linear_output_ciphertexts=linear_out,
            compact_mask_expansions=inv['ciphertext_by_plaintext_products']),
        recovery=dict(ring_products_q=outputs,vector_operations_q=outputs,rounds_q_to_2=outputs,
                      full_decodes=outputs,**row['field_work']['terminal']),
        kernel_scope='Conditional complete kernel ledger plus source construction, public factor/plan generation, mask/sign materialization and all IO. M=qP; q-squared scaled tensor semantics. No implemented receiver timing, numerical transform count or security qualification.')


def main():
    matrix_checks = trial.check_factors()
    fs, gs = trial.inputs()
    expected, library = trial.independent_expected(fs, gs)
    rows = []
    prepared_hashes = None
    for width in (1,2,4,8,16):
        path = HERE/f'width{width}.json'
        data = json.loads(path.read_text())
        for name,binding in data['bindings_after'].items():
            assert trial.analysis.compiler.bind(ROOT/name)==binding, name
        assert data['bindings_before']==data['bindings_after']
        builder = trial.Builder(width)
        graph, actual, work = builder.build(fs,gs)
        # JSON canonicalization accounts only for tuple/list representation.
        canon = lambda v:json.dumps(json.loads(json.dumps(v)),sort_keys=True)
        assert canon(graph)==canon(data['graph'])
        assert canon(builder.summary)==canon(data['map_summary'])
        assert actual==expected and work==data['field_work']
        assert builder.checkpoints==data['checkpoints']
        input_nodes = {op['node'] for op in graph['operations'] if op['op']=='input'}
        input_hashes = {x['node']:x['sha256'] for x in builder.checkpoints if x['node'] in input_nodes}
        if prepared_hashes is None:
            prepared_hashes = input_hashes
        assert prepared_hashes==input_hashes
        C, inv = trial.analysis.compiler.compile_graph(graph,builder.summary,32769)
        signs = trial.analysis.signed_contract(graph,builder.summary,C)
        assert canon(C)==canon(data['record']['symbolic_contract'])
        assert canon(inv)==canon(data['record']['inventory'])
        assert canon(signs)==canon(data['signs'])
        loads,deps = trial.analysis.reuse.contract(data['record'],graph,builder.summary)
        assert canon(loads)==canon(data['linear_variance_contract'])
        assert canon(deps)==canon(data['no_self_dependency_checks'])
        assert trial.analysis.reuse.parameters(data['record'],graph)==data['source_parameters']
        objective = trial.analysis.SEARCH['objective']
        best = min(data['search']['best_per_q'],key=lambda r:tuple(r[k] for k in objective))
        assert all(best[k]==data['search']['selected'][k] for k in objective)
        row = dict(width=width, grid_tested=data['search']['tested'], grid_admitted=data['search']['admitted'],
                   grid_decision_sha256=data['search']['decision_stream_sha256'],
                   floor_bits=data['recurrence_floor']['q_bits'],nodes=len(graph['operations']),
                   graph_edges=builder.edge_count, public_field_elements=len(actual),
                   output_sha256=sha256(actual.tobytes()).hexdigest(),
                   rational_check=rational_bounds(data),costs=costs(data))
        rows.append(row)
        print(json.dumps(dict(width=width,verified=True,costs={k:row['costs'][k] for k in
              ('q_bits','P_bits','raw_public_bytes','source_total_vectors')})),flush=True)
    # Public encoders/decoders need not use the evaluator's fusion policy.
    # All input carriers and recovered outputs above are byte-for-byte equal.
    for row in rows:
        row['costs']['unfused_public_codec_alternative'] = dict(
            owner=rows[0]['costs']['owner'],recovery=rows[0]['costs']['recovery'],
            scope='Use width-one field factors only in owner preparation and post-decryption recovery. Identical input/output values, unchanged HE graph and row screen. No timing assertion.')
    baseline = trial.RESEARCH/'existing-results-revision-2026-09-13/prepared_w0_analysis_v1.json'
    old = json.loads(baseline.read_text())
    assert old['search']['selected']['raw_public_bytes']==25940590592
    result = dict(status='FACTORED_CONTROL_PUBLIC_GRAPH_AND_SELECTED_BOUNDS_PASS',
                  matrices=matrix_checks, profiles=rows,
                  direct_control=dict(q_bits=780,P_bits=390,raw_public_bytes=25940590592,
                                      ring_products_M=129356,ring_products_q_squared=103,
                                      owner_ciphertexts=29,terminal_ciphertexts=6),
                  old_control_sha256=digest(baseline),
                  recorded_grid_policies=sum(r['grid_tested'] for r in rows),
                  scope='Five concrete field circuits reexecuted; selected rational bounds independently recomputed. Grid decisions are source-bound recorded runs, not reexecuted here. No encrypted receiver run, security qualification or measured total-time ordering.')
    files = [HERE/'PLAN.md',HERE/'crt_factors.py',HERE/'compile_control.py',Path(__file__),
             *[HERE/f'width{w}.json' for w in (1,2,4,8,16)]]
    for optional in ('PROOF.md','RESULTS.md','REPRODUCE.md'):
        if (HERE/optional).exists():
            files.append(HERE/optional)
    result['files'] = {p.name:digest(p) for p in files}
    (HERE/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(dict(status=result['status'],recorded_grid_policies=result['recorded_grid_policies'])),flush=True)


if __name__=='__main__':
    main()
