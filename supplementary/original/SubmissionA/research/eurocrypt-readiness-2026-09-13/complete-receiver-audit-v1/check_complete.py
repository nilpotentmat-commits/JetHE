"""Prepare public acceptance conditions and audit a real complete HE record."""
import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
READY, ROOT = HERE.parent, HERE.parents[3]
RUNNER = READY/'compiled-receiver-v1'
KERNELS = READY/'receiver-kernels-v1'
PROFILE = READY/'factored-control-v1/width16.json'
N, Q, P = 32768, (1 << 1066)-1, (1 << 533)-3


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def bind(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=sha256(raw).hexdigest())


def bound_paths(bindings):
    for name, expected in bindings.items():
        path = (ROOT/name).resolve()
        assert path.is_relative_to(ROOT.resolve())
        assert bind(path) == expected, name


def inputs():
    profile, export = read(PROFILE), read(RUNNER/'graph.json')
    preflight = read(RUNNER/'preflight-v1/execution.json')
    assert export['status'] == 'EXACT_COMPILED_CONTROL_EXPORT_PASS'
    assert profile['graph'] == export['graph']
    assert bind(PROFILE) == export['profile']
    assert preflight['status'] == 'COMPILED_BSGS_MAP_PREFLIGHT_PASS'
    assert preflight['mode'] == 'preflight' and preflight['terminal'] is None
    for record in (export, preflight):
        bound_paths(record['bindings'])
    for name, expected in export['files'].items():
        path = (RUNNER/name).resolve()
        assert path.is_relative_to(RUNNER.resolve()) and bind(path) == expected
    assert export['expected_sha256'] == bind(RUNNER/'expected.bin')['sha256']
    assert export['expected_sha256'] == 'd22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
    paths = {ROOT/name for record in (export, preflight) for name in record['bindings']}
    paths.update(HERE/x for x in ('PLAN.md', 'REPRODUCE.md', 'check_complete.py'))
    paths.add(RUNNER/'preflight-v1/execution.json')
    binding = {p.relative_to(ROOT).as_posix(): bind(p) for p in sorted(paths)}
    return profile, export, preflight, binding


def inventory(profile):
    graph, inv = profile['graph'], profile['record']['inventory']
    ops = graph['operations']
    by_node = {op['node']: op for op in ops}
    assert len(by_node) == len(ops) == 45
    banks = {(b['source_main_key'], b['target_main_key']): b for b in inv['banks']}
    counts, mask_keys, max_babies = Counter(), set(), 0
    for position, op in enumerate(ops):
        if op['op'] == 'input':
            assert op['key'] == 0
            continue
        counts['P_division_vectors'] += 2*op['carriers']
        if op['op'] == 'field_product':
            assert [by_node[x]['key'] for x in op['args']] == op['source_keys']
            distinct = len(set(op['source_keys']))
            counts['ciphertext_products'] += op['carriers']
            counts['ordinary_payload_families'] += distinct+1
            counts['ordinary_switches'] += (distinct+1)*op['carriers']
            counts['raw_tensor_products'] += (distinct+2)*op['carriers']
            continue
        assert op['op'] == 'linear' and len(op['recipes']) == op['carriers']
        routed = defaultdict(list)
        for out, recipe in enumerate(op['recipes']):
            for node, carrier, name in recipe:
                assert 0 <= carrier < by_node[node]['carriers']
                routed[by_node[node]['key']].append((out, node, carrier, name))
        for source, recipes in routed.items():
            bank = banks[source, op['key']]
            assert bank['source_secret'] < bank['helper_secret'] < bank['target_secret']
            assert bank['mode'] == 'diagonal' and bank['error_divisor'] == 1
            cut = bank['specification']['cut']
            babies, giants = set(), set()
            for out, node, carrier, name in recipes:
                for parity, exponent in profile['map_summary'][name]['exponents']:
                    assert parity == 0
                    baby, giant = exponent % cut, exponent-exponent % cut
                    babies.add((node, carrier, baby))
                    giants.add((giant, out))
                    mask_keys.add((name, exponent, giant))
                    counts['mask_products'] += 2
            assert len(babies) == sum(n for p, n in bank['baby_uses'] if p == position)
            assert len(giants) == sum(n for p, o, n in bank['giant_uses'] if p == position)
            assert sorted({b for a, i, b in babies}) == [b for parity, b in bank['specification']['baby_coordinates']]
            assert sorted({g for g, o in giants}) == [g for parity, g in bank['specification']['giant_coordinates']]
            counts['baby_switches'] += len(babies)
            counts['giant_switches'] += len(giants)
            counts['map_payload_families'] += len({b for a, i, b in babies})+len({g for g, o in giants})
            max_babies = max(max_babies, len(babies))
    assert counts['ordinary_payload_families'] == inv['ordinary_payload_families']
    assert counts['map_payload_families'] == inv['modes']['diagonal']['payload_families']
    assert counts['baby_switches']+counts['giant_switches'] == inv['modes']['diagonal']['switch_evaluations']
    owners = sum(op['carriers'] for op in ops if op['op'] == 'input')
    checked = sum(op['carriers'] for op in ops)
    outputs = sum(by_node[name]['carriers'] for out in graph['outputs'] for name in out.values())
    rows = 1+2*(counts['ordinary_payload_families']+counts['map_payload_families'])
    secrets = len(inv['main_secret_order'])+len(banks)
    assert (owners, checked, outputs, rows, secrets) == (31, 150, 6, 1571, 70)
    assert secrets == inv['independent_secrets'] and rows == profile['search']['selected']['primitive_rows']
    row_products = 4*(counts['ordinary_switches']+counts['baby_switches']+counts['giant_switches'])
    evaluator_M = row_products+counts['mask_products']
    setup_M = rows-1+sum(op['op'] == 'field_product' for op in ops)
    q_products = 1+2*owners+checked+outputs
    moduli = {str(Q.bit_length()): q_products, str((Q*P).bit_length()): evaluator_M+setup_M,
              str((Q*Q).bit_length()): counts['raw_tensor_products']}
    signs = {name: [str(e) for parity, e in profile['map_summary'][name]['exponents']]
             for name, gain in profile['signs']['gains'].items() if gain['randomize']}
    assert sum(map(len, signs.values())) == profile['signs']['unbiased_bits'] == 4606
    return dict(counts=dict(counts), checked_carriers=checked, binary_coordinates=N*checked,
                owner_encryptions=owners, terminal_ciphertexts=outputs, independent_secrets=secrets,
                primitive_rows=rows, finite_vectors=secrets+rows+3*owners,
                evaluator_ring_products_M=evaluator_M, setup_ring_products_M=setup_M,
                expected_ring_products_by_modulus_bits=moduli,
                instrumented_ring_products=sum(moduli.values()),
                maximum_baby_ciphertexts=max_babies, compact_mask_cache_bytes=len(mask_keys)*N//8,
                sign_keys=signs, sign_bits=4606, sign_os_bytes=sum((len(x)+7)//8 for x in signs.values()),
                uniform_os_bytes_minimum=N*(134+(rows-1)*200))


def prepare():
    profile, export, preflight, before = inputs()
    sys.path.insert(0, str(KERNELS))
    from arithmetic import GMP
    from codec import Codec
    backend = GMP()
    assert backend.binding() == preflight['backend']
    codec, states = Codec(backend), (RUNNER/'states.bin').read_bytes()
    expected, bounds = [], {row['node']: row['bounds'] for row in profile['search']['selected']['bounds']}
    ops = profile['graph']['operations']
    order = [op for op in ops if op['op'] == 'input']+[op for op in ops if op['op'] != 'input']
    for op in order:
        state = export['states'][op['node']]
        raw = states[state['offset']:state['offset']+state['bytes']]
        assert sha256(raw).hexdigest() == state['sha256'] and len(raw) == 4096*op['carriers']
        words = [x for x, in struct.iter_unpack('<H', raw)]
        hashes = [sha256(bytes(codec.encode(words[i:i+2048]))).hexdigest() for i in range(0, len(words), 2048)]
        assert len(hashes) == len(bounds[op['node']]) == op['carriers']
        expected.append(dict(node=op['node'], carriers=op['carriers'], decoded_sha256=hashes,
                             admitted_bounds=[str(b) for b in bounds[op['node']]]))
    by_node = {r['node']: r for r in expected}
    assert sum(row['carriers'] for row in preflight['checks']) == 6
    for row in preflight['checks']:
        assert [c['decoded_sha256'] for c in row['checks']] == by_node[row['node']]['decoded_sha256']
    bound_paths(before)
    result = dict(status='PUBLIC_COMPLETE_RECEIVER_ACCEPTANCE_CONTRACT_PREPARED',
                  bindings=before, receiver_bindings=preflight['bindings'], backend=backend.binding(),
                  expected_checks=expected, inventory=inventory(profile),
                  terminal=dict(field_elements=4096, sha256=export['expected_sha256'], terminal_ciphertexts=6),
                  preflight_public_hash_crosschecks=6, new_he_execution=False,
                  complete_execution_verified=False, security_bits=None,
                  scope='Public expected states and independently derived final-record acceptance conditions; not a complete HE result.')
    (HERE/'contract.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('bindings','receiver_bindings','expected_checks','inventory')}, indent=2))
    print(json.dumps({k:v for k,v in result['inventory'].items() if k != 'sign_keys'}, indent=2))


def verify(name):
    destination = (RUNNER/name).resolve()
    assert destination.parent == RUNNER.resolve(), 'Use a receiver child run directory.'
    assert not (destination/'failure.json').exists(), 'A recorded failure must be inspected, not promoted.'
    if not (destination/'execution.json').exists():
        print(json.dumps(dict(status='FINAL_EXECUTION_RECORD_UNAVAILABLE', complete_execution_verified=False,
                             scope='No final record at this path; no process-liveness assertion.')))
        return 2
    contract, receipt = read(HERE/'contract.json'), read(destination/'execution.json')
    assert contract['status'] == 'PUBLIC_COMPLETE_RECEIVER_ACCEPTANCE_CONTRACT_PREPARED'
    bound_paths(contract['bindings'])
    assert receipt['status'] == 'COMPLETE_CONVENTIONAL_GRAPH_EXECUTION_PASS' and receipt['mode'] == 'complete'
    assert receipt['bindings'] == contract['receiver_bindings']
    bound_paths(receipt['bindings'])
    assert receipt['backend'] == contract['backend']
    assert bind(Path(receipt['backend']['path']))['sha256'] == receipt['backend']['sha256']
    expected, inv = contract['expected_checks'], contract['inventory']
    assert len(receipt['checks']) == len(expected) == 45
    for actual, want in zip(receipt['checks'], expected):
        assert (actual['node'], actual['carriers']) == (want['node'], want['carriers'])
        assert actual['compared_with_admitted_bound'] is True
        assert len(actual['checks']) == want['carriers']
        assert actual['ciphertext_bytes'] == want['carriers']*2*N*134
        for check, digest, cap in zip(actual['checks'], want['decoded_sha256'], want['admitted_bounds']):
            assert check['coefficients'] == N and check['decoded_sha256'] == digest
            assert check['strict_quarter_modulus'] is True
            assert 0 <= int(check['maximum_error']) <= int(cap)
            assert 4*int(check['maximum_error']) < Q-1
    assert receipt['terminal'] == contract['terminal']
    assert receipt['counts'] == inv['counts']
    source = receipt['sources']
    for key in ('independent_secrets', 'primitive_rows', 'owner_encryptions', 'finite_vectors', 'sign_bits', 'sign_os_bytes'):
        assert source[key] == inv[key], key
    assert source['finite_os_bytes'] == inv['finite_vectors']*(32*(N+1)+1)
    assert 0 <= source['caps'] <= inv['finite_vectors']
    assert source['uniform_vectors'] == inv['primitive_rows']
    assert inv['uniform_os_bytes_minimum'] <= source['uniform_os_bytes'] <= 256*inv['uniform_os_bytes_minimum']
    assert source['signs'] == bind(destination/'signs.json')
    signs = read(destination/'signs.json')
    assert set(signs) == set(inv['sign_keys'])
    for map_name, exponents in inv['sign_keys'].items():
        assert set(signs[map_name]) == set(exponents)
        assert all(type(x) is int and x in (-1, 1) for x in signs[map_name].values())
    arithmetic, grouped = receipt['arithmetic'], Counter()
    assert arithmetic['instrumented_ring_products'] == inv['instrumented_ring_products']
    for row in arithmetic['width_inventory']:
        assert row['count'] > 0 and row['packed_word_bytes'] >= 0
        assert len(row['shifted_operand_bits']) == 2 and min(row['shifted_operand_bits']) >= 0
        grouped[str(row['modulus_bits'])] += row['count']
    assert dict(grouped) == inv['expected_ring_products_by_modulus_bits']
    ranges = receipt['range_checks']
    assert ranges['independent_small_coefficients'] == 372 and ranges['full_dimension_coefficients'] == 131072
    assert [(x['modulus_bits'], x['right_operand'], x['coefficients']) for x in ranges['full_dimension_comparisons']] == [
        (1066, 'binary', N), (1599, 'small', N), (2132, 'dense', N), (1599, 'digits', N)]
    execution = receipt['execution']
    assert execution['address_space_limit_bytes'] == 6 << 30
    assert execution['seconds'] > 0 and 0 < execution['peak_rss_kib']*1024 <= 6 << 30
    for key in ('maximum_baby_ciphertexts', 'compact_mask_cache_bytes'):
        assert execution[key] == inv[key], key
    assert receipt['security_bits'] is None
    files = {p.relative_to(ROOT).as_posix(): bind(p) for p in
             (HERE/'contract.json', destination/'execution.json', destination/'signs.json')}
    bound_paths(contract['bindings'])
    result = dict(status='COMPLETE_CONVENTIONAL_RECEIVER_RECORDED_EXECUTION_READBACK_PASS',
                  files=files, input_bindings=contract['bindings'], checked_nodes=45,
                  recorded_binary_coordinates=inv['binary_coordinates'], terminal=receipt['terminal'],
                  inventory={k:v for k,v in inv.items() if k != 'sign_keys'},
                  diagnostic_seconds=execution['seconds'], peak_rss_kib=execution['peak_rss_kib'],
                  complete_execution_record_verified=True, new_he_execution=False, security_bits=None,
                  optimized_warm_workflow=False, scientific_readiness='NOT_YET_ESTABLISHED',
                  scope='Consistency of an actual final encrypted-run record with public expectations and current source/library bindings. No fresh decryption, independent secret replay, security or speed qualification.')
    (HERE/'verification.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('files','input_bindings','inventory')}, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--verify', metavar='RUN_DIRECTORY')
    args = parser.parse_args()
    if args.prepare:
        prepare()
        return 0
    return verify(args.verify)


if __name__ == '__main__':
    raise SystemExit(main())
