"""Readback of bound fresh receiver records; no new HE or security authority."""
from hashlib import sha256
import argparse
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SNAPSHOT = ROOT / 'SubmissionA/research/paired-src-v1'
SNAPSHOT_HERE = SNAPSHOT / HERE.relative_to(ROOT)


def bind(path):
    return dict(bytes=path.stat().st_size, sha256=sha256(path.read_bytes()).hexdigest())


def read(path):
    return json.loads(path.read_text())


def catalogue_check(catalogue, base=ROOT):
    assert catalogue
    for relative, value in catalogue.items():
        path = (base / relative).resolve()
        assert path.is_relative_to(base) and bind(path) == value, relative


def audit(directory, require_full):
    if not (directory / 'run.json').exists():
        raise FileNotFoundError('No completed receiver record.')
    record = read(directory / 'run.json')
    mode = record['mode']
    if require_full and mode != 'full':
        raise ValueError('A preflight is not a complete-workload execution.')
    assert mode in ('full', 'preflight')
    assert record['status'] == 'FRESH_PAIRED_TERMINAL_' + mode.upper() + '_FUNCTIONAL_PASS'
    assert not (directory / 'failure.json').exists()
    assert record['bindings_before'] == record['bindings_after']
    catalogue_check(record['bindings_after'], SNAPSHOT)
    admission, prefix = read(SNAPSHOT_HERE / 'admission.json'), read(SNAPSHOT_HERE / 'prefix-receipt.json')
    catalogue_check(admission['bindings_after'], SNAPSHOT)
    catalogue_check(prefix['bindings'], SNAPSHOT)
    assert admission['bindings_before'] == admission['bindings_after']
    assert bind(SNAPSHOT_HERE / 'prefix16.bin')['sha256'] == prefix['prefix_sha256']
    assert prefix['additional_statistical_distance'] == '0'
    n, q, cap = 32768, 2**89 - 1, 96
    kappa = 4 * n - 3
    fresh = 2 * kappa * cap**2 + cap
    raw = 8 * kappa * (fresh**2 + fresh) + 2 * kappa
    residue = 4
    for _ in range(87):
        residue = (residue * residue - 2) % q
    assert residue == 0 and q > 2 + 4 * raw
    assert [int(admission['selected'][key]) for key in ('q', 'fresh_cap', 'raw_cap')] == [q, fresh, raw]
    assert (record['q'], record['n'], record['q_bits'], record['source_cap']) == (str(q), n, 89, cap)
    jobs, length = record['jobs'], record['length']
    assert (jobs, length) == (16, 256 if mode == 'full' else 4)
    scalar_pairs = jobs * (2 * length**2 + 3 * length - 8) // 12
    carriers = (scalar_pairs + 2047) // 2048
    bypasses = (jobs * length + 2047) // 2048
    inputs = 4 * carriers + 2 * bypasses
    assert (record['scalar_pairs'], record['product_carriers'], record['bypass_carriers_per_owner'],
            record['input_ciphertexts']) == (scalar_pairs, carriers, bypasses, inputs)
    products = dict(public_key=1, encryption=2 * inputs, raw_tensors=3 * carriers,
                    input_validation=inputs, secret_square=1,
                    terminal_decryption=2 * carriers + 2 * bypasses)
    assert record['ring_products'] == products
    assert record['total_instrumented_core_ring_products'] == sum(products.values())
    assert record['extra_diagnostic_ring_products'] == (6 if mode == 'preflight' else 2)
    counts = record['counts']
    required_counts = dict(public_polynomials=2, fresh_inputs=inputs,
                           input_ciphertexts=inputs, input_polynomials=2 * inputs,
                           raw_products=carriers, output_ciphertexts=carriers + 2 * bypasses,
                           output_polynomials=3 * carriers + 4 * bypasses,
                           input_binary_coefficients=n * inputs,
                           output_binary_coefficients=n * (carriers + 2 * bypasses),
                           decoded_field_slots=2048 * (carriers + 2 * bypasses))
    assert all(counts[key] == value for key, value in required_counts.items())
    expected_payload = dict(public=2 * n * 12, input=2 * inputs * n * 12,
                            output=(3 * carriers + 4 * bypasses) * n * 12)
    assert record['payload_bytes'] == expected_payload
    source = record['finite_source']
    vectors = 2 + 3 * inputs
    assert source['vectors'] == vectors and source['exact_law_preserved'] and source['diagnostic_only']
    assert source['source_bytes'] == 65539 * vectors + 30 * source['ambiguous_draws']
    assert 0 <= source['ambiguous_draws'] <= (n + 1) * vectors
    assert 0 <= source['cap_events'] <= vectors
    assert source['original_fixed_byte_budget'] == 1048609 * vectors
    assert record['uniform_source']['vectors'] == 1
    assert record['uniform_source']['source_bytes'] >= n * 12
    assert record['uniform_source']['bounded_exhaustion_upper'] == '2^-22769'
    assert all(record['omitted_correction_nonconstant_failures'][owner] > 0 for owner in ('outer', 'inner'))
    assert record['arithmetic_checks'] == dict(field_pairs=512, independent_small_range_coefficients=124,
                                               production_range_coefficients=n)
    events = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
    assert events[-1]['stage'] == record['status']
    assert events[-1]['finite_vectors'] == vectors
    assert events[-1]['ring_products'] == sum(products.values())
    assert [row['carrier'] for row in events if row['stage'] == 'product recovered'] == list(range(carriers))
    assert [(row['owner'], row['carrier']) for row in events if row['stage'] == 'bypass recovered'] == [
        (owner, carrier) for owner in ('outer', 'inner') for carrier in range(bypasses)]
    assert all(left['seconds'] <= right['seconds'] for left, right in zip(events, events[1:]))
    assert 0 < record['workflow_phase_seconds'] <= record['instrumented_wall_seconds'] <= events[-1]['seconds']
    output = (directory / 'recovered.bin').read_bytes()
    assert len(output) == 2 * jobs * length
    assert sha256(output).hexdigest() == record['recovered_sha256'] == events[-1]['result_sha256']
    if mode == 'full':
        assert output == (HERE.parent / 'compiled-receiver-v1' / 'expected.bin').read_bytes()
    else:
        from prepare import composition_fixture, independent_horner
        fs, gs = composition_fixture.inputs()
        expected = independent_horner([f[:4] for f in fs], [g[:4] for g in gs])
        assert list(struct.unpack('<64H', output)) == expected
    assert record['backend']['version'] == '6.3.0'
    assert record['backend']['sha256'] == 'fda9699eef15deda5f1c626e9140377a7f5d88c41516a54278ac02429cb20fa5'
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', default='full-v1')
    parser.add_argument('--preflight', default='preflight-v1')
    args = parser.parse_args()
    full_dir, preflight_dir = (HERE / args.run).resolve(), (HERE / args.preflight).resolve()
    assert full_dir.parent == preflight_dir.parent and full_dir.parent in (HERE, SNAPSHOT_HERE)
    snapshot = read(HERE / 'source-snapshot.json')
    assert snapshot['status'] == 'EXACT_COMPLETED_EXECUTION_SOURCE_SNAPSHOT_PASS'
    assert snapshot['snapshot_root'] == SNAPSHOT.relative_to(ROOT).as_posix()
    assert snapshot['file_count'] == len(snapshot['files']) == 30
    assert snapshot['total_bytes'] == sum(v['bytes'] for v in snapshot['files'].values())
    catalogue_check(snapshot['files'], SNAPSHOT)
    for name, value in snapshot['run_records'].items():
        assert bind(HERE / name / 'run.json') == value
    full, preflight = audit(full_dir, True), audit(preflight_dir, False)
    rejected = []
    for name, directory, exception in (('missing record', HERE / '_intentionally_absent_record', FileNotFoundError),
                                        ('preflight as full', preflight_dir, ValueError)):
        try:
            audit(directory, True)
        except exception:
            rejected.append(name)
        else:
            raise AssertionError('Invalid acceptance: ' + name)
    paths = [HERE / 'verify_receiver.py', HERE / 'prepare.py', HERE / 'source-snapshot.json']
    paths += [directory / name for directory in (full_dir, preflight_dir)
              for name in ('run.json', 'events.jsonl', 'recovered.bin')]
    receipt = dict(status='PAIRED_TERMINAL_ADMISSION_AND_RECORDED_EXECUTION_CHECKS_PASS',
                   full_run=args.run, preflight_run=args.preflight,
                   full_core_ring_products=1480, full_extra_diagnostic_ring_products=2,
                   full_finite_source_vectors=1046, full_binary_coordinates=14352384,
                   full_recovered_field_words=4096, full_input_ciphertexts=348,
                   full_raw_products=86, full_output_ciphertexts=90,
                   full_finite_source_bytes=full['finite_source']['source_bytes'],
                   full_payload_bytes=full['payload_bytes'],
                   preflight_binary_coordinates=294912, rejected_incomplete_records=rejected,
                   full_workflow_phase_seconds=full['workflow_phase_seconds'],
                   full_instrumented_wall_seconds=full['instrumented_wall_seconds'],
                   execution_bindings={(SNAPSHOT / name).relative_to(ROOT).as_posix(): value
                                       for name, value in snapshot['files'].items()},
                   execution_snapshot_files=30, execution_snapshot_bytes=36949136,
                   files={str(p.relative_to(ROOT)).replace('\\', '/'): bind(p) for p in paths},
                   new_he_execution=False, security_bits=None, performance_comparison=False,
                   scope='Independent integer admission and recorded-run consistency checks against the exact '
                         'completed-execution source snapshot, preserving its proof checkpoint. No retained '
                         'ciphertext replay, new encryption, formal proof verification or matched runtime ranking.')
    assert full['counts']['input_binary_coefficients'] + full['counts']['output_binary_coefficients'] == receipt['full_binary_coordinates']
    (HERE / 'verification.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({k: v for k, v in receipt.items() if k not in ('execution_bindings', 'files')}, indent=2))


if __name__ == '__main__':
    main()
