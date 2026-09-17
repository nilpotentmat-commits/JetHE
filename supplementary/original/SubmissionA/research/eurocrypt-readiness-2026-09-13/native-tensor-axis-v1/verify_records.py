"""Portable consistency checks of the completed tensor-axis evidence.

This reader checks current repository bytes and recorded execution results. It
does not rerun encryption or rehash external Linux libraries from Windows.
"""
from datetime import datetime
from hashlib import sha256
import json
from math import isclose
from pathlib import Path
from statistics import median

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
STAGE = HERE.parent / 'native-stage-gadgets-v1'
ORDER = ['baseline', 'tensor', 'tensor', 'baseline', 'baseline', 'tensor', 'tensor', 'baseline']


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def binding(path):
    return dict(bytes=path.stat().st_size, sha256=sha256(path.read_bytes()).hexdigest())


def metrics(rows):
    values = dict(
        setup=[r['setup_wall_seconds'] for r in rows],
        cold=[r['batches'][0]['batch_wall_seconds'] for r in rows],
        warm=[r['batches'][1]['batch_wall_seconds'] for r in rows],
        first_use=[r['setup_wall_seconds'] + r['batches'][0]['batch_wall_seconds'] for r in rows],
        warm_encryption=[r['batches'][1]['seconds']['encryption'] for r in rows],
        warm_evaluation=[r['batches'][1]['seconds']['evaluation'] for r in rows],
        peak_rss_MiB=[r['peak_rss_kib'] / 1024 for r in rows])
    return {key: dict(samples=v, median=median(v), minimum=min(v), maximum=max(v))
            for key, v in values.items()}


def main():
    gate = read(HERE / 'gate-v1/summary.json')
    campaign = read(HERE / 'campaign-v1/summary.json')
    assert gate['status'] == 'NATIVE_TENSOR_AXIS_BOTH_FRESH_GATES_PASS'
    assert campaign['status'] == 'NATIVE_TENSOR_AXIS_CONTROLLED_WORKFLOW_PASS'
    assert gate['order'] == ['baseline', 'tensor'] and campaign['order'] == ORDER
    assert gate['source_manifest'] == campaign['source_manifest']
    assert gate['runtime_manifest'] == campaign['runtime_manifest']
    assert len(gate['source_manifest']) == 124 and len(gate['runtime_manifest']) == 12
    for name, wanted in gate['source_manifest'].items():
        assert binding(ROOT / name) == wanted, name
    assert campaign['gate'] == binding(HERE / 'gate-v1/summary.json')
    measured, files = [], []
    for directory, summary, mode in ((HERE / 'gate-v1', gate, 'gate'),
                                     (HERE / 'campaign-v1', campaign, 'measure')):
        assert summary['new_he_execution'] and summary['security_bits'] is None
        for name, wanted in summary['files'].items():
            assert binding(directory / name) == wanted, name
        for index, variant in enumerate(summary['order']):
            stem = f'{index:02d}-{variant}'
            record = read(directory / (stem + '.json'))
            result = record['result']
            assert record['status'] == 'PASS' and record['worker_exit_code'] == 0
            assert record['termination'] is None and record['error'] is None
            assert record['stdout'] == binding(directory / (stem + '.stdout.txt'))
            assert record['stderr'] == binding(directory / (stem + '.stderr.txt'))
            assert record['stderr']['bytes'] == 0
            raw = [json.loads(line) for line in (directory / (stem + '.stdout.txt')).read_text().splitlines()]
            assert [v['result'] for v in raw if v.get('event') == 'native_stage_gadget_result'] == [result]
            assert (result['mode'], result['variant'], result['index'], result['arm']) == (mode, variant, index, 'native')
            suffix = 'GATE_PASS' if mode == 'gate' else 'MEASUREMENT_PASS'
            assert result['status'] == 'NATIVE_TENSOR_AXIS_WORKFLOW_' + suffix
            assert result['profile_version'] == 'native-tensor-axis-v1'
            assert result['source_bindings'] == gate['source_manifest']
            assert result['runtime_bindings'] == gate['runtime_manifest']
            assert result['phase_checked_states'] == (57 if mode == 'gate' else 0)
            assert result['phase_checked_coefficients'] == 65536 * result['phase_checked_states']
            assert result['worker_threads'] == 1 and result['affinity'] == [0]
            assert result['terminal_limbs'] == 2
            assert result['encrypted_execution'] and result['security_bits'] is None
            material = result['material']
            assert material['public_material_raw_bytes'] == 297 << 20
            assert [material[k] for k in ('independent_secrets', 'public_keys', 'evaluation_rows',
                                         'setup_error_vectors', 'setup_small_vectors')] == [9, 5, 102, 107, 116]
            assert len(result['batches']) == (1 if mode == 'gate' else 2)
            for i, batch in enumerate(result['batches']):
                assert batch['index'] == i and batch['output_symbols'] == 4096
                assert batch['output_sha256'] == 'd22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
                assert batch['counts'] == dict(fresh_encryptions=35, small_vectors=105,
                                               error_vectors=70, ciphertext_products=19)
                assert batch['wire']['input_raw_bytes'] == 103 << 20
                assert batch['wire']['output_raw_bytes'] == 3 << 20
                assert batch['batch_wall_seconds'] >= sum(batch['seconds'].values()) > 0
            if mode == 'measure':
                measured.append(result)
        files.extend(directory.glob('*.json'))
        files.extend(directory.glob('*.txt'))
    build, check = read(HERE / 'build.json'), read(HERE / 'public-check.json')
    assert build['status'] == 'NATIVE_TENSOR_AXIS_BUILD_PASS' and build['returncode'] == 0
    assert check['status'] == 'NATIVE_TENSOR_AXIS_PUBLIC_CORRESPONDENCE_PASS'
    assert check['build_receipt'] == binding(HERE / 'build.json')
    assert check['checker'] == binding(HERE / 'check_candidate.py')
    assert check['advance_to_fresh_gate'] and check['kernel_baseline_over_candidate'] >= 1.03
    assert not check['new_he_execution']
    admission = read(STAGE / 'admission.json')
    assert admission['status'] == 'NATIVE_STAGE_GADGETS_CONDITIONAL_ADMISSION_PASS'
    for name, wanted in admission['bindings'].items():
        assert binding(ROOT / name) == wanted, name
    host = read(HERE / 'campaign-v1/host-observation.json')
    assert host == read(HERE / 'host-observation-v1.json') and set(host) == {'windows', 'wsl'}
    for value in host.values():
        assert value['workers'] == [] and value['tool_exit_code'] == 0
        age = (datetime.fromisoformat(campaign['started_utc']) -
               datetime.fromisoformat(value['recorded_utc'])).total_seconds()
        assert 0 <= age <= 300
    calculated = {arm: metrics([r for r in measured if r['variant'] == arm])
                  for arm in ('baseline', 'tensor')}
    assert campaign['summary'] == calculated
    ratios = campaign['baseline_over_tensor_median_ratios']
    assert set(ratios) == set(calculated['baseline'])
    for key, ratio in ratios.items():
        assert isclose(ratio, calculated['baseline'][key]['median'] /
                       calculated['tensor'][key]['median'], rel_tol=1e-12)
    files += [HERE / name for name in ('verify_records.py', 'RESULTS.md', 'REPRODUCE.md',
                                      'host-observation-v1.json', 'execution.json')]
    receipt = dict(status='NATIVE_TENSOR_AXIS_RECORDED_WORKFLOW_READBACK_PASS',
                   source_files=len(gate['source_manifest']), recorded_runtime_files=len(gate['runtime_manifest']),
                   fresh_gate_states_by_arm=dict(baseline=57, tensor=57),
                   fresh_gate_coefficients_by_arm=dict(baseline=3735552, tensor=3735552),
                   measured_setups=8, measured_batches=16,
                   summary=calculated, ratios=ratios, source_bindings=gate['source_manifest'],
                   files={p.relative_to(ROOT).as_posix(): binding(p) for p in files},
                   new_he_execution=False, current_external_runtime_rehashed=False, security_bits=None,
                   scope='Recorded fresh gate and campaign consistency and current repository bindings; no secret replay, population speedup, source-hardness claim or cross-campaign ratio.')
    (HERE / 'verification.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in receipt.items() if k not in ('summary', 'source_bindings', 'files')}))


if __name__ == '__main__':
    main()
