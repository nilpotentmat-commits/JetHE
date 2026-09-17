"""Validate a source-bound recorded kernel execution; no fresh HE run."""
from hashlib import sha256
import json
from math import gcd
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def binding(path):
    return dict(bytes=path.stat().st_size, sha256=sha256(path.read_bytes()).hexdigest())


def main():
    receipt = HERE/'execution-v2.json'
    data = json.loads(receipt.read_text())
    assert data['status'] == 'REAL_PERIOD_RECEIVER_KERNEL_CHECKS_PASS'
    for name, expected in data['bindings'].items():
        path = (ROOT/name).resolve()
        assert path.is_relative_to(ROOT.resolve())
        assert binding(path) == expected, name
    backend = data['backend']
    if os.name == 'nt':
        result = subprocess.run(['wsl', '-e', 'sha256sum', backend['path']],
                                check=True, capture_output=True)
        current = result.stdout.decode().split()[0]
    else:
        current = binding(Path(backend['path']))['sha256']
    assert current == backend['sha256']
    small = data['small']
    assert small['independent_ring_coefficients'] == 585
    assert small['integer_rounding_cases'] == 669468
    assert small['balanced_digit_endpoints'] == 60
    assert small['wrong_mod_q_tensor_reduction_detected']
    p = data['production']
    q, P = int(p['q']), int(p['P'])
    assert (q, P) == ((1 << 1066)-1, (1 << 533)-3)
    assert gcd(q, P) == gcd(q*P, 2*65537) == 1
    assert (p['dimension'], p['conductor'], p['field_slots']) == (32768, 65537, 2048)
    assert p['modulus_bits'] == [1066, 533, 1599]
    selected = json.loads((HERE.parent/'factored-control-v1/width16.json').read_text())['search']['selected']
    assert (selected['q_bits'], selected['P_bits']) == (1066, 533)
    codec = p['codec']
    for name, count in (('roundtrip_field_slots', 4096), ('original_fixture_slot_order_checks', 4096),
                        ('inverse_coordinate_basis_checks', 65536), ('full_field_product_slots', 2048),
                        ('encrypted_product_field_slots', 2048)):
        assert codec[name] == count
    assert codec['original_root_oracle_slots'] == [0, 1, 37, 2047]
    assert [row['modulus_bits'] for row in p['arithmetic']] == [1066, 1599, 2132]
    assert sum(row['direct_coefficients'] for row in p['arithmetic']) == 12
    tests = p['primitive_tests']
    assert [row['name'] for row in tests] == ['fresh_owner_0', 'fresh_owner_1',
        'ordinary_independent_key_switch', 'single_diagonal_automorphism_and_mask',
        'different_key_scaled_BFV_product']
    for row in tests:
        assert row['coefficients'] == 32768 and row['strict_quarter_modulus']
        assert 0 <= 4*int(row['maximum_error']) < q-1
        assert len(row['decoded_sha256']) == 64
    assert tests[0]['decoded_sha256'] == tests[2]['decoded_sha256']
    for i in range(2):
        path = ROOT/f'SubmissionA/research/core-resolution/packed-fermat-receiver-v1/prime-physical-plaintext-{i}-v1.bin'
        raw = path.read_bytes()
        assert len(raw) == 65536 and raw == raw[::-1]
        assert sha256(raw[:32768]).hexdigest() == tests[i]['decoded_sha256']
    source, he = p['sources'], p['he']
    assert he['primitive_public_rows'] == source['uniform_vectors'] == 12
    assert he['owner_encryptions'] == 2 and he['instrumented_ring_products'] == 50
    assert 0 < he['omitted_identity_changes_plaintext_bits'] <= 32768
    assert source['finite_vectors'] == 5 + 12 + 3*2 == 23
    assert source['finite_os_bytes'] == 23*(32*(32768+1)+1)
    assert 0 <= source['capped_vectors'] <= 23
    uniform_minimum = 32768*(2*134+10*200)
    assert uniform_minimum <= source['uniform_os_bytes'] <= 256*uniform_minimum
    files = {path.name: binding(path) for path in sorted(HERE.iterdir())
             if path.is_file() and path.suffix in ('.py', '.md')}
    files['execution-v2.json'] = binding(receipt)
    out = dict(status='RECEIVER_KERNEL_RECORDED_EXECUTION_READBACK_PASS',
               execution_receipt_sha256=binding(receipt)['sha256'], files=files,
               library_sha256=current, recorded_dimension=32768,
               recorded_primitive_decryptions=len(tests), recorded_source_vectors=23,
               recorded_binary_coordinates=sum(t['coefficients'] for t in tests),
               recorded_encrypted_product_slots=2048,
               receipt_check_runs_new_encryption=False, complete_control_execution=False,
               security_bits=None,
               scope='Current source and library hashes plus recorded execution consistency; no fresh encryption or timing in this readback.')
    (HERE/'verification.json').write_text(json.dumps(out, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in out.items() if k != 'files'}, indent=2))


if __name__ == '__main__':
    main()
