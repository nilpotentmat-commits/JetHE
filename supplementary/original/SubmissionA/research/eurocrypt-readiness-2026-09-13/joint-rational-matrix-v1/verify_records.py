"""Validate recorded rational-matrix evidence; does not rerun its experiments."""
from pathlib import Path
from hashlib import sha256
import json

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent


def binding(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw),sha256=sha256(raw).hexdigest())


def main():
    manifest = json.loads((HERE/'manifest.json').read_text(encoding='utf-8'))
    for name,want in manifest['local_files'].items():
        assert binding(HERE/name) == want,name
    for name,want in manifest['frozen_context'].items():
        assert name.startswith('checkpoint-v42/manuscript/')
        assert binding(PARENT/name) == want,name
    record = json.loads((HERE/'check.json').read_text(encoding='utf-8'))
    execution = json.loads((HERE/'execution.json').read_text(encoding='utf-8'))
    assert execution['actual_exit_code'] == 0
    for channel in ['stdout','stderr']:
        assert binding(HERE/f'check.{channel}.txt') == execution[channel]
    assert not (HERE/'check.stderr.txt').read_bytes()
    assert record['status'] == 'EXACT_RATIONAL_MATRIX_CHECKS_PASS'
    assert record['counts'] == dict(exact_reconstruction_divisions=6132,
        prefix_rounding_cases=249,ring_matrices=49,ring_output_coefficients=506112,
        signed_integer_matrices=20,tensor_coefficients=64)
    assert len(record['fixtures']) == 49
    assert sum(x['e']**2*256*x['ell'] for x in record['fixtures']) == 506112
    assert sum(x['dense'] for x in record['fixtures']) == 3
    assert any(x['denominator_is_nonunit'] for x in record['fixtures'])
    assert (record['prefix_exponent'],record['threshold_exponent'],record['work_exponent']) == (
        '93/343','250/343','436/343')
    for key in ['modern_exponent_kernel_implemented','fresh_HE',
                'independent_proof_review','numerical_security_qualification']:
        assert record[key] is False
    files = {p.relative_to(HERE).as_posix():binding(p) for p in sorted(HERE.rglob('*'))
             if p.is_file() and '__pycache__' not in p.parts and p.name!='verification.json'}
    result = dict(status='RATIONAL_MATRIX_EVIDENCE_READBACK_PASS',
                  checked_ring_coefficients=506112,checked_ring_matrices=49,
                  context_files=len(manifest['frozen_context']),files=files,
                  modern_exponent_kernel_implemented=False,fresh_HE=False,
                  independent_proof_review=False,numerical_security_qualification=False)
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='files'}))


if __name__ == '__main__':
    main()
