"""Read back and recompute finite hypothesis boundaries, without HE execution."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
    return json.loads(p.read_text(encoding='utf-8'))

run = read(HERE / 'execution.json')
assert run['returncode'] == 0 and run['sources_unchanged']
assert run['source_hashes_before'] == run['source_hashes_after']
for n, want in run['source_hashes_after'].items():
    assert digest(HERE / n) == want, n
for n, want in run['outputs'].items():
    assert digest(HERE / n) == want, n
spec = importlib.util.spec_from_file_location('ciphertext_length_boundaries', HERE / 'check_boundaries.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fresh = module.check()
assert fresh == read(HERE / 'boundary-check.json')
assert len(fresh['cases']) == 7 and fresh['pad_message_key_assignments'] == 87376
assert not fresh['new_he_execution'] and not fresh['toy_is_reusable_pke']
for item in read(HERE / 'retrieval.json'):
    assert item['status'] == 'DOWNLOADED'
    assert digest(HERE / item['file']) == item['sha256'], item['file']
    assert (HERE / item['file']).stat().st_size == item['bytes']
names = ('PLAN.md', 'PROOF.md', 'RESULTS.md', 'REPRODUCE.md', 'check_boundaries.py',
         'run_check.py', 'verify_records.py', 'boundary-check.json', 'execution.json',
         'check.stdout.txt', 'check.stderr.txt', 'retrieval.json')
out = {'status': 'CIPHERTEXT_LENGTH_BOUNDARIES_READBACK_PASS', 'widths': 7,
       'plain_code_cases': sum(1 << row['message_bits'] for row in fresh['cases']),
       'pad_message_key_assignments': 87376, 'new_he_execution': False,
       'new_timing_benchmark': False, 'new_security_assumption': False,
       'full_domain_correctness_and_privacy_required': True,
       'fused_preparation_and_joint_compression_covered_under_contract': True,
       'restricted_image_compression_excluded_from_length_implication': True,
       'unrestricted_runtime_separation_claimed': False,
       'files': {n: {'bytes': (HERE / n).stat().st_size, 'sha256': digest(HERE / n)} for n in names}}
(HERE / 'verification.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
print(json.dumps({k: v for k, v in out.items() if k != 'files'}))
