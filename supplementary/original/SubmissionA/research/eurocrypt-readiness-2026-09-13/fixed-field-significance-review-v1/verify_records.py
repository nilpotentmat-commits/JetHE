"""Read back the frozen run and recheck public algebra without new HE execution."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
    return json.loads(p.read_text(encoding='utf-8'))

record = read(HERE / 'execution.json')
assert record['returncode'] == 0 and record['sources_unchanged']
assert record['source_hashes_before'] == record['source_hashes_after']
for name, want in record['source_hashes_after'].items():
    assert digest(HERE / name) == want, name
for name, want in record['outputs'].items():
    assert digest(HERE / name) == want, name
spec = importlib.util.spec_from_file_location('jethe_exact_arithmetic', HERE / 'check_arithmetic.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fresh = module.check()
assert fresh == read(HERE / 'arithmetic-check.json')
assert len(fresh['ring_cases']) == 24 and len(fresh['jet_cases']) == 40
assert len(fresh['carlitz_cases']) == 6 and fresh['field_irreducibility_checked']
assert not fresh['new_he_execution'] and not fresh['timing_benchmark']
for item in read(HERE / 'retrieval.json'):
    assert item['status'] == 'DOWNLOADED'
    assert digest(HERE / item['file']) == item['sha256'], item['file']
    assert (HERE / item['file']).stat().st_size == item['bytes']
names = ('PLAN.md', 'FAST_WORK_PROOF.md', 'RESULTS.md', 'REPRODUCE.md',
         'check_arithmetic.py', 'run_check.py', 'verify_records.py',
         'execution.json', 'arithmetic-check.json', 'check.stdout.txt', 'check.stderr.txt',
         'retrieval.json')
result = {'status': 'FAST_EXACT_ARITHMETIC_READBACK_PASS',
          'ring_cases': 24, 'jet_cases': 40, 'carlitz_cases': 6,
          'new_he_execution': False, 'timing_benchmark': False,
          'unrestricted_runtime_separation_claimed': False,
          'explicit_materialization_model_required': True,
          'files': {n: {'bytes': (HERE / n).stat().st_size, 'sha256': digest(HERE / n)} for n in names}}
(HERE / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps({k: v for k, v in result.items() if k != 'files'}))
