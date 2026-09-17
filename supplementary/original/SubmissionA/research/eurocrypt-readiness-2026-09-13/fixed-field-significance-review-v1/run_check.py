"""Capture the actual child exit and bind proof/checker inputs before and after."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

here = Path(__file__).resolve().parent
names = ('FAST_WORK_PROOF.md', 'check_arithmetic.py', 'run_check.py')
def bindings():
    return {n: hashlib.sha256((here / n).read_bytes()).hexdigest() for n in names}
before = bindings()
run = subprocess.run([sys.executable, '-B', str(here / 'check_arithmetic.py')], capture_output=True)
(here / 'check.stdout.txt').write_bytes(run.stdout)
(here / 'check.stderr.txt').write_bytes(run.stderr)
after = bindings()
record = {'returncode': run.returncode, 'source_hashes_before': before,
          'source_hashes_after': after, 'sources_unchanged': before == after,
          'new_he_execution': False, 'timing_benchmark': False}
record['outputs'] = {n: hashlib.sha256((here / n).read_bytes()).hexdigest()
                     for n in ('check.stdout.txt', 'check.stderr.txt', 'arithmetic-check.json')
                     if (here / n).exists()}
(here / 'execution.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
print(run.stdout.decode('utf-8', errors='replace').strip())
print(json.dumps({'returncode': run.returncode, 'sources_unchanged': before == after}))
if run.stderr:
    print(run.stderr.decode('utf-8', errors='replace'), file=sys.stderr)
assert before == after
sys.exit(run.returncode)
