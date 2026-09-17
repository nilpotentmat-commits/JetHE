"""Capture the actual checker exit and immutable executed inputs."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
def hashes():
    return {n: hashlib.sha256((HERE / n).read_bytes()).hexdigest()
            for n in ('PROOF.md', 'check_boundaries.py', 'run_check.py')}
before = hashes()
run = subprocess.run([sys.executable, '-B', str(HERE / 'check_boundaries.py')], capture_output=True)
(HERE / 'check.stdout.txt').write_bytes(run.stdout)
(HERE / 'check.stderr.txt').write_bytes(run.stderr)
after = hashes()
out = {'returncode': run.returncode, 'source_hashes_before': before,
       'source_hashes_after': after, 'sources_unchanged': before == after,
       'new_he_execution': False, 'new_timing_benchmark': False,
       'outputs': {n: hashlib.sha256((HERE / n).read_bytes()).hexdigest()
                   for n in ('boundary-check.json', 'check.stdout.txt', 'check.stderr.txt')
                   if (HERE / n).exists()}}
(HERE / 'execution.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
print(run.stdout.decode('utf-8', errors='replace').strip())
print(json.dumps({'returncode': run.returncode, 'sources_unchanged': before == after}))
if run.stderr:
    print(run.stderr.decode('utf-8', errors='replace'), file=sys.stderr)
assert before == after
sys.exit(run.returncode)
