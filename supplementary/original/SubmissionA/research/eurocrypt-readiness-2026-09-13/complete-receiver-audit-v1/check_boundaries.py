"""Exercise actual missing/preflight records; never synthesize a full HE pass."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RUNNER = HERE.parent/'compiled-receiver-v1'


def bind(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=sha256(raw).hexdigest())


def main():
    missing = '__audit_missing_record__'
    assert not (RUNNER/missing).exists()
    assert json.loads((RUNNER/'preflight-v1/execution.json').read_text())['mode'] == 'preflight'
    paths = [HERE/x for x in ('check_boundaries.py', 'check_complete.py', 'contract.json')]
    paths.append(RUNNER/'preflight-v1/execution.json')
    before = {p.relative_to(ROOT).as_posix(): bind(p) for p in paths}
    verification = HERE/'verification.json'
    previous = bind(verification) if verification.exists() else None
    cases = []
    for name, expected in ((missing, 2), ('preflight-v1', 1)):
        run = subprocess.run([sys.executable, '-B', str(HERE/'check_complete.py'), '--verify', name],
                             capture_output=True)
        assert run.returncode == expected, (name, run.returncode, run.stdout, run.stderr)
        if expected == 2:
            report = json.loads(run.stdout)
            assert report['status'] == 'FINAL_EXECUTION_RECORD_UNAVAILABLE'
            assert report['complete_execution_verified'] is False
        else:
            assert b"receipt['status'] == 'COMPLETE_CONVENTIONAL_GRAPH_EXECUTION_PASS'" in run.stderr
        assert (bind(verification) if verification.exists() else None) == previous
        cases.append(dict(input=name, python_returncode=run.returncode,
                          stdout_sha256=sha256(run.stdout).hexdigest(),
                          stderr_sha256=sha256(run.stderr).hexdigest(),
                          new_complete_receipt_written=False))
    assert before == {p.relative_to(ROOT).as_posix(): bind(p) for p in paths}
    result = dict(status='MISSING_AND_PREFLIGHT_RECORD_BOUNDARIES_PASS', cases=cases, bindings=before,
                  new_he_execution=False, complete_execution_verified=False,
                  scope='Two actual negative acceptance cases. No synthetic full record or liveness assertion.')
    (HERE/'boundary-checks.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'bindings'}, indent=2))


if __name__ == '__main__':
    main()
