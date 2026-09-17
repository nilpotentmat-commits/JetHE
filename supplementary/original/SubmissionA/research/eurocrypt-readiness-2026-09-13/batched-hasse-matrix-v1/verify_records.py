"""Validate recorded bindings and ledgers; does not rerun algebra or HE."""
from pathlib import Path
from hashlib import sha256
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]


def binding(path):
    data=path.read_bytes()
    return dict(bytes=len(data),sha256=sha256(data).hexdigest())


def main():
    audit=json.loads((HERE/'audit.json').read_text(encoding='utf8'))
    receipt=json.loads((HERE/'execution.json').read_text(encoding='utf8'))
    assert receipt['actual_exit_code']==0 and not receipt['new_he_execution']
    for name in ('stdout','stderr'):
        raw=(HERE/f'check.{name}.txt').read_bytes()
        assert sha256(raw).hexdigest()==receipt[f'{name}_sha256']
        if name=='stderr':
            assert not raw
    # Read the original mathematical context at its exact recorded bytes.
    # Executable inputs and all other bindings still resolve to their old paths.
    context='SubmissionA/research/eurocrypt-readiness-2026-09-13/manuscript/sections/prepared-composition.tex'
    archived=context.replace('/manuscript/','/checkpoint-v38/manuscript/')
    for name,expected in audit['source_bindings'].items():
        assert binding(ROOT/(archived if name==context else name))==expected,name
    assert not any(audit[x] for x in ('new_he_execution','performance_benchmark',
                                     'proof_verified_by_program','security_bits_assigned'))
    old=HERE/'initial-digit-failure'
    failure=json.loads((old/'execution.json').read_text(encoding='utf8'))
    assert failure['actual_exit_code']==1
    assert b'AssertionError' in (old/'check.stderr.txt').read_bytes()
    for name in ('stdout','stderr'):
        assert sha256((old/f'check.{name}.txt').read_bytes()).hexdigest()==failure[f'{name}_sha256']
    total=0
    for row in audit['algebra_cases']:
        e,g,B=row['e'],row['gadget'],row['batches']
        power=7**(e.bit_length()-1); blocks=2*g*((B+e-1)//e)
        assert row['multiplies']==blocks*power
        assert row['additions']==blocks*(6*(power-e*e)+e*e)
        assert row['coefficients_compared']==2*B*row['L']*(row['p']-1)
        total+=row['coefficients_compared']
    assert total==audit['algebra_coefficients_compared']==6720
    assert sum(x['retained_states'] for x in audit['trace_cases'])==88
    assert sum(x['coefficients_compared'] for x in audit['trace_cases'])==4992
    for row in audit['ledger_cases']:
        tau,k,g,B=row['tail'],row['prefix'],row['gadget'],row['batches']
        E=1<<tau; M=(1<<k)-1; H=g*(2*E+3*tau)
        direct=H+2*tau+2+B*(7*M+5*tau+2*H+3)
        assert row['full_ring_products_remaining']+row['full_ring_products_removed']==direct
        assert row['full_ring_products_removed']==4*B*g*(E-1)
        assert row['source_rows']==(2*g if tau==0 else max(3*g,E*g+1))
        assert row['threshold_met']==(B>=E)
    extras=[HERE/x for x in ('audit.json','execution.json','check.stdout.txt','check.stderr.txt',
                             'RESULTS.md','verify_records.py')]
    extras+=sorted(old.iterdir())
    result=dict(status='RECORDED_PUBLIC_AUDIT_READBACK_PASS',source_files=len(audit['source_bindings']),
                historical_manuscript_context={context:archived},
                extra_bindings={p.relative_to(HERE).as_posix():binding(p) for p in extras},
                algebra_cases=len(audit['algebra_cases']),ledger_cases=len(audit['ledger_cases']),
                failed_first_run_preserved=True,new_he_execution=False,
                independent_mathematical_proof_review=False)
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k!='extra_bindings'},indent=2))


if __name__=='__main__':
    main()
