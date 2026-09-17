"""Read saved projection evidence; does not rerun algebra, HE or a proof checker."""
from pathlib import Path
from hashlib import sha256
import json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent


def binding(path):
    raw=path.read_bytes()
    return dict(bytes=len(raw),sha256=sha256(raw).hexdigest())


def main():
    a=json.loads((HERE/'check.json').read_text(encoding='utf-8'))
    ex=json.loads((HERE/'execution.json').read_text(encoding='utf-8'))
    assert ex['actual_exit_code']==0
    assert not (HERE/'check.stderr.txt').read_bytes()
    assert a['status']=='COEFFICIENT_PROJECTION_CHECK_PASS'
    for name,want in a['source_bindings'].items():
        assert binding(ROOT/name)==want,name
    expected=[(2,1,1),(3,2,2),(4,4,3),(5,7,5),(6,10,7),(7,13,9),
              (8,17,11),(10,27,16),(12,40,23),(16,69,39),(24,155,81),(32,273,143)]
    assert [(x['length'],x['centered_ring_dimension'],x['scalar_dimension']) for x in a['results']]==expected
    for row in a['results']:
        length=row['length']
        ring=sum(max(0,length-2*i+i.bit_count()) for i in range(1,length+1))
        assert row['centered_ring_dimension']==row['newton_basis_functions']==ring
        assert row['projection_kernel_dimension']==ring-row['scalar_dimension']
        assert (row['exhaustive'] is not None)==(length<=8)
    assert a['family_difference']['E2_output']==0 and a['family_difference']['T3_output']==384
    assert not any(a[k] for k in ('new_he_execution','new_security_execution',
                                 'exact_general_scalar_rank_proved','novelty_established'))
    truth=[x['exhaustive'] for x in a['results'] if x['exhaustive']]
    files={p.relative_to(HERE).as_posix():binding(p) for p in sorted(HERE.rglob('*'))
           if p.is_file() and '__pycache__' not in p.parts and p.name!='verification.json'}
    out=dict(status='COEFFICIENT_PROJECTION_READBACK_PASS',source_files=len(a['source_bindings']),
             symbolic_cases=len(a['results']),exhaustive_cases=len(truth),
             coefficient_values=sum(x['coefficient_values'] for x in truth),
             valuation_values=sum(x['valuation_values'] for x in truth),
             new_he_execution=False,independent_proof_review=False,novelty_established=False,
             exact_general_scalar_rank_proved=False,files=files)
    (HERE/'verification.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in out.items() if k!='files'}))


if __name__=='__main__':
    main()
