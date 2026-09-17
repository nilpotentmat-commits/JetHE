"""Recorded public-algebra readback; no encryption or proof verification."""
from pathlib import Path
from hashlib import sha256
import json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]


def binding(path):
    raw=path.read_bytes()
    return dict(bytes=len(raw),sha256=sha256(raw).hexdigest())


def main():
    a=json.loads((HERE/'check.json').read_text(encoding='utf-8'))
    ex=json.loads((HERE/'execution.json').read_text(encoding='utf-8'))
    assert ex['actual_exit_code']==0 and not ex['new_he_execution']
    for channel in ('stdout','stderr'):
        assert binding(HERE/f'check.{channel}.txt')['sha256']==ex[f'{channel}_sha256']
    assert not (HERE/'check.stderr.txt').read_bytes()
    assert a['status']=='PAID_HASSE_PORTABILITY_PUBLIC_ALGEBRA_PASS'
    for name,want in a['source_bindings'].items():assert binding(ROOT/name)==want,name
    assert len(a['cases'])==72 and len(a['ledger'])==210
    expected=[(l,q,1<<j,f) for l in (2,4,8) for q in (17,97,315,65537)
              for j in range(l.bit_length()-1) for f in range(3)]
    assert [(x['length'],x['q'],x['order'],x['fixture']) for x in a['cases']]==expected
    for x in a['cases']:
        assert x['naive_map_counterexample'] and [v['paid'] for v in x['variants']]==[False,True]
        for arm in x['variants']:
            assert arm['max_noise']<=arm['bound']
            assert arm['rows']==x['gadget_length']*(x['order']+1 if arm['paid'] else 2*x['order'])
    for name,want in [('phase_coefficients',8160),('converted_component_coefficients',6528),('raw_product_coefficients',4896)]:
        assert a[name]==sum(x[name if name!='converted_component_coefficients' else 'converted_components'] for x in a['cases'])==want
    for x in a['ledger']:
        d,k=x['d'],x['k'];tau=d-k;e=1<<tau;g=d+1
        assert x['reference_rows']==g*(2*e+3*tau)
        assert x['paid_rows']==g*(e+1+4*tau)
    for Q,q in a['modulus_projection_cases']:assert Q%q==0 and ((Q-1)//2)%q==(q-1)//2
    assert not any(a[k] for k in ('new_he_execution','new_timing','independent_implementation',
                                 'ordinary_bfv_multiplication_identified','mathematical_proof_verified_by_program'))
    assert a['security_bits'] is None
    boundary=json.loads((HERE/'boundary-check.json').read_text(encoding='utf-8'))
    bx=json.loads((HERE/'boundary-execution.json').read_text(encoding='utf-8'))
    assert bx['actual_exit_code']==0 and not (HERE/'boundary.stderr.txt').read_bytes()
    for channel in ('stdout','stderr'):
        assert binding(HERE/f'boundary.{channel}.txt')['sha256']==bx[f'{channel}_sha256']
    for name,want in boundary['source_bindings'].items():assert binding(ROOT/name)==want,name
    assert boundary['status']=='PLAINTEXT_ARITHMETIC_INTERFACE_BOUNDARY_PASS'
    assert len(boundary['cases'])==10 and boundary['gate_pairs']==160000
    assert boundary['sampled_composition_pairs']==2000 and boundary['exhaustive_composition_pairs']==10272
    assert not any(boundary[k] for k in ('new_he_execution','full_composition_impossibility_claimed',
                                       'arbitrary_ciphertext_lower_bound','mathematical_proof_verified_by_program'))
    files={p.relative_to(HERE).as_posix():binding(p) for p in sorted(HERE.rglob('*'))
           if p.is_file() and '__pycache__' not in p.parts and p.name!='verification.json'}
    out=dict(status='PAID_HASSE_PORTABILITY_READBACK_PASS',source_files=len(a['source_bindings']),
             boundary_source_files=len(boundary['source_bindings']),boundary_cases=10,
             boundary_gate_pairs=160000,sampled_composition_pairs=2000,exhaustive_composition_pairs=10272,
             public_cases=72,transport_variants=144,ledger_cases=210,projection_cases=len(a['modulus_projection_cases']),
             phase_coefficients=8160,converted_component_coefficients=6528,raw_product_coefficients=4896,
             new_he_execution=False,independent_implementation=False,independent_proof_review=False,
             ordinary_bfv_multiplication_identified=False,security_bits=None,files=files)
    (HERE/'verification.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in out.items() if k!='files'}))


if __name__=='__main__':main()
