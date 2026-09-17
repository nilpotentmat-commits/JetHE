"""Read back public finite-ring evidence; does not execute HE or verify a proof."""
from pathlib import Path
from hashlib import sha256
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]


def binding(p):
    b=p.read_bytes()
    return dict(bytes=len(b),sha256=sha256(b).hexdigest())


def main():
    a=json.loads((HERE/'check.json').read_text(encoding='utf-8'))
    ex=json.loads((HERE/'execution.json').read_text(encoding='utf-8'))
    assert a['status']=='MIXED_IDEAL_BOUNDARY_PUBLIC_CHECK_PASS'
    assert ex['actual_exit_code']==0 and not ex['new_he_execution']
    for c in ('stdout','stderr'):
        assert binding(HERE/f'check.{c}.txt')['sha256']==ex[f'{c}_sha256']
    assert not (HERE/'check.stderr.txt').read_bytes()
    for n,want in a['source_bindings'].items():assert binding(ROOT/n)==want,n
    assert len(a['exhaustive'])==6 and len(a['circuits'])==24 and len(a['witnesses'])==24
    assert a['exhaustive_gate_quads']==sum(x['gate_quads'] for x in a['exhaustive'])==415042
    assert a['sampled_gate_quads']==sum(x['gate_quads'] for x in a['circuits'])==69120
    assert a['automorphism_law_checks']==2160 and a['unit_linear_inner_witnesses']==18
    assert a['horner_input_pairs']==sum(x['input_pairs'] for x in a['horner'])==1526
    for x in a['horner']:
        assert x['private_products']==x['length']-1
        assert x['outer_carriers']==x['length'] and x['inner_carriers']==1
    for x in a['witnesses']:
        assert x['raw_mixed_zero_required'] and x['coefficient_preparation_escapes'] and x['nonlinear_relay_escapes']
    assert not any(a[k] for k in ('new_he_execution','new_timing_comparison','arbitrary_he_impossibility',
                                 'arbitrary_preparation_lower_bound','independent_proof_review'))
    archive=json.loads((HERE/'initial-check/manifest.json').read_text(encoding='utf-8'))
    for n,want in archive['files'].items():assert binding(HERE/'initial-check'/n)==want,n
    files={p.relative_to(HERE).as_posix():binding(p) for p in sorted(HERE.rglob('*'))
           if p.is_file() and '__pycache__' not in p.parts and p.relative_to(HERE).as_posix()!='verification.json'}
    out=dict(status='MIXED_IDEAL_BOUNDARY_READBACK_PASS',source_files=len(a['source_bindings']),
             exhaustive_gate_quads=415042,sampled_gate_quads=69120,automorphism_law_checks=2160,
             raw_witnesses=24,unit_linear_inner_witnesses=18,horner_input_pairs=1526,
             additive_recovery_allowed=True,arbitrary_preparation_lower_bound=False,
             arbitrary_he_impossibility=False,new_he_execution=False,independent_proof_review=False,
             security_bits=None,files=files)
    (HERE/'verification.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in out.items() if k!='files'}))


if __name__=='__main__':main()
