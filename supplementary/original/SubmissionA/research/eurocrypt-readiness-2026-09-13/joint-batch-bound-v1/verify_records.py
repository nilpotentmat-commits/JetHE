"""Recorded algebra readback; no new execution or proof certification."""
from pathlib import Path
from hashlib import sha256
import json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]


def binding(p):
    data=p.read_bytes();return dict(bytes=len(data),sha256=sha256(data).hexdigest())


def main():
    a=json.loads((HERE/'check.json').read_text(encoding='utf8'))
    ex=json.loads((HERE/'execution.json').read_text(encoding='utf8'))
    assert ex['actual_exit_code']==0 and not ex['new_he_execution']
    assert a['status']=='JOINT_BATCH_FUNCTION_CHECKS_PASS'
    for name in ('stdout','stderr'):assert binding(HERE/f'check.{name}.txt')['sha256']==ex[f'{name}_sha256']
    assert not (HERE/'check.stderr.txt').read_bytes()
    for name,want in a['source_bindings'].items():assert binding(ROOT/name)==want,name
    assert [(x['length'],x['batches']) for x in a['rank_cases']]==[(l,b) for l in (8,16,32,64) for b in (1,2,3,5)]
    for row in a['rank_cases']:
        l,b=row['length'],row['batches'];c=(5*l*l+4*l*l.bit_length())//64
        assert row['one_block_witness']==row['diagonal_promise_rank']==c
        assert row['joint_rank']==b*c and row['uncentered_constants_rank']==1
    assert len(a['mixed_cases'])==8 and len(a['count_cases'])==12
    assert a['total_joint_witnesses']==sum(x['joint_rank'] for x in a['rank_cases'])==5192
    assert a['mixed_recovered_bit_values']==sum(x['recovered_bit_values'] for x in a['mixed_cases'])==6144
    for row in a['mixed_cases']:assert row['generator_rank']<=row['centered_generators'] and row['target_functions']==48
    for row in a['count_cases']:
        l,b=row['length'],row['batches'];c=(5*l*l+4*l*l.bit_length())//64
        assert row['inner_width']==16*b*c and row['capacity']==256*l
        assert row['mixed_calls']==(b*c+32*l-1)//(32*l)
        assert row['inner_carriers']==(b*c+16*l-1)//(16*l)
        assert row['outer_carriers']==(b*(l-1)+l-1)//l
    assert not any(a[k] for k in ('new_he_execution','new_timing','new_security_attack','mathematical_proof_verified_by_program'))
    assert a['security_bits'] is None
    files={p.name:binding(p) for p in HERE.iterdir() if p.is_file() and p.name!='verification.json'}
    out=dict(status='JOINT_BATCH_BOUND_READBACK_PASS',source_files=len(a['source_bindings']),rank_cases=16,
             mixed_cases=8,count_cases=12,joint_witnesses=5192,mixed_bit_values=6144,
             independent_proof_review=False,new_he_execution=False,security_bits=None,files=files)
    (HERE/'verification.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in out.items() if k!='files'},indent=2))


if __name__=='__main__':main()
