"""Recorded-evidence readback only; no new encryption or security estimate."""
from hashlib import sha256
import json
from math import prod,isclose
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
sys.path.insert(0,str(HERE))
from admission import binding, bindings, N, KAPPA, F, BRAW, Q


def load_record(directory,full):
    record=json.loads((directory/'run.json').read_text())
    assert record['mode']==('full' if full else 'preflight')
    assert record['status']==('SAME_ALGEBRA_TERMINAL_FULL_FUNCTIONAL_PASS' if full else 'SAME_ALGEBRA_TERMINAL_PREFLIGHT_PASS')
    assert record['bindings_before']==record['bindings_after']
    for relative,value in record['bindings_after'].items():assert binding(ROOT/relative)==value,relative
    C=86 if full else 1
    I=4*C+2
    assert record['counts']==dict(public_polynomials=2,public_ciphertexts=1,
        input_polynomials=2*I,input_ciphertexts=I,phase_coefficients=N*(I+C+2),
        ciphertext_products=C,output_polynomials=3*C+4,output_ciphertexts=C+2)
    assert record['source_vectors']==3*I+2 and record['error_vectors']==2*I+1
    assert record['native_dimension']==N and int(record['q'])==Q
    assert record['jobs']==16 and record['length']==(256 if full else 4)
    assert record['scalar_pairs']==(175776 if full else 48)
    assert record['raw_payload_bytes']==dict(public=2<<20,input=(2*I)<<20,output=(3*C+4)<<20)
    assert all(record['serialized_payload_bytes'][name]>value for name,value in record['raw_payload_bytes'].items())
    raw=(directory/'recovered.bin').read_bytes()
    assert len(raw)==2*16*record['length']
    assert sha256(raw).hexdigest()==record['recovered_sha256']
    if full:
        assert raw==(HERE.parent/'compiled-receiver-v1/expected.bin').read_bytes()
        assert record['recovered_sha256']=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
    assert record['missing_outer_correction_failures']>0 and record['missing_inner_correction_failures']>0
    assert isclose(record['complete_workflow_phase_seconds'],sum(v for k,v in record['phases'].items() if k!='private_diagnostics'),rel_tol=1e-12)
    assert record['instrumented_wall_seconds']>=record['complete_workflow_phase_seconds']
    assert record['encrypted_execution'] and not record['matched_benchmark'] and record['security_bits'] is None
    assert record['environment']['address_space_limit']==2<<30 and record['environment']['threads']==1
    assert record['peak_rss_kib']<2<<20
    events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    assert events[-1]['stage']=='complete' and events[-1]['status']==record['status']
    assert events[-1]['counts']==record['counts']
    assert all(a['wall_seconds']<=b['wall_seconds'] for a,b in zip(events,events[1:]))
    return record


def main():
    admission=json.loads((HERE/'admission.json').read_text())
    assert admission['status']=='SAME_ALGEBRA_TERMINAL_ADMISSION_CHECKS_PASS'
    assert admission['bindings_before']==admission['bindings_after']==bindings()
    assert Q>2+4*BRAW and F==(2*KAPPA+1)*20
    assert int(admission['q'])==Q and int(admission['raw_bound'])==BRAW
    assert int(admission['correctness_margin'])==Q-2-4*BRAW
    assert admission['interpolation']['independent_evaluation_coordinates']==17036
    preflight=load_record(HERE/'preflight-v1',False)
    full=load_record(HERE/'full-v1',True)
    rejected=[]
    try:load_record(HERE/'missing-record-negative',True)
    except FileNotFoundError:rejected.append('missing record')
    try:load_record(HERE/'preflight-v1',True)
    except AssertionError:rejected.append('preflight as full')
    assert len(rejected)==2
    files=[HERE/x for x in ('verify_receiver.py','admission.json','RESULTS.md','REPRODUCE.md')]
    files += [HERE/m/x for m in ('preflight-v1','full-v1') for x in ('run.json','events.jsonl','recovered.bin')]
    result=dict(status='SAME_ALGEBRA_TERMINAL_RECORDED_EXECUTION_CHECKS_PASS',
        files={p.relative_to(ROOT).as_posix():binding(p) for p in files},
        execution_bindings=full['bindings_after'],preflight_phase_coefficients=preflight['counts']['phase_coefficients'],
        full_phase_coefficients=full['counts']['phase_coefficients'],full_inputs=346,full_products=86,full_outputs=88,
        full_source_vectors=1040,full_recovered_symbols=4096,full_payload_bytes=full['raw_payload_bytes'],
        recorded_workflow_phase_seconds=full['complete_workflow_phase_seconds'],
        rejected_incomplete_records=rejected,new_he_execution=False,performance_comparison=False,security_bits=None)
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('files','execution_bindings')}))


if __name__=='__main__':main()
