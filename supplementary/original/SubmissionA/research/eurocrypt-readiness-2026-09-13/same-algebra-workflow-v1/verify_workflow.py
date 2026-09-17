"""Platform-neutral readback of the new gates and optional completed campaign."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from math import isclose
from pathlib import Path
from statistics import median

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
EXPECTED='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
ORDER=['native','control','control','native','native','control']


def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())


def read(p):return json.loads(p.read_text())


def result_check(r,arm,mode,index):
    assert r['status']==('SAME_ALGEBRA_WORKFLOW_GATE_PASS' if mode=='gate' else 'SAME_ALGEBRA_WORKFLOW_WORKER_PASS')
    assert (r['arm'],r['mode'],r['index'])==(arm,mode,index)
    assert r['worker_threads']==1 and r['affinity']==[0]
    assert r['encrypted_execution'] and r['security_bits'] is None
    states=(57 if arm=='native' else 434) if mode=='gate' else 0
    assert r['phase_checked_states']==states and r['phase_checked_coefficients']==states*65536
    assert len(r['batches'])==(1 if mode=='gate' else 2)
    I,C,O,P,MB=(35,19,1,3,103) if arm=='native' else (346,86,88,262,692)
    assert r['material']['public_material_raw_bytes']==(391 if arm=='native' else 2)<<20
    for i,b in enumerate(r['batches']):
        assert b['index']==i and b['state']==('gate' if mode=='gate' else 'cold' if i==0 else 'warm')
        assert b['output_symbols']==4096 and b['output_sha256']==EXPECTED
        assert b['counts']==dict(fresh_encryptions=I,small_vectors=3*I,error_vectors=2*I,ciphertext_products=C)
        w=b['wire']
        assert (w['input_ciphertexts'],w['input_polynomials'],w['input_raw_bytes'])==(I,2*I,MB<<20)
        assert (w['output_ciphertexts'],w['output_polynomials'],w['output_raw_bytes'])==(O,P,P<<20)
        assert w['input_wire_bytes']>w['input_raw_bytes'] and w['output_wire_bytes']>w['output_raw_bytes']
        assert b['batch_wall_seconds']>=sum(b['seconds'].values())>0


def record(directory,filename,arm,mode,index,source,runtime):
    value=read(directory/filename)
    assert value['status']=='PASS' and value['worker_exit_code']==0
    assert value['error_type'] is None and value['termination_reason'] is None
    assert value['sources_unchanged'] and value['source_manifest']==source and value['runtime_manifest']==runtime
    assert value['result']['source_bindings_before']==value['result']['source_bindings_after']==source
    assert value['result']['runtime_bindings']==runtime
    for suffix in ('stdout','stderr'):
        path=directory/(filename.removesuffix('.json')+'.'+suffix+'.txt')
        assert binding(path)==value[suffix]
    assert value['stderr']['bytes']==0
    lines=[json.loads(line) for line in (directory/filename.replace('.json','.stdout.txt')).read_text().splitlines()]
    matches=[v['result'] for v in lines if v.get('event')=='result']
    assert matches==[value['result']]
    result_check(value['result'],arm,mode,index)
    return value['result']


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--gate',type=Path,default=HERE/'gate-v1')
    p.add_argument('--campaign',type=Path)
    args=p.parse_args()
    args.gate=args.gate.resolve()
    if args.campaign is not None:
        args.campaign=args.campaign.resolve()
    gate=read(args.gate/'gate.json')
    assert gate['status']=='SAME_ALGEBRA_WORKFLOW_BOTH_GATES_PASS'
    source,runtime=gate['source_manifest'],gate['runtime_manifest']
    for name,want in source.items():assert binding(ROOT/name)==want,name
    for name,want in gate['receipts'].items():assert binding(args.gate/name)==want
    gates=[record(args.gate,f'gate-{i:02d}-{arm}.json',arm,'gate',i,source,runtime) for i,arm in enumerate(('native','control'))]
    # Evidence-type guards: a gate cannot stand in for a measured campaign,
    # and a full-sized but mismatching recovered output is rejected.
    negatives=[]
    try:result_check(gates[0],'native','measure',0)
    except AssertionError:negatives.append('gate offered as measurement')
    tampered=deepcopy(gates[1]);tampered['batches'][0]['output_sha256']='0'*64
    try:result_check(tampered,'control','gate',1)
    except AssertionError:negatives.append('wrong recovered output')
    assert len(negatives)==2
    campaign=None;summary=None;ratios=None
    files=list(args.gate.glob('*.json'))+list(args.gate.glob('*.txt'))
    if args.campaign:
        host=read(HERE/'host-observation-v1.json')
        assert set(host)=={'wsl','windows'}
        for observation in host.values():
            assert observation['tool_exit_code']==0 and observation['workers']==[]
        campaign=read(args.campaign/'summary.json')
        assert campaign['status']=='SAME_ALGEBRA_CONTROLLED_WORKFLOW_CAMPAIGN_PASS'
        assert campaign['order']==ORDER and campaign['source_manifest']==source and campaign['runtime_manifest']==runtime
        assert campaign['gate']==binding(args.gate/'gate.json')
        for name,want in campaign['receipts'].items():assert binding(args.campaign/name)==want
        rows=[record(args.campaign,f'measure-{i:02d}-{arm}.json',arm,'measure',i,source,runtime) for i,arm in enumerate(ORDER)]
        summary=campaign['summary'];ratios=campaign['control_over_native_median_ratios']
        for arm in ('native','control'):
            selected=[r for r in rows if r['arm']==arm]
            actual=dict(setup=[r['setup_wall_seconds'] for r in selected],
                cold=[r['batches'][0]['batch_wall_seconds'] for r in selected],
                warm=[r['batches'][1]['batch_wall_seconds'] for r in selected],
                setup_plus_cold=[r['setup_wall_seconds']+r['batches'][0]['batch_wall_seconds'] for r in selected],
                warm_evaluation=[r['batches'][1]['seconds']['evaluation'] for r in selected],
                warm_encryption=[r['batches'][1]['seconds']['encryption'] for r in selected],
                peak_rss_MiB=[r['peak_rss_kib']/1024 for r in selected])
            for name,values in actual.items():
                assert summary[arm][name]==dict(samples=values,median=median(values),minimum=min(values),maximum=max(values))
        for name,value in ratios.items():assert isclose(value,summary['control'][name]['median']/summary['native'][name]['median'],rel_tol=1e-12)
        files+=list(args.campaign.glob('*.json'))+list(args.campaign.glob('*.txt'))
        files += [HERE/'check_host_workers.py',HERE/'host-observation-v1.json']
    files+=[HERE/'verify_workflow.py',HERE/'RESULTS.md',HERE/'REPRODUCE.md',HERE/'premature-campaign-negative.json']
    result=dict(status='SAME_ALGEBRA_WORKFLOW_CAMPAIGN_READBACK_PASS' if campaign else 'SAME_ALGEBRA_WORKFLOW_GATES_READBACK_PASS',
        source_bindings=source,recorded_runtime_bindings=runtime,
        files={p.relative_to(ROOT).as_posix():binding(p) for p in files},
        native_gate_states=57,native_gate_coefficients=3735552,control_gate_states=434,control_gate_coefficients=28442624,
        source_files=len(source),recorded_runtime_files=len(runtime),rejected_evidence=negatives,
        campaign_verified=bool(campaign),summary=summary,ratios=ratios,
        current_external_runtime_rehashed=False,new_he_execution=False,security_bits=None,
        scope='Recorded gate/campaign consistency and current repository source bindings; external runtime hashes were checked during actual workers, not rehashed by this portable reader.')
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('source_bindings','recorded_runtime_bindings','files','summary','ratios')}))


if __name__=='__main__':main()
