"""Serial, source-bound current-native/control gates and measurements."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
from statistics import median
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
READY = HERE.parent
ROOT = HERE.parents[3]
FIXED = READY/'native-fixed-multipliers-v1'
ORDER = ('native','control','control','native','native','control','control','native')
THREADS = ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS')
LIMITS = dict(address_space_bytes=2<<30, cpu_seconds=900, wall_seconds=960)
EXPECTED = 'd22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'

def read(p): return json.loads(p.read_text())
def binding(p): return dict(bytes=p.stat().st_size, sha256=sha256(p.read_bytes()).hexdigest())
def save(p, value):
    with p.open('x') as f: json.dump(value, f, indent=2); f.write('\n')

def imports():
    spec=importlib.util.spec_from_file_location('frozen_fixed_driver',FIXED/'run.py')
    driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
    common,NativeWorker=driver.imports()
    from adapter import CurrentControlWorker
    return driver,common,NativeWorker,CurrentControlWorker

def manifest(driver,common):
    values=driver.manifest(common)
    paths=[HERE/n for n in ('PLAN.md','PROOF.md','adapter.py','run.py','preflight.py')]
    paths += [READY/n for n in ('same-algebra-one-prime-v1/PROOF.md','same-algebra-source-alignment-v1/PROOF.md','native-stage-gadgets-v1/PROOF.md')]
    for p in paths: values[p.relative_to(ROOT).as_posix()]=binding(p)
    return values

def admission(common):
    common.verify_admission()
    from bounds import trace_spec, PRIMES
    a=read(READY/'native-stage-gadgets-v1/admission.json')
    assert a['common_sufficient_source']=='q3/37'
    assert a['incoming_rows']==[1,8,37,12,16,9,10,9,5]
    assert a['two_batch_source_gap_factor']==158
    assert len(a['trace'])==len(trace_spec())==22
    for actual,(n,k,l,c,b) in zip(a['trace'],trace_spec()):
        assert (actual['state'],actual['key'],actual['limbs'],actual['components'],int(actual['error_bound']))==(n,k,l,c,b)
    for name,want in a['bindings'].items(): assert binding(ROOT/name)==want,name
    assert common.Q==PRIMES[0]

def validate(r,mode,arm,index):
    assert r['status']=='CURRENT_CONTROL_'+('GATE_PASS' if mode=='gate' else 'MEASUREMENT_PASS')
    assert (r['mode'],r['arm'],r['index'])==(mode,arm,index)
    assert r['profile_version']=='current-control-workflow-v1'
    assert r['terminal_limbs']==(2 if arm=='native' else 1)
    assert r['worker_threads']==1 and r['affinity']==[0]
    states=(57 if arm=='native' else 434) if mode=='gate' else 0
    assert r['phase_checked_states']==states and r['phase_checked_coefficients']==65536*states
    m=r['material'];native=arm=='native'
    assert [m[k] for k in ('independent_secrets','public_keys','evaluation_rows','setup_error_vectors')]==([9,5,102,107] if native else [1,1,0,1])
    assert m['public_material_raw_bytes']==(297 if native else 1)<<20
    assert m['public_material_serialized_bytes']>m['public_material_raw_bytes']
    assert r['setup_wall_seconds']>=sum(r['setup_seconds'].values())>0
    assert r['encrypted_execution'] and r['security_bits'] is None
    assert len(r['batches'])==(1 if mode=='gate' else 2)
    for i,b in enumerate(r['batches']):
        assert b['index']==i and b['state']==('gate' if mode=='gate' else 'cold' if i==0 else 'warm')
        assert b['output_symbols']==4096 and b['output_sha256']==EXPECTED
        assert b['counts']==(dict(fresh_encryptions=35,small_vectors=105,error_vectors=70,ciphertext_products=19) if native else dict(fresh_encryptions=346,small_vectors=1038,error_vectors=692,ciphertext_products=86))
        assert b['wire']['input_raw_bytes']==(103 if native else 346)<<20
        assert b['wire']['output_raw_bytes']==(3 if native else 131)<<20
        assert b['batch_wall_seconds']>=sum(b['seconds'].values())>0
        for kind in ('input','output'): assert b['wire'][kind+'_wire_bytes']>b['wire'][kind+'_raw_bytes']

def child(args):
    import resource
    resource.setrlimit(resource.RLIMIT_AS,(LIMITS['address_space_bytes'],)*2)
    resource.setrlimit(resource.RLIMIT_CPU,(LIMITS['cpu_seconds'],)*2)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.sched_setaffinity(0,{0})
    assert all(os.environ.get(k)=='1' for k in THREADS)
    driver,common,Native,Control=imports()
    frozen=manifest(driver,common);libraries=driver.runtime(common)
    admission(common)
    worker=Native(args.mode,'fixed',args.index) if args.arm=='native' else Control(args.mode,'control',args.index)
    try:
        r=worker.run()
        assert Path(worker.ring.dll._name).resolve()==FIXED/'build/fixed_core.so'
        r.update(status='CURRENT_CONTROL_'+('GATE_PASS' if args.mode=='gate' else 'MEASUREMENT_PASS'),profile_version='current-control-workflow-v1',arithmetic_library=binding(FIXED/'build/fixed_core.so'))
        validate(r,args.mode,args.arm,args.index)
        assert manifest(driver,common)==frozen and driver.runtime(common)==libraries
        r.update(source_bindings=frozen,runtime_bindings=libraries,resource_limits=LIMITS)
        print(json.dumps(dict(event='current_control_result',result=r)),flush=True)
    finally:
        if worker.ring: worker.ring.close()

def sample(args,out,arm,index,driver,common,frozen,libraries):
    command=[sys.executable,'-B','-u',str(Path(__file__).resolve()),'--child','--mode',args.mode,'--arm',arm,'--index',str(index)]
    env=os.environ.copy();env.update({k:'1' for k in THREADS})
    start=time.monotonic()
    proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
    termination=None
    try: stdout,stderr=proc.communicate(timeout=LIMITS['wall_seconds'])
    except subprocess.TimeoutExpired:
        termination='wall limit';os.killpg(proc.pid,signal.SIGKILL);stdout,stderr=proc.communicate()
    stem=f'{index:02d}-{arm}'
    (out/(stem+'.stdout.txt')).write_bytes(stdout);(out/(stem+'.stderr.txt')).write_bytes(stderr)
    result=None;error=None
    try:
        assert proc.returncode==0 and not stderr and termination is None
        values=[json.loads(x) for x in stdout.decode().splitlines()]
        found=[x['result'] for x in values if x.get('event')=='current_control_result']
        assert len(found)==1
        result=found[0];validate(result,args.mode,arm,index)
        assert result['source_bindings']==frozen and result['runtime_bindings']==libraries
        assert manifest(driver,common)==frozen and driver.runtime(common)==libraries
    except Exception as exc: error=type(exc).__name__+': '+str(exc)
    record=dict(status='PASS' if error is None else 'FAIL',worker_exit_code=proc.returncode,termination=termination,error=error,command=command,elapsed_seconds=time.monotonic()-start,result=result,stdout=binding(out/(stem+'.stdout.txt')),stderr=binding(out/(stem+'.stderr.txt')))
    save(out/(stem+'.json'),record)
    print(json.dumps(dict(index=index,arm=arm,status=record['status'],worker_exit_code=proc.returncode)),flush=True)
    assert error is None,stem
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--child',action='store_true')
    p.add_argument('--mode',choices=('gate','measure'),required=True)
    p.add_argument('--arm',choices=('native','control'));p.add_argument('--index',type=int)
    p.add_argument('--out',type=Path);p.add_argument('--gate',type=Path);p.add_argument('--host-observation',type=Path)
    args=p.parse_args()
    if args.child: child(args);return
    assert args.out and not args.out.exists()
    out=args.out.resolve();assert out.parent==HERE
    driver,common,_,_=imports();frozen=manifest(driver,common);libraries=driver.runtime(common)
    pre=read(HERE/'preflight.json');assert pre['status']=='CURRENT_CONTROL_PREFLIGHT_PASS'
    assert pre['source_manifest']==frozen and pre['runtime_manifest']==libraries
    gate=host=None
    if args.mode=='measure':
        assert args.gate and args.host_observation
        gate=read(args.gate/'summary.json');assert gate['status']=='CURRENT_CONTROL_BOTH_FRESH_GATES_PASS'
        assert gate['source_manifest']==frozen and gate['runtime_manifest']==libraries
        for name,want in gate['files'].items(): assert binding(args.gate/name)==want,name
        host=read(args.host_observation);assert set(host)=={'windows','wsl'}
        for h in host.values():
            assert h['workers']==[] and h['tool_exit_code']==0
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(h['recorded_utc'])).total_seconds()
            assert 0<=age<=300,'Stale worker observation'
    out.mkdir()
    start=datetime.now(timezone.utc).isoformat()
    save(out/'frozen.json',dict(started_utc=start,source_manifest=frozen,runtime_manifest=libraries,preflight=binding(HERE/'preflight.json'),order=('native','control') if args.mode=='gate' else ORDER,limits=LIMITS,interpreter=sys.version,executable=binding(Path(sys.executable)),host=host))
    order=('native','control') if args.mode=='gate' else ORDER
    results=[sample(args,out,a,i,driver,common,frozen,libraries) for i,a in enumerate(order)]
    summary={}
    if args.mode=='measure':
        for arm in ('native','control'):
            rows=[r for r in results if r['arm']==arm]
            values=dict(setup=[r['setup_wall_seconds'] for r in rows],cold=[r['batches'][0]['batch_wall_seconds'] for r in rows],warm=[r['batches'][1]['batch_wall_seconds'] for r in rows],first_use=[r['setup_wall_seconds']+r['batches'][0]['batch_wall_seconds'] for r in rows],warm_encryption=[r['batches'][1]['seconds']['encryption'] for r in rows],warm_evaluation=[r['batches'][1]['seconds']['evaluation'] for r in rows],peak_rss_MiB=[r['peak_rss_kib']/1024 for r in rows])
            summary[arm]={k:dict(samples=v,median=median(v),minimum=min(v),maximum=max(v)) for k,v in values.items()}
    result=dict(status='CURRENT_CONTROL_BOTH_FRESH_GATES_PASS' if args.mode=='gate' else 'CURRENT_CONTROL_DIRECT_WORKFLOW_PASS',mode=args.mode,started_utc=start,order=order,source_manifest=frozen,runtime_manifest=libraries,files={p.name:binding(p) for p in out.iterdir()},summary=summary,control_over_native_median_ratios={k:summary['control'][k]['median']/summary['native'][k]['median'] for k in summary.get('native',{})},gate=binding(args.gate/'summary.json') if gate else None,platform=platform.platform(),processor=platform.processor(),new_he_execution=True,security_bits=None)
    save(out/'summary.json',result)
    print(json.dumps(dict(status=result['status'],ratios=result['control_over_native_median_ratios'])),flush=True)

if __name__=='__main__': main()
