"""Fresh bounded native gates and a predeclared eight-setup comparison."""
import argparse
from datetime import datetime,timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import signal
from statistics import median
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
READY=HERE.parent
STAGE=READY/'native-stage-gadgets-v1'
ROOT=HERE.parents[3]
ORIGINAL=READY/'same-algebra-one-prime-workflow-v1'
LAZY=READY/'native-lazy-ntt-v1'
ORDER=('baseline','tensor','tensor','baseline','baseline','tensor','tensor','baseline')
THREADS=('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS')

def read(p):return json.loads(p.read_text())
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
def save(p,x):
    with p.open('x') as f:json.dump(x,f,indent=2);f.write('\n')

def imports():
    sys.path[:0]=[str(ORIGINAL),str(LAZY),str(STAGE),str(HERE)]
    import common
    from tensor_worker import TensorWorker
    return common,TensorWorker

def baseline_module():
    import importlib.util
    spec=importlib.util.spec_from_file_location('checked_stage_driver',STAGE/'run.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def manifest(common):
    result=baseline_module().manifest(common)
    build=read(HERE/'build.json');check=read(HERE/'public-check.json')
    assert build['status']=='NATIVE_TENSOR_AXIS_BUILD_PASS'
    assert check['status']=='NATIVE_TENSOR_AXIS_PUBLIC_CORRESPONDENCE_PASS'
    assert check['advance_to_fresh_gate'] and check['kernel_baseline_over_candidate']>=1.03
    assert check['build_receipt']==binding(HERE/'build.json')
    assert check['checker']==binding(HERE/'check_candidate.py')
    for name,want in build['source_bindings'].items():
        assert binding(ROOT/name)==want,name;result[name]=want
    for name,want in build['candidate_files'].items():
        assert binding(HERE/name)==want,name;result[(HERE/name).relative_to(ROOT).as_posix()]=want
    for name in ['WORKFLOW_PLAN.md','run.py','tensor_worker.py','build.json','public-check.json','check_candidate.py']:
        result[(HERE/name).relative_to(ROOT).as_posix()]=binding(HERE/name)
    return result


def runtime(common):
    result=baseline_module().runtime(common)
    result[str(HERE/'build/tensor_core.so')]=binding(HERE/'build/tensor_core.so')
    return result


def validate(r,mode,variant,index):
    assert r['status']=='NATIVE_TENSOR_AXIS_WORKFLOW_'+('GATE_PASS' if mode=='gate' else 'MEASUREMENT_PASS')
    assert (r['mode'],r['variant'],r['index'],r['arm'])==(mode,variant,index,'native')
    assert r['profile_version']=='native-tensor-axis-v1' and r['terminal_limbs']==2
    assert r['worker_threads']==1 and r['affinity']==[0]
    assert r['phase_checked_states']==(57 if mode=='gate' else 0)
    assert r['phase_checked_coefficients']==65536*r['phase_checked_states']
    assert r['material']['public_material_raw_bytes']==297<<20
    assert [r['material'][k] for k in ('independent_secrets','public_keys','evaluation_rows')]==[9,5,102]
    assert len(r['batches'])==(1 if mode=='gate' else 2)
    assert r['encrypted_execution'] and r['security_bits'] is None
    for i,b in enumerate(r['batches']):
        assert b['index']==i and b['output_symbols']==4096
        assert b['output_sha256']=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
        assert b['counts']==dict(fresh_encryptions=35,small_vectors=105,error_vectors=70,ciphertext_products=19)
        assert b['wire']['input_raw_bytes']==103<<20 and b['wire']['output_raw_bytes']==3<<20
        assert b['batch_wall_seconds']>=sum(b['seconds'].values())>0

def child(args):
    import resource
    resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
    resource.setrlimit(resource.RLIMIT_CPU,(180,180))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.sched_setaffinity(0,{0})
    assert all(os.environ.get(k)=='1' for k in THREADS)
    common,Worker=imports()
    frozen=manifest(common);libraries=runtime(common)
    common.verify_admission()
    from bounds import trace_spec
    admission=read(STAGE/'admission.json')
    assert len(admission['trace'])==len(trace_spec())==22
    for actual,(n,k,a,c,b) in zip(admission['trace'],trace_spec()):
        assert (actual['state'],actual['key'],actual['limbs'],actual['components'],int(actual['error_bound']))==(n,k,a,c,b)
    for name,want in admission['bindings'].items():assert binding(ROOT/name)==want,name
    worker=Worker(args.mode,args.variant,args.index)
    try:
        result=worker.run()
        result.update(status='NATIVE_TENSOR_AXIS_WORKFLOW_'+('GATE_PASS' if args.mode=='gate' else 'MEASUREMENT_PASS'),
            variant=args.variant,profile_version='native-tensor-axis-v1')
        validate(result,args.mode,args.variant,args.index)
        assert manifest(common)==frozen and runtime(common)==libraries
        result.update(source_bindings=frozen,runtime_bindings=libraries)
        print(json.dumps(dict(event='native_stage_gadget_result',result=result)),flush=True)
    finally:
        if worker.ring:worker.ring.close()

def sample(args,out,variant,index,common,frozen,libraries):
    command=[sys.executable,'-B','-u',str(Path(__file__).resolve()),'--child','--mode',args.mode,'--variant',variant,'--index',str(index)]
    env=os.environ.copy();env.update({k:'1' for k in THREADS})
    start=time.monotonic()
    proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
    termination=None
    try:stdout,stderr=proc.communicate(timeout=210)
    except subprocess.TimeoutExpired:
        termination='210-second wall limit';os.killpg(proc.pid,signal.SIGKILL);stdout,stderr=proc.communicate()
    stem=f'{index:02d}-{variant}'
    (out/(stem+'.stdout.txt')).write_bytes(stdout);(out/(stem+'.stderr.txt')).write_bytes(stderr)
    result=None;error=None
    try:
        assert proc.returncode==0 and not stderr and termination is None
        values=[json.loads(x) for x in stdout.decode().splitlines()]
        results=[x['result'] for x in values if x.get('event')=='native_stage_gadget_result']
        assert len(results)==1
        result=results[0];validate(result,args.mode,variant,index)
        assert result['source_bindings']==frozen and result['runtime_bindings']==libraries
        assert manifest(common)==frozen and runtime(common)==libraries
    except BaseException as exc:error=type(exc).__name__
    record=dict(status='PASS' if error is None else 'FAIL',worker_exit_code=proc.returncode,termination=termination,error=error,
        command=command,elapsed_seconds=time.monotonic()-start,result=result,
        stdout=binding(out/(stem+'.stdout.txt')),stderr=binding(out/(stem+'.stderr.txt')))
    save(out/(stem+'.json'),record)
    print(json.dumps(dict(mode=args.mode,index=index,variant=variant,status=record['status'],worker_exit_code=proc.returncode)),flush=True)
    assert error is None,stem
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--child',action='store_true')
    p.add_argument('--mode',choices=('gate','measure'),required=True)
    p.add_argument('--variant',choices=('baseline','tensor'));p.add_argument('--index',type=int)
    p.add_argument('--out',type=Path);p.add_argument('--gate',type=Path);p.add_argument('--host-observation',type=Path)
    args=p.parse_args()
    if args.child:child(args);return
    assert args.out and not args.out.exists()
    out=args.out.resolve();assert out.parent==HERE
    common,_=imports();frozen=manifest(common);libraries=runtime(common)
    gate=None;host=None
    if args.mode=='measure':
        assert args.gate and args.host_observation
        gate=read(args.gate/'summary.json')
        assert gate['status']=='NATIVE_TENSOR_AXIS_BOTH_FRESH_GATES_PASS'
        assert gate['source_manifest']==frozen and gate['runtime_manifest']==libraries
        for name,want in gate['files'].items():assert binding(args.gate/name)==want,name
        host=read(args.host_observation);assert set(host)=={'windows','wsl'}
        for r in host.values():
            assert r['workers']==[] and r['tool_exit_code']==0
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(r['recorded_utc'])).total_seconds()
            assert 0<=age<=300,'Worker observation is stale'
    out.mkdir()
    if host:save(out/'host-observation.json',host)
    order=('baseline','tensor') if args.mode=='gate' else ORDER
    start=datetime.now(timezone.utc).isoformat()
    results=[sample(args,out,v,i,common,frozen,libraries) for i,v in enumerate(order)]
    summary={}
    if args.mode=='measure':
        for variant in ('baseline','tensor'):
            rows=[r for r in results if r['variant']==variant]
            values=dict(setup=[r['setup_wall_seconds'] for r in rows],cold=[r['batches'][0]['batch_wall_seconds'] for r in rows],
                warm=[r['batches'][1]['batch_wall_seconds'] for r in rows],
                first_use=[r['setup_wall_seconds']+r['batches'][0]['batch_wall_seconds'] for r in rows],
                warm_encryption=[r['batches'][1]['seconds']['encryption'] for r in rows],
                warm_evaluation=[r['batches'][1]['seconds']['evaluation'] for r in rows],
                peak_rss_MiB=[r['peak_rss_kib']/1024 for r in rows])
            summary[variant]={k:dict(samples=v,median=median(v),minimum=min(v),maximum=max(v)) for k,v in values.items()}
    result=dict(status='NATIVE_TENSOR_AXIS_BOTH_FRESH_GATES_PASS' if args.mode=='gate' else 'NATIVE_TENSOR_AXIS_CONTROLLED_WORKFLOW_PASS',
        mode=args.mode,started_utc=start,order=order,source_manifest=frozen,runtime_manifest=libraries,
        files={p.name:binding(p) for p in out.iterdir()},summary=summary,
        baseline_over_tensor_median_ratios={k:summary['baseline'][k]['median']/summary['tensor'][k]['median'] for k in summary.get('baseline',{})},
        gate=binding(args.gate/'summary.json') if gate else None,platform=platform.platform(),processor=platform.processor(),
        new_he_execution=True,security_bits=None)
    save(out/'summary.json',result)
    print(json.dumps({k:v for k,v in result.items() if k not in ('source_manifest','runtime_manifest','files','summary')}),flush=True)

if __name__=='__main__':main()
