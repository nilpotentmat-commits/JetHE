"""Sequential exclusive receipts, explicit resource bounds and admission gates."""
import argparse
from datetime import datetime,timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import selectors
import signal
from statistics import median
import subprocess
import sys
import time

from common import (HERE,READY,ROOT,ORDER,LIMITS,THREAD_VARIABLES,EXPECTED_SHA,
                    source_manifest,runtime_manifest,verify_admission,binding)


def save(path,value):
    with path.open('x',encoding='utf-8') as f:json.dump(value,f,indent=2);f.write('\n')


def research_workers():
    found=[]
    for path in Path('/proc').iterdir():
        if not path.name.isdigit() or int(path.name)==os.getpid():continue
        try:
            args=(path/'cmdline').read_bytes().split(b'\0')
            if not args or b'python' not in Path(os.fsdecode(args[0])).name.encode():continue
            scripts=[os.fsdecode(a) for a in args[1:] if b'/research/' in a and a.endswith(b'.py')]
            if scripts:found.append(dict(pid=int(path.name),scripts=scripts))
        except (FileNotFoundError,PermissionError,ProcessLookupError):pass
    return found


def campaign_prerequisite():
    busy=research_workers()
    assert not busy, 'Another research worker is still live; no campaign started.'
    # This gate is intentionally not inferred from RUN_STATE.json or a timeout.
    path=READY/'complete-receiver-audit-v1/verification.json'
    receipt=json.loads(path.read_text())
    assert receipt['status']=='COMPLETE_CONVENTIONAL_RECEIVER_RECORDED_EXECUTION_READBACK_PASS'
    assert receipt['complete_execution_record_verified']
    for name,value in receipt['files'].items():assert binding(ROOT/name)==value
    return dict(complete_receiver_audit=binding(path),other_research_workers=busy)


def validate_result(result,mode,arm,index):
    assert result['status']==('SAME_ALGEBRA_WORKFLOW_GATE_PASS' if mode=='gate' else 'SAME_ALGEBRA_WORKFLOW_WORKER_PASS')
    assert (result['mode'],result['arm'],result['index'])==(mode,arm,index)
    assert result['worker_threads']==1 and result['affinity']==[0]
    assert result['encrypted_execution'] and result['security_bits'] is None
    assert result['phase_checked_states']==((57 if arm=='native' else 434) if mode=='gate' else 0)
    assert result['phase_checked_coefficients']==65536*result['phase_checked_states']
    assert len(result['batches'])==(1 if mode=='gate' else 2)
    assert result['peak_rss_kib']*1024<=LIMITS['address_space_bytes']
    material=result['material']
    assert [material[k] for k in ('independent_secrets','public_keys','evaluation_rows','setup_small_vectors')]==([9,5,134,148] if arm=='native' else [1,1,0,2])
    assert material['public_material_raw_bytes']==(391 if arm=='native' else 2)<<20
    assert result['setup_wall_seconds']>=sum(result['setup_seconds'].values())
    for i,batch in enumerate(result['batches']):
        assert batch['index']==i
        assert batch['state']==('gate' if mode=='gate' else 'cold' if i==0 else 'warm')
        assert batch['output_sha256']==EXPECTED_SHA and batch['output_symbols']==4096
        assert batch['batch_wall_seconds']>=sum(batch['seconds'].values())
        I,C,O,polys,mb=(35,19,1,3,103) if arm=='native' else (346,86,88,262,692)
        assert batch['counts']==dict(fresh_encryptions=I,small_vectors=3*I,error_vectors=2*I,ciphertext_products=C)
        wire=batch['wire']
        assert [wire[k] for k in ('input_ciphertexts','input_polynomials','input_raw_bytes','output_ciphertexts','output_polynomials','output_raw_bytes')]==[I,2*I,mb<<20,O,polys,polys<<20]
        assert wire['input_wire_bytes']>wire['input_raw_bytes'] and wire['output_wire_bytes']>wire['output_raw_bytes']


def sample(output,mode,arm,index,frozen,runtime):
    assert source_manifest()==frozen and runtime_manifest()==runtime
    env=dict(os.environ)
    env.update({k:'1' for k in THREAD_VARIABLES})
    def limits():
        os.sched_setaffinity(0,{0})
        for key,value in ((resource.RLIMIT_AS,LIMITS['address_space_bytes']),(resource.RLIMIT_CPU,LIMITS['cpu_seconds']),(resource.RLIMIT_CORE,0)):
            resource.setrlimit(key,(value,value))
    command=[sys.executable,'-B','-u',str(HERE/'worker.py'),'--supervised','--mode',mode,'--arm',arm,'--index',str(index)]
    child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           env=env,preexec_fn=limits,start_new_session=True)
    selector=selectors.DefaultSelector()
    selector.register(child.stdout,selectors.EVENT_READ,0)
    selector.register(child.stderr,selectors.EVENT_READ,1)
    captured=[bytearray(),bytearray()]
    start=time.monotonic();deadline=start+LIMITS['wall_seconds']
    error=None;result=None;termination=None
    try:
        while selector.get_map():
            if time.monotonic()>deadline:
                termination='Declared worker wall limit exceeded'
                raise TimeoutError
            for key,_ in selector.select(0.5):
                data=os.read(key.fileobj.fileno(),65536)
                if not data:selector.unregister(key.fileobj);continue
                captured[key.data].extend(data)
                if sum(map(len,captured))>8<<20:
                    termination='Declared diagnostic output cap exceeded'
                    raise OverflowError
        assert child.wait(timeout=10)==0
        assert not captured[1]
        values=[json.loads(line) for line in captured[0].decode().splitlines()]
        results=[v['result'] for v in values if v.get('event')=='result']
        assert len(results)==1
        result=results[0]
        validate_result(result,mode,arm,index)
        assert result['source_bindings_before']==result['source_bindings_after']==frozen
        assert result['runtime_bindings']==runtime
        assert source_manifest()==frozen and runtime_manifest()==runtime
    except BaseException as exc:error=type(exc).__name__
    finally:
        if child.poll() is None:
            os.killpg(child.pid,signal.SIGKILL)
            termination=termination or 'Worker stopped after supervisor validation failure'
        child.wait(timeout=10)
        selector.close()
    stem=f'{mode}-{index:02d}-{arm}'
    for label,data in zip(('stdout','stderr'),captured):
        with (output/f'{stem}.{label}.txt').open('xb') as f:f.write(data)
    receipt=dict(status='PASS' if error is None else 'FAIL',mode=mode,arm=arm,index=index,
        worker_pid=child.pid,worker_exit_code=child.returncode,command=command,limits=LIMITS,
        error_type=error,termination_reason=termination,elapsed_seconds=time.monotonic()-start,
        result=result,source_manifest=frozen,runtime_manifest=runtime,
        sources_unchanged=source_manifest()==frozen,
        stdout=binding(output/f'{stem}.stdout.txt'),stderr=binding(output/f'{stem}.stderr.txt'))
    save(output/f'{stem}.json',receipt)
    print(json.dumps(dict(status=receipt['status'],mode=mode,arm=arm,index=index,
                         elapsed_seconds=receipt['elapsed_seconds'],worker_exit_code=child.returncode)),flush=True)
    return receipt


def summarize(receipts):
    summary={}
    for arm in ('native','control'):
        rows=[r['result'] for r in receipts if r['arm']==arm]
        assert len(rows)==3
        fields=dict(setup=[r['setup_wall_seconds'] for r in rows],
            cold=[r['batches'][0]['batch_wall_seconds'] for r in rows],
            warm=[r['batches'][1]['batch_wall_seconds'] for r in rows],
            setup_plus_cold=[r['setup_wall_seconds']+r['batches'][0]['batch_wall_seconds'] for r in rows],
            warm_evaluation=[r['batches'][1]['seconds']['evaluation'] for r in rows],
            warm_encryption=[r['batches'][1]['seconds']['encryption'] for r in rows],
            peak_rss_MiB=[r['peak_rss_kib']/1024 for r in rows])
        summary[arm]={k:dict(samples=v,median=median(v),minimum=min(v),maximum=max(v)) for k,v in fields.items()}
    ratios={name:summary['control'][name]['median']/summary['native'][name]['median']
            for name in ('warm','cold','setup','setup_plus_cold','warm_evaluation','warm_encryption','peak_rss_MiB')}
    return summary,ratios


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--mode',choices=('gate','campaign'),required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--gate',type=Path)
    args=p.parse_args()
    verify_admission()
    frozen=source_manifest();runtime=runtime_manifest()
    prerequisite=campaign_prerequisite() if args.mode=='campaign' else dict(other_research_workers=research_workers(),timings_excluded=True)
    if args.mode=='campaign':
        assert args.gate is not None
        gate=json.loads((args.gate/'gate.json').read_text())
        assert gate['status']=='SAME_ALGEBRA_WORKFLOW_BOTH_GATES_PASS'
        assert gate['source_manifest']==frozen and gate['runtime_manifest']==runtime
        for name,value in gate['receipts'].items():assert binding(args.gate/name)==value
    output=args.out.resolve()
    assert output.parent==HERE
    output.mkdir(exist_ok=False)
    environment=dict(created_utc=datetime.now(timezone.utc).isoformat(),platform=platform.platform(),python=sys.version,
                     cpu=subprocess.check_output(['lscpu'],text=True),load_average=os.getloadavg(),
                     supervisor_pid=os.getpid(),prerequisite=prerequisite,source_manifest=frozen,runtime_manifest=runtime)
    save(output/'environment.json',environment)
    receipts=[]
    order=('native','control') if args.mode=='gate' else ORDER
    for index,arm in enumerate(order):
        if args.mode=='campaign':assert not research_workers()
        receipt=sample(output,'gate' if args.mode=='gate' else 'measure',arm,index,frozen,runtime)
        receipts.append(receipt)
        if receipt['status']!='PASS':
            save(output/'failure.json',dict(status='CAMPAIGN_OR_GATE_FAILURE',at_index=index,arm=arm,
                 receipt_failure=receipt['error_type'],all_completed_receipts=len(receipts)))
            raise SystemExit(1)
    bound={p.name:binding(p) for p in sorted(output.glob('*.json'))}
    if args.mode=='gate':
        save(output/'gate.json',dict(status='SAME_ALGEBRA_WORKFLOW_BOTH_GATES_PASS',
             source_manifest=frozen,runtime_manifest=runtime,receipts=bound,timing_comparison=False,security_bits=None))
    else:
        summary,ratios=summarize(receipts)
        result=dict(status='SAME_ALGEBRA_CONTROLLED_WORKFLOW_CAMPAIGN_PASS',order=list(ORDER),
            source_manifest=frozen,runtime_manifest=runtime,receipts=bound,gate=binding(args.gate/'gate.json'),
            summary=summary,control_over_native_median_ratios=ratios,security_bits=None,
            scope='One host, three setups per arm, identical source laws/algebra/backend, distinct admitted moduli. Complete local workflows; no population or equal-certified-security claim.')
        save(output/'summary.json',result)
        print(json.dumps(dict(status=result['status'],summary=summary,ratios=ratios)),flush=True)


if __name__=='__main__':main()
