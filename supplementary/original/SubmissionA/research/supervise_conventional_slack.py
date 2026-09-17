"""Bounded public/gate/timing workers for the immutable V2 control."""
from array import array
from hashlib import sha256
from pathlib import Path
import json
import os
import platform
import resource
import selectors
import signal
import subprocess
import sys
import time
from supervise_matched_screen import manifest as v1_manifest, LIMITS, CAP, ORDER, ROOT, HERE


def manifest(include_selection):
    result=v1_manifest()
    paths=[Path(__file__),HERE/'CONVENTIONAL_SLACK_V2.md',
        HERE/'helib_composition'/'leveled'/'slack_profile.cpp',
        HERE/'helib_composition'/'leveled'/'slack'/'CMakeLists.txt',
        ROOT/'build'/'helib-slack-control'/'helib_slack_control',
        ROOT/'build'/'helib-slack-control'/'CMakeCache.txt',
        ROOT/'build'/'helib-slack-control'/'build.ninja']
    if include_selection:paths.append(ROOT/'evidence'/'conventional-slack-v2-selection.json')
    for path in paths:result[str(path.relative_to(ROOT.parent))]=sha256(path.read_bytes()).hexdigest()
    return result


def main():
    assert len(sys.argv)>=3
    mode=sys.argv[1];assert mode in ('public','gate','sample')
    sample=None
    if mode=='sample':
        assert len(sys.argv)==3
        sample=int(sys.argv[2]);assert 0<=sample<9
        arm=ORDER[sample]
        selection=json.loads((ROOT/'evidence'/'conventional-slack-v2-selection.json').read_text())
        assert selection['status']=='SELECTED_BEFORE_TIMING'
        if arm=='native':m=bits=None
        else:m,bits=(selection['selected'][arm][x] for x in ('m','requested_bits'))
    else:
        assert len(sys.argv)==(4 if mode=='public' else 5)
        arm='column' if mode=='public' else sys.argv[2]
        m,bits=map(int,sys.argv[-2:])
        assert arm in ('column','b16') and m in (4369,13107,21845) and bits in (20,60)
        if mode=='gate':
            p=json.loads((ROOT/'evidence'/f'conventional-slack-v2-public-{m}-{bits}.json').read_text())
            assert p['status']=='PASS' and p['result']['profile']['library_security_estimate_NOT_CERTIFICATION']>=128
    stem=(f'sample-{sample}-{arm}' if mode=='sample' else f'{mode}-{m}-{bits}' if mode=='public' else f'gate-{arm}-{m}-{bits}')
    assert not (ROOT/'evidence'/f'conventional-slack-v2-{stem}.json').exists(),'Do not overwrite an existing worker receipt'
    before=manifest(mode=='sample');cpu=min(os.sched_getaffinity(0))
    command=([sys.executable,'-B',str(HERE/'measure_composition_native.py'),'--screen-v1'] if arm=='native'
        else [str(ROOT/'build'/'helib-slack-control'/'helib_slack_control'),mode,arm,str(m),str(bits)])
    env=dict(os.environ);env.update(OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1')
    def limits():
        os.sched_setaffinity(0,{cpu})
        resource.setrlimit(resource.RLIMIT_AS,(LIMITS['address_space_bytes'],)*2)
        resource.setrlimit(resource.RLIMIT_CPU,(LIMITS['cpu_seconds'],)*2)
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,
        start_new_session=True,preexec_fn=limits,close_fds=True)
    capture=[bytearray(),bytearray()];selector=selectors.DefaultSelector()
    selector.register(child.stdout,selectors.EVENT_READ,0);selector.register(child.stderr,selectors.EVENT_READ,1)
    deadline=time.monotonic()+LIMITS['wall_seconds'];error=None;result=None;events=[];after=None;code=None
    try:
        while selector.get_map():
            if time.monotonic()>deadline:raise TimeoutError('V2 wall limit')
            for key,_ in selector.select(timeout=min(1,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk:selector.unregister(key.fileobj);continue
                if sum(map(len,capture))+len(chunk)>CAP:raise RuntimeError('V2 output cap')
                capture[key.data].extend(chunk)
        code=child.wait(timeout=max(1,deadline-time.monotonic()))
        assert code==0,f'Worker exit {code}'
        records=[json.loads(line) for line in capture[0].decode().splitlines()]
        result=records[-1];events=records[:-1]
        expected='MATCHED_SCREEN_NATIVE_PASS' if arm=='native' else f'SLACK_{mode.upper()}_PASS'
        assert result['status']==expected
        if mode!='public':
            assert result['arm']==arm and len(result['batches'])==(1 if mode=='gate' else 2)
            for i,b in enumerate(result['batches']):
                assert (b['index'],b['state'],b['output_symbols'])==(i,'cold' if i==0 else 'warm',4096)
                if arm!='native':
                    values=array('H',b.pop('recovered_public_fixture_symbols'))
                    assert len(values)==4096 and sys.byteorder=='little'
                    b['output_sha256']=sha256(values.tobytes()).hexdigest()
                    b['public_vector_verified_then_condensed']=True
                    assert b['minimum_output_bit_capacity']>=10
                assert b['output_sha256']=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
        after=manifest(mode=='sample');assert after==before,'Sources changed during worker'
    except Exception as exc:error=f'{type(exc).__name__}: {exc}'
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        code=child.wait(timeout=10);selector.close()
    if after is None:
        try:after=manifest(mode=='sample')
        except Exception as exc:error=(error+'; ' if error else '')+f'After-manifest unavailable: {exc}'
    cpu_model=next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),'unavailable')
    compiler=subprocess.check_output(['/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-c++','--version'],text=True).splitlines()[0]
    record=dict(status='PASS' if error is None else 'FAIL',phase=mode,sample_index=sample,arm=arm,m=m,requested_bits=bits,
        limits=LIMITS,affinity_cpu=cpu,host=dict(kernel=platform.release(),machine=platform.machine(),cpu_model=cpu_model,python=sys.version,compiler=compiler),
        source_manifest=before,sources_unchanged=after==before,worker_exit_code=code,stdout_bytes=len(capture[0]),
        stderr=capture[1].decode(errors='replace'),error=error,result=result,events=events,
        capture_scope='Complete bounded worker output; successful public fixture vectors checked then explicitly condensed')
    if error:record['failed_stdout']=capture[0].decode(errors='replace')
    print(json.dumps(record,indent=2),flush=True)
    if error:raise SystemExit(1)


if __name__=='__main__':main()
