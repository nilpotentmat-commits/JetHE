"""One bounded sample from the immutable V1 order; public JSON only."""
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

ROOT=Path(__file__).resolve().parent.parent
HERE=ROOT/'research'
CAP=4<<20
LIMITS=dict(address_space_bytes=2<<30,wall_seconds=900,cpu_seconds=840,output_bytes=CAP,core_bytes=0)
ORDER=['native','column','b16','column','b16','native','b16','native','column']


def manifest():
    old=json.loads((ROOT/'evidence'/'composition-isolated-v1-summary.json').read_text())['source_manifest']
    paths={ROOT/name for name in old}
    paths.update([Path(__file__),HERE/'measure_composition_native.py',HERE/'MATCHED_SCREEN_V1.md',
        HERE/'check_composition_executed_ledger.py',HERE/'helib_composition'/'leveled'/'measure_composition.cpp',
        HERE/'helib_composition'/'leveled'/'diagonal_bsgs.cpp',HERE/'helib_composition'/'leveled'/'composition_fixture.h',
        HERE/'helib_composition'/'leveled'/'measurement'/'CMakeLists.txt',
        ROOT/'build'/'helib-matched-screen'/'helib_matched_screen',
        ROOT/'build'/'helib-matched-screen'/'CMakeCache.txt',
        ROOT/'build'/'helib-matched-screen'/'build.ninja',
        ROOT.parent/'Code'/'build-helib-2.3.0'/'install'/'lib'/'libhelib.a',
        Path('/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-c++')])
    return {str(p.relative_to(ROOT.parent)) if p.is_relative_to(ROOT.parent) else str(p):sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def main():
    assert len(sys.argv)==2 and sys.argv[1].isdigit()
    sample=int(sys.argv[1]);assert 0<=sample<len(ORDER)
    arm=ORDER[sample];cpu=min(os.sched_getaffinity(0));before=manifest()
    compiler=subprocess.check_output(['/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-c++','--version'],text=True).splitlines()[0]
    command=([sys.executable,'-B',str(HERE/'measure_composition_native.py'),'--screen-v1'] if arm=='native'
        else [str(ROOT/'build'/'helib-matched-screen'/'helib_matched_screen'),'--screen-v1',arm])
    env=dict(os.environ)
    env.update(OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1')
    def limits():
        os.sched_setaffinity(0,{cpu})
        resource.setrlimit(resource.RLIMIT_AS,(LIMITS['address_space_bytes'],)*2)
        resource.setrlimit(resource.RLIMIT_CPU,(LIMITS['cpu_seconds'],)*2)
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env=env,start_new_session=True,preexec_fn=limits,close_fds=True)
    capture=[bytearray(),bytearray()];selector=selectors.DefaultSelector()
    selector.register(child.stdout,selectors.EVENT_READ,0);selector.register(child.stderr,selectors.EVENT_READ,1)
    deadline=time.monotonic()+LIMITS['wall_seconds'];error=None;result=None;events=[];code=None;after=None
    try:
        while selector.get_map():
            if time.monotonic()>deadline:raise TimeoutError('Screen wall limit')
            for key,_ in selector.select(timeout=min(1,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk:selector.unregister(key.fileobj);continue
                if sum(map(len,capture))+len(chunk)>CAP:raise RuntimeError('Screen output cap')
                capture[key.data].extend(chunk)
        code=child.wait(timeout=max(1,deadline-time.monotonic()))
        assert code==0, f'Worker exit {code}'
        records=[json.loads(line) for line in capture[0].decode().splitlines()]
        result=records[-1];events=records[:-1]
        assert result['status']==('MATCHED_SCREEN_NATIVE_PASS' if arm=='native' else 'MATCHED_SCREEN_HELIB_PASS')
        assert result['arm']==arm and len(result['batches'])==2
        for i,b in enumerate(result['batches']):
            assert (b['index'],b['state'],b['output_symbols'])==(i,'cold' if i==0 else 'warm',4096)
            if arm!='native':
                values=array('H',b.pop('recovered_public_fixture_symbols'))
                assert len(values)==4096 and sys.byteorder=='little'
                b['output_sha256']=sha256(values.tobytes()).hexdigest()
                b['public_vector_verified_then_condensed']=True
            assert b['output_sha256']=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
            assert all(v>=0 for v in b['seconds'].values())
        after=manifest();assert after==before,'Sources changed during sample'
    except Exception as exc:error=f'{type(exc).__name__}: {exc}'
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        code=child.wait(timeout=10);selector.close()
    if after is None:
        try:after=manifest()
        except Exception as exc:error=(error+'; ' if error else '')+f'After-manifest unavailable: {type(exc).__name__}: {exc}'
    cpu_model=next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),'unavailable')
    record=dict(status='PASS' if error is None else 'FAIL',sample_index=sample,arm=arm,
        limits=LIMITS,affinity_cpu=cpu,host=dict(kernel=platform.release(),machine=platform.machine(),
        cpu_model=cpu_model,python=sys.version,compiler=compiler),source_manifest=before,sources_unchanged=after==before,
        worker_exit_code=code,stdout_bytes=len(capture[0]),stderr=capture[1].decode(errors='replace'),
        error=error,result=result,events=events,
        capture_scope='Bounded complete worker JSON parsed; HElib public output vectors verified against frozen independent digest then condensed')
    if error:record['failed_stdout']=capture[0].decode(errors='replace')
    print(json.dumps(record,indent=2),flush=True)
    if error:raise SystemExit(1)


if __name__=='__main__':main()
