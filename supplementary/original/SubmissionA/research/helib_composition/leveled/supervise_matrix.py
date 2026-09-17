"""Linux-bounded public fixture check OR one untimed four-job encrypted pilot."""
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time


def main():
    assert os.name=='posix' and len(sys.argv)==2 and sys.argv[1] in ('public','encrypted')
    mode=sys.argv[1];root=Path(__file__).resolve().parents[3]
    sys.path.insert(0,str(root/'research'))
    from composition_fixture import inputs,metadata
    executable=root/'build'/'helib-matrix-k8'/'helib_matrix_k8'
    here=Path(__file__).resolve().parent
    paths=[Path(__file__).resolve(),here/'matrix_k8.cpp',here/'composition_fixture.h',
           here/'matrix'/'CMakeLists.txt',root/'research'/'composition_fixture.py',executable]
    bound={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    address_space,output_limit=2<<30,2<<20
    wall,cpu=(120,90) if mode=='public' else (300,240)

    def limits():
        resource.setrlimit(resource.RLIMIT_AS,(address_space,address_space))
        resource.setrlimit(resource.RLIMIT_CPU,(cpu,cpu))
        resource.setrlimit(resource.RLIMIT_FSIZE,(output_limit,output_limit))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))

    argument='--public-fixture' if mode=='public' else '--encrypted-k8'
    child=subprocess.Popen([str(executable),argument],cwd=executable.parent,
          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=limits)
    selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
    chunks=[];size=0;error=None;began=time.monotonic()
    try:
        while selector.get_map():
            if time.monotonic()-began>wall:raise TimeoutError('Matrix pilot wall cap')
            for key,_ in selector.select(0.1):
                block=os.read(key.fileobj.fileno(),65536)
                if not block:selector.unregister(key.fileobj);continue
                size+=len(block)
                if size>output_limit:raise RuntimeError('Matrix pilot output cap')
                chunks.append(block)
        child.wait(timeout=1)
        assert child.returncode==0,'Matrix pilot failed'
    except Exception as e:error=str(e)
    finally:
        if child.poll() is None:
            assert os.getpgid(child.pid)==child.pid
            os.killpg(child.pid,signal.SIGKILL)
        child.wait(timeout=10);selector.close()
    output=b''.join(chunks).decode('utf-8',errors='replace');records=[]
    for line in output.splitlines():
        try:records.append(json.loads(line))
        except json.JSONDecodeError:pass
    results=[x for x in records if 'status' in x]
    same=bound=={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    expected_status='PUBLIC_FIXTURE_PASS' if mode=='public' else 'HELIB_K8_ENCRYPTED_CORRESPONDENCE_PASS'
    fixture=metadata()
    if len(results)!=1 or results[0].get('status')!=expected_status or not same:
        error=error or 'Invalid result or changed sources'
    else:
        result=results[0]
        if result.get('fixture_fnv64')!=fixture['fnv64_cross_language_check']:
            error=error or 'Fixture fingerprint mismatch'
        if mode=='public':
            fs,gs=inputs();expected=[x for pair in zip(fs,gs) for v in pair for x in v]
            if result.get('inputs')!=expected:error=error or 'Cross-language input mismatch'
            result.pop('inputs',None);result['cross_language_input_symbols_checked']=8192
        elif (result.get('symbols_checked')!=1024 or result.get('fresh_encryptions')!=511
              or result.get('private_products')!=255 or result.get('relinearizations')!=1
              or result.get('rotations')!=0 or result.get('fixture_jobs')!=[0,1,2,3]):
            error=error or 'Wrong executed inventory'
    receipt=dict(status='PASS' if error is None else 'FAIL',mode=mode,error=error,
          limits=dict(address_space_bytes=address_space,output_capture_bytes=output_limit,wall_seconds=wall,cpu_seconds=cpu),
          peak_child_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
          child_exit_code=child.returncode,source_manifest=bound,sources_unchanged=same,
          fixture=fixture,result=results[0] if len(results)==1 else None,
          events=[x for x in records if 'event' in x],
          scope='Linux bounded correctness only; stock BGV key/noise policy; no benchmark, native security transfer or process isolation')
    if error:receipt['diagnostic']=output[-8192:]
    print(json.dumps(receipt));return int(error is not None)


if __name__=='__main__':
    raise SystemExit(main())
