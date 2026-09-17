"""Bound one public larger-carrier check on Linux; no keys or benchmarks."""
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

ADDRESS_SPACE,OUTPUT,WALL,CPU=2<<30,1<<20,120,90


def main():
    assert os.name=='posix' and len(sys.argv)==2 and sys.argv[1] in ('21845','65535')
    root=Path(__file__).resolve().parents[3]
    executable=root/'build'/'helib-leveled'/'helib_leveled_preflight'
    paths=[Path(__file__).resolve(),Path(__file__).with_name('preflight.cpp'),
           Path(__file__).with_name('CMakeLists.txt'),executable]
    bound={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}

    def limits():
        resource.setrlimit(resource.RLIMIT_AS,(ADDRESS_SPACE,ADDRESS_SPACE))
        resource.setrlimit(resource.RLIMIT_CPU,(CPU,CPU))
        resource.setrlimit(resource.RLIMIT_FSIZE,(OUTPUT,OUTPUT))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))

    child=subprocess.Popen([str(executable),sys.argv[1]],cwd=executable.parent,
          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=limits)
    selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
    chunks=[];size=0;error=None;began=time.monotonic()
    try:
        while selector.get_map():
            if time.monotonic()-began>WALL:raise TimeoutError('Public preflight wall cap')
            for key,_ in selector.select(0.1):
                block=os.read(key.fileobj.fileno(),65536)
                if not block:selector.unregister(key.fileobj);continue
                size+=len(block)
                if size>OUTPUT:raise RuntimeError('Public preflight output cap')
                chunks.append(block)
        child.wait(timeout=1)
        assert child.returncode==0,'HElib public preflight failed'
    except Exception as e:error=str(e)
    finally:
        if child.poll() is None:
            assert os.getpgid(child.pid)==child.pid
            os.killpg(child.pid,signal.SIGKILL)
        child.wait(timeout=10);selector.close()
    output=b''.join(chunks).decode('utf-8',errors='replace');results=[]
    for line in output.splitlines():
        try:results.append(json.loads(line))
        except json.JSONDecodeError:pass
    same=bound=={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    if len(results)!=1 or results[0].get('status')!='HELIB_LARGER_CARRIER_PUBLIC_PASS' or not same:
        error=error or 'Invalid result or changed sources'
    receipt=dict(status='PASS' if error is None else 'FAIL',error=error,
          limits=dict(address_space_bytes=ADDRESS_SPACE,output_capture_bytes=OUTPUT,wall_seconds=WALL,cpu_seconds=CPU),
          peak_child_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
          child_exit_code=child.returncode,source_manifest=bound,sources_unchanged=same,
          result=results[0] if len(results)==1 else None,
          scope='One Linux public carrier/codec screen; library estimate is not security certification; no keys, ciphertexts or timings')
    if error:receipt['diagnostic']=output[-8192:]
    print(json.dumps(receipt));return int(error is not None)


if __name__=='__main__':
    raise SystemExit(main())
