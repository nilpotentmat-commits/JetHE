"""Source-bound Linux caps for a public layout check or one untimed BSGS run."""
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
    from composition_fixture import metadata
    executable=root/'build'/'helib-diagonal-bsgs'/'helib_diagonal_bsgs'
    here=Path(__file__).resolve().parent
    paths=[Path(__file__).resolve(),here/'diagonal_bsgs.cpp',here/'composition_fixture.h',
           here/'diagonal'/'CMakeLists.txt',root/'research'/'composition_fixture.py',executable]
    bound={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    address_space,output_limit=2<<30,2<<20
    wall,cpu=(150,120) if mode=='public' else (300,240)

    def limits():
        resource.setrlimit(resource.RLIMIT_AS,(address_space,address_space))
        resource.setrlimit(resource.RLIMIT_CPU,(cpu,cpu))
        resource.setrlimit(resource.RLIMIT_FSIZE,(output_limit,output_limit))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))

    argument='--public-layout' if mode=='public' else '--encrypted-b16'
    child=subprocess.Popen([str(executable),argument],cwd=executable.parent,
          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=limits)
    selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
    chunks=[];size=0;error=None;began=time.monotonic()
    try:
        while selector.get_map():
            if time.monotonic()-began>wall:raise TimeoutError('Diagonal correctness wall cap')
            for key,_ in selector.select(0.1):
                block=os.read(key.fileobj.fileno(),65536)
                if not block:selector.unregister(key.fileobj);continue
                size+=len(block)
                if size>output_limit:raise RuntimeError('Diagonal correctness output cap')
                chunks.append(block)
        child.wait(timeout=1)
        assert child.returncode==0,'Diagonal correctness child failed'
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
    expected='HELIB_DIAGONAL_LAYOUT_PASS' if mode=='public' else 'HELIB_DIAGONAL_B16_ENCRYPTED_PASS'
    fixture=metadata()
    if len(results)!=1 or results[0].get('status')!=expected or not same:
        error=error or 'Invalid result or changed sources'
    else:
        r=results[0]
        if r.get('fixture_fnv64')!=fixture['fnv64_cross_language_check']:
            error=error or 'Fixture fingerprint mismatch'
        required=dict(generators=[8996,21591],orders=[16,64],native_giant_axis=0,slots=1024)
        if mode=='public':required.update(keys_generated=0,polynomial_automorphisms_checked=15,rotated_field_symbols_checked=15360,units_checked=16384)
        else:required.update(symbols_checked=1024,fresh_encryptions=271,owner_codec_roundtrips=271,
               private_products=255,group_relinearizations=16,physical_automorphisms=15,
               rotation_key_switches=15,raw_group_additions=239,canonical_output_additions=15,
               public_mask_multiplications=0,key_switch_matrices=16,fixture_jobs=[0,1,2,3],
               direct_rotation_matrices_checked=15,automorphism_recording_disabled=True)
        if any(r.get(k)!=v for k,v in required.items()):error=error or 'Wrong checked/executed inventory'
    receipt=dict(status='PASS' if error is None else 'FAIL',mode=mode,error=error,
          limits=dict(address_space_bytes=address_space,output_capture_bytes=output_limit,wall_seconds=wall,cpu_seconds=cpu),
          peak_child_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
          child_exit_code=child.returncode,source_manifest=bound,sources_unchanged=same,
          fixture=fixture,result=results[0] if len(results)==1 else None,
          events=[x for x in records if 'event' in x],
          scope='Linux bounded correctness only; stock BGV cyclic hints; no benchmark, optimality, native security transfer or process isolation')
    if error:receipt['diagnostic']=output[-8192:]
    print(json.dumps(receipt));return int(error is not None)


if __name__=='__main__':raise SystemExit(main())
