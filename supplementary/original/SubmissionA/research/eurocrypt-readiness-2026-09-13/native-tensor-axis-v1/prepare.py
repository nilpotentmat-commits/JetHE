"""Derive a separately linked tensor-axis implementation from current stage sources."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
STAGE=HERE.parent/'native-stage-gadgets-v1'
COMPILER=Path('/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-g++')
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())

def main():
    assert not (HERE/'build.json').exists(),'Preserve earlier build'
    prior=json.loads((STAGE/'build.json').read_text())
    for name,want in prior['candidate_files'].items():assert binding(STAGE/name)==want,name
    paths=list((STAGE/'backend').glob('*.cpp'))+[STAGE/n for n in ['stage_binding.py','stage_crypto.py','stage_worker.py','run.py','build.json']]
    paths += [HERE/n for n in ['PLAN.md','PROOF.md','WORKFLOW_PLAN.md','axis.cpp.inc','prepare.py','check_candidate.py']]
    before={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    (HERE/'backend').mkdir(exist_ok=True);(HERE/'build').mkdir(exist_ok=True)
    for p in (STAGE/'backend').glob('*.cpp'):
        text=p.read_text()
        if p.name=='composition_native_core.cpp':
            start=text.index('        auto first_axis=[&](){')
            end=text.index('        if(inverse){extension();first_axis();}',start)
            text=text[:start]+(HERE/'axis.cpp.inc').read_text()+text[end:]
        (HERE/'backend'/p.name).write_text(text)
    text=(STAGE/'stage_binding.py').read_text().replace("'stage_core.so'","'tensor_core.so'")
    (HERE/'tensor_binding.py').write_text(text)
    text=(STAGE/'stage_crypto.py').read_text().replace('from stage_binding import SlimRingBase','from tensor_binding import SlimRingBase')
    (HERE/'tensor_crypto.py').write_text(text)
    text=(STAGE/'stage_worker.py').read_text().replace('from candidate_crypto import SlimRing as LazyRing','from tensor_crypto import SlimRing as TensorRing')
    text=text.replace('class StageWorker(Worker):','class TensorWorker(Worker):')
    text=text.replace("('baseline','stage')","('baseline','tensor')")
    text=text.replace("self.native=stage_public if variant=='stage' else native","self.native=stage_public")
    text=text.replace("StageRing() if self.variant=='stage' else LazyRing()","TensorRing() if self.variant=='tensor' else StageRing()")
    text=text.replace("(297 if self.variant=='stage' else 391)",'297')
    text=text.replace("(107 if self.variant=='stage' else 139)",'107')
    (HERE/'tensor_worker.py').write_text(text)
    command=[str(COMPILER),'-std=c++17','-O3','-DNDEBUG','-fPIC','-shared',str(HERE/'backend/fast_core_v1.cpp'),'-o',str(HERE/'build/tensor_core.so')]
    run=subprocess.run(command,capture_output=True,timeout=120)
    (HERE/'build.stdout.txt').write_bytes(run.stdout);(HERE/'build.stderr.txt').write_bytes(run.stderr)
    assert before=={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    names=['tensor_binding.py','tensor_crypto.py','tensor_worker.py','build/tensor_core.so']
    names += [p.relative_to(HERE).as_posix() for p in (HERE/'backend').glob('*.cpp')]
    result=dict(status='NATIVE_TENSOR_AXIS_BUILD_PASS' if run.returncode==0 else 'BUILD_FAILURE',returncode=run.returncode,
        command=command,compiler=binding(COMPILER),compiler_version=subprocess.check_output([str(COMPILER),'--version'],text=True),
        source_bindings=before,candidate_files={n:binding(HERE/n) for n in names if (HERE/n).exists()},
        new_he_execution=False,security_bits=None)
    (HERE/'build.json').write_text(json.dumps(result,indent=2)+'\n')
    assert run.returncode==0,run.stderr.decode(errors='replace')
    print(json.dumps(dict(status=result['status'],source_files=len(before),library=result['candidate_files']['build/tensor_core.so'])))
if __name__=='__main__':main()
