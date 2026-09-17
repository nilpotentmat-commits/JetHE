"""Derive an isolated extension-axis implementation from the current tensor backend."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
TENSOR=HERE.parent/'native-tensor-axis-v1'
COMPILER=Path('/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-g++')
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
def main():
    assert not (HERE/'build.json').exists(),'Preserve earlier build'
    prior=json.loads((TENSOR/'build.json').read_text())
    for name,want in prior['candidate_files'].items():assert binding(TENSOR/name)==want,name
    paths=list((TENSOR/'backend').glob('*.cpp'))+[TENSOR/n for n in ['tensor_binding.py','tensor_crypto.py','tensor_worker.py','run.py','build.json','check_candidate.py']]
    paths += [HERE/n for n in ['PLAN.md','PROOF.md','WORKFLOW_PLAN.md','extension.cpp.inc','prepare.py','check_candidate.py','run.py']]
    before={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    (HERE/'backend').mkdir(exist_ok=True);(HERE/'build').mkdir(exist_ok=True)
    for p in (TENSOR/'backend').glob('*.cpp'):
        text=p.read_text()
        if p.name=='composition_native_core.cpp':
            start=text.index('        auto extension=[&](){')
            end=text.index('        auto first_axis=[&](){',start)
            text=text[:start]+(HERE/'extension.cpp.inc').read_text()+text[end:]
        (HERE/'backend'/p.name).write_text(text)
    text=(TENSOR/'tensor_binding.py').read_text().replace('tensor_core.so','extension_core.so')
    (HERE/'extension_binding.py').write_text(text)
    text=(TENSOR/'tensor_crypto.py').read_text().replace('from tensor_binding import SlimRingBase','from extension_binding import SlimRingBase')
    (HERE/'extension_crypto.py').write_text(text)
    text=(TENSOR/'tensor_worker.py').read_text().replace('from stage_crypto import SlimRing as StageRing','from extension_crypto import SlimRing as ExtensionRing')
    text=text.replace('class TensorWorker(Worker):','class ExtensionWorker(Worker):').replace("('baseline','tensor')","('baseline','extension')")
    text=text.replace("TensorRing() if self.variant=='tensor' else StageRing()","ExtensionRing() if self.variant=='extension' else TensorRing()")
    (HERE/'extension_worker.py').write_text(text)
    command=[str(COMPILER),'-std=c++17','-O3','-DNDEBUG','-fPIC','-shared',str(HERE/'backend/fast_core_v1.cpp'),'-o',str(HERE/'build/extension_core.so')]
    run=subprocess.run(command,capture_output=True,timeout=120)
    (HERE/'build.stdout.txt').write_bytes(run.stdout);(HERE/'build.stderr.txt').write_bytes(run.stderr)
    assert before=={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    names=['extension_binding.py','extension_crypto.py','extension_worker.py','build/extension_core.so']
    names += [p.relative_to(HERE).as_posix() for p in (HERE/'backend').glob('*.cpp')]
    result=dict(status='NATIVE_EXTENSION_AXIS_BUILD_PASS' if run.returncode==0 else 'BUILD_FAILURE',returncode=run.returncode,
        command=command,compiler=binding(COMPILER),compiler_version=subprocess.check_output([str(COMPILER),'--version'],text=True),
        source_bindings=before,candidate_files={n:binding(HERE/n) for n in names if (HERE/n).exists()},new_he_execution=False,security_bits=None)
    (HERE/'build.json').write_text(json.dumps(result,indent=2)+'\n')
    assert run.returncode==0,run.stderr.decode(errors='replace')
    print(json.dumps(dict(status=result['status'],source_files=len(before),library=result['candidate_files']['build/extension_core.so'])))
if __name__=='__main__':main()
