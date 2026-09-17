"""Derive a separate width-aware implementation from the checked lazy backend."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
LAZY=HERE.parent/'native-lazy-ntt-v1'
FAST=HERE.parents[1]/'jethe-throughput-redesign-2026-09-13'
COMPILER=Path('/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-g++')
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
def main():
    assert not (HERE/'build.json').exists(),'Preserve prior build'
    admission=json.loads((HERE/'admission.json').read_text())
    assert admission['status']=='NATIVE_STAGE_GADGETS_CONDITIONAL_ADMISSION_PASS'
    for name,want in admission['bindings'].items():assert binding(ROOT/name)==want,name
    paths=list((LAZY/'backend').glob('*.cpp'))+[LAZY/'candidate_binding.py',LAZY/'candidate_crypto.py',
        FAST/'slim_public_v2.py',HERE/'PLAN.md',HERE/'PROOF.md',HERE/'bounds.py',HERE/'admission.json',
        HERE/'check_admission.py',Path(__file__),HERE/'relin.py.inc']
    before={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    (HERE/'backend').mkdir(exist_ok=True);(HERE/'build').mkdir(exist_ok=True)
    for p in (LAZY/'backend').glob('*.cpp'):
        value=p.read_text()
        if p.name=='composition_native_core.cpp':
            old='need(width==44||width==48||width==60,"supported gadget widths48/60");'
            assert value.count(old)==1
            value=value.replace(old,'need(width==40||width==44||width==45||width==48||width==60,"supported gadget widths40/44/45/48/60");')
        (HERE/'backend'/p.name).write_text(value)
    value=(LAZY/'candidate_binding.py').read_text().replace("'lazy_core.so'","'stage_core.so'")
    (HERE/'stage_binding.py').write_text(value)
    value=(LAZY/'candidate_crypto.py').read_text().replace('Same sampler, 44-bit gadget, lower creation moduli; no global patching.',
        'Same sampler, explicit stage gadgets and unchanged creation moduli.')
    value=value.replace('from candidate_binding import SlimRingBase','from stage_binding import SlimRingBase\nfrom bounds import WIDTH_BY_VERTEX')
    value=value.replace('def gadget(self,limbs,width=44):','def gadget(self,limbs,width):')
    value=value.replace('assert width==44 and 1<=limbs<=self.limbs','assert width in (40,45,60) and 1<=limbs<=self.limbs')
    value=value.replace('(self.moduli[limbs].bit_length()+43)//44','(self.moduli[limbs].bit_length()+width-1)//width')
    value=value.replace('def digits(self,spectrum,limbs,width=44):\n        assert width==44',
        'def digits(self,spectrum,limbs,width):\n        assert width in (40,45,60)')
    value=value.replace('self.gadget(limbs)','self.gadget(limbs,width)')
    value=value.replace('a=destination.limbs','a=destination.limbs\n    width=WIDTH_BY_VERTEX[destination.key]')
    value=value.replace('ring.gadget(a)','ring.gadget(a,width)').replace('ring.scale(payload,a,44*j)','ring.scale(payload,a,width*j)')
    value+='\n'+(HERE/'relin.py.inc').read_text()
    (HERE/'stage_crypto.py').write_text(value)
    value=(FAST/'slim_public_v2.py').read_text().replace("OLD = HERE.parent/'existing-results-revision-2026-09-13'",
        "OLD = HERE.parents[1]/'existing-results-revision-2026-09-13'")
    value=value.replace('from slim_crypto_v2 import','from stage_crypto import')
    value=value.replace('from stage_crypto import make_bank','from stage_crypto import make_bank,relin')
    value=value.replace('from analysis.slim_bounds_v2 import FRESH, WIDTH, CHAIN, trace_spec',
        'from bounds import FRESH, CHAIN, trace_spec, WIDTH_BY_VERTEX')
    value=value.replace('== 134 and coins.errors == 139','== 102 and coins.errors == 107')
    value=value.replace('ring.gadget(a)','ring.gadget(a,WIDTH_BY_VERTEX[dst])')
    value=value.replace('ring.digits(current.components[1],a)',"ring.digits(current.components[1],a,WIDTH_BY_VERTEX[f'h{r}'])")
    value=value[:value.index('\n\ndef decrypt(')]+'\n'
    (HERE/'stage_public.py').write_text(value)
    command=[str(COMPILER),'-std=c++17','-O3','-DNDEBUG','-fPIC','-shared',str(HERE/'backend/fast_core_v1.cpp'),'-o',str(HERE/'build/stage_core.so')]
    run=subprocess.run(command,capture_output=True,timeout=120)
    (HERE/'build.stdout.txt').write_bytes(run.stdout);(HERE/'build.stderr.txt').write_bytes(run.stderr)
    assert before=={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    names=['stage_binding.py','stage_crypto.py','stage_public.py','build/stage_core.so']
    names += [p.relative_to(HERE).as_posix() for p in (HERE/'backend').glob('*.cpp')]
    result=dict(status='NATIVE_STAGE_GADGETS_BUILD_PASS' if run.returncode==0 else 'BUILD_FAILURE',returncode=run.returncode,
        command=command,compiler=binding(COMPILER),compiler_version=subprocess.check_output([str(COMPILER),'--version'],text=True),
        source_bindings=before,candidate_files={n:binding(HERE/n) for n in names if (HERE/n).exists()},
        new_he_execution=False,security_bits=None)
    (HERE/'build.json').write_text(json.dumps(result,indent=2)+'\n')
    assert run.returncode==0,run.stderr.decode(errors='replace')
    print(json.dumps(dict(status=result['status'],source_files=len(before),library=result['candidate_files']['build/stage_core.so'])))
if __name__=='__main__':main()
