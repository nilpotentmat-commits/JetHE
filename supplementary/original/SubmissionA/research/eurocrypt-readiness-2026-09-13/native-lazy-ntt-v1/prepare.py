"""Derive and separately build the lazy-reduction exact transform."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
FAST=HERE.parents[1]/'jethe-throughput-redesign-2026-09-13'
ROOT=HERE.parents[3]
PREVIOUS=HERE.parent/'native-tuning-v1'
COMPILER=Path('/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-g++')

def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())

def main():
    assert not (HERE/'build.json').exists(),'Preserve prior build'
    paths=list((FAST/'backend-v2').glob('*.cpp'))+[FAST/'slim_ring_base_v2.py',FAST/'slim_crypto_v2.py',PREVIOUS/'check_candidate.py']
    before={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    (HERE/'backend').mkdir(exist_ok=True);(HERE/'build').mkdir(exist_ok=True)
    for p in (FAST/'backend-v2').glob('*.cpp'):
        text=p.read_text()
        if p.name=='composition_native_core.cpp':
            begin=text.index('    V run(const V& input) const {')
            end=text.index('\n};',begin)
            text=text[:begin]+(HERE/'ntt-run.cpp.inc').read_text()+text[end:]
        if p.name=='fast_core_v1.cpp':
            text += """
API int jc_lazy_check(const U* x,const U* w,U* out,unsigned count,unsigned channel) {
    BEGIN need(channel<4,"channel");const U p=primes[channel];
    for(unsigned i=0;i<count;++i) {
        need(x[i]<4*p&&w[i]<p,"lazy range");
        const U pre=U((Wide(w[i])<<64)/p);
        const U quo=U((Wide(x[i])*pre)>>64);
        out[i]=x[i]*w[i]-quo*p;
    } END
}
"""
        (HERE/'backend'/p.name).write_text(text)
    text=(FAST/'slim_ring_base_v2.py').read_text().replace('RESEARCH = HERE.parent','RESEARCH = HERE.parents[1]')
    text=text.replace("LIBRARY = HERE / 'build' / 'fast_core_v2.so'","LIBRARY = HERE / 'build' / 'lazy_core.so'")
    (HERE/'candidate_binding.py').write_text(text)
    text=(FAST/'slim_crypto_v2.py').read_text().replace('from slim_ring_base_v2 import SlimRingBase','from candidate_binding import SlimRingBase')
    (HERE/'candidate_crypto.py').write_text(text)
    text=(PREVIOUS/'check_candidate.py').read_text().replace('build/host_core.so','build/lazy_core.so').replace('NATIVE_HOST_BACKEND_PUBLIC_CORRESPONDENCE_PASS','NATIVE_LAZY_NTT_BACKEND_PUBLIC_CORRESPONDENCE_PASS')
    (HERE/'check_candidate.py').write_text(text)
    command=[str(COMPILER),'-std=c++17','-O3','-DNDEBUG','-fPIC','-shared',str(HERE/'backend/fast_core_v1.cpp'),'-o',str(HERE/'build/lazy_core.so')]
    run=subprocess.run(command,capture_output=True,timeout=120)
    (HERE/'build.stdout.txt').write_bytes(run.stdout);(HERE/'build.stderr.txt').write_bytes(run.stderr)
    assert run.returncode==0,run.stderr.decode(errors='replace')
    assert before=={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    names=['PLAN.md','prepare.py','ntt-run.cpp.inc','PROOF.md','candidate_binding.py','candidate_crypto.py','check_candidate.py','build/lazy_core.so']
    names += [p.relative_to(HERE).as_posix() for p in (HERE/'backend').glob('*.cpp')]
    result=dict(status='NATIVE_LAZY_NTT_BUILD_PASS',returncode=run.returncode,command=command,
        compiler=binding(COMPILER),compiler_version=subprocess.check_output([str(COMPILER),'--version'],text=True),
        source_bindings=before,candidate_files={n:binding(HERE/n) for n in names},
        unchanged_baseline_library=binding(FAST/'build/fast_core_v2.so'),new_he_execution=False)
    (HERE/'build.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],source_files=len(before),library=result['candidate_files']['build/lazy_core.so'])))

if __name__=='__main__':main()
