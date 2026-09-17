"""Build an isolated exact fixed-multiplier candidate from the frozen extension backend."""
from pathlib import Path
from hashlib import sha256
import json,subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
BASE=HERE.parent/'native-extension-axis-v1'
COMPILER=Path('/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-g++')
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
def replace_one(text,old,new):
    assert text.count(old)==1,(old,text.count(old))
    return text.replace(old,new)
def main():
    assert not (HERE/'build.json').exists(),'Preserve earlier build'
    prior=json.loads((BASE/'build.json').read_text())
    for name,want in prior['candidate_files'].items():assert binding(BASE/name)==want,name
    paths=list((BASE/'backend').glob('*.cpp'))+[BASE/x for x in ['extension_binding.py','extension_crypto.py','extension_worker.py','run.py','check_candidate.py','build.json']]
    paths += [HERE/x for x in ['PLAN.md','PROOF.md','WORKFLOW_PLAN.md','prepare.py','run.py','check_candidate.py']]
    before={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    (HERE/'backend').mkdir();(HERE/'build').mkdir()
    for path in (BASE/'backend').glob('*.cpp'):
        text=path.read_text()
        if path.name=='composition_native_core.cpp':
            text=replace_one(text,'V twists,untwists;','V twists,untwists,twist_quotients,untwist_quotients;')
            text=replace_one(text,'twists(n),untwists(n) {','twists(n),untwists(n),twist_quotients(n),untwist_quotients(n) {')
            anchor='for(unsigned j=1;j<n;++j){twists[j]=mul(twists[j-1],root,p);untwists[j]=mul(untwists[j-1],inverse,p);}'
            text=replace_one(text,anchor,anchor+'\n        for(unsigned j=0;j<n;++j){twist_quotients[j]=U((Wide(twists[j])<<64)/p);untwist_quotients[j]=U((Wide(untwists[j])<<64)/p);}')
            text=replace_one(text,'mul(y[j],untwists[j],p)','shoup(y[j],untwists[j],untwist_quotients[j],p)')
            text=replace_one(text,'mul(y[j],twists[j],p)','shoup(y[j],twists[j],twist_quotients[j],p)')
            text=replace_one(text,'std::array<V,2> kernels;','std::array<V,2> kernels,kernel_quotients;')
            anchor='for(auto& kernel:kernels)for(auto& x:kernel)x=mul(x,invn,p);'
            text=replace_one(text,anchor,anchor+'\n        for(unsigned side=0;side<2;++side){kernel_quotients[side].resize(n);for(unsigned j=0;j<n;++j)kernel_quotients[side][j]=U((Wide(kernels[side][j])<<64)/p);}')
            text=replace_one(text,'mul(spectrum[j],kernels[inverse][j],p)','shoup(spectrum[j],kernels[inverse][j],kernel_quotients[inverse][j],p)')
            text=replace_one(text,'mul(x,d.kernels[inverse][j],p)','shoup(x,d.kernels[inverse][j],d.kernel_quotients[inverse][j],p)')
            text=replace_one(text,'mul(out[i*256+e],twist,p)','shoup(out[i*256+e],twist,d.twist_quotients[i],p)')
            text=replace_one(text,'mul(x,d.untwists[i],p)','shoup(x,d.untwists[i],d.untwist_quotients[i],p)')
        (HERE/'backend'/path.name).write_text(text)
    (HERE/'fixed_binding.py').write_text((BASE/'extension_binding.py').read_text().replace('extension_core.so','fixed_core.so'))
    (HERE/'fixed_crypto.py').write_text((BASE/'extension_crypto.py').read_text().replace('from extension_binding import','from fixed_binding import'))
    text=(BASE/'extension_worker.py').read_text()
    text=text.replace('from tensor_crypto import SlimRing as TensorRing','from extension_crypto import SlimRing as BaselineRing')
    text=text.replace('from extension_crypto import SlimRing as ExtensionRing','from fixed_crypto import SlimRing as FixedRing')
    text=text.replace('class ExtensionWorker(Worker):','class FixedWorker(Worker):')
    text=text.replace("('baseline','extension')","('baseline','fixed')")
    text=text.replace("ExtensionRing() if self.variant=='extension' else TensorRing()","FixedRing() if self.variant=='fixed' else BaselineRing()")
    (HERE/'fixed_worker.py').write_text(text)
    command=[str(COMPILER),'-std=c++17','-O3','-DNDEBUG','-fPIC','-shared',str(HERE/'backend/fast_core_v1.cpp'),'-o',str(HERE/'build/fixed_core.so')]
    run=subprocess.run(command,capture_output=True,timeout=120)
    (HERE/'build.stdout.txt').write_bytes(run.stdout);(HERE/'build.stderr.txt').write_bytes(run.stderr)
    assert before=={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    names=['fixed_binding.py','fixed_crypto.py','fixed_worker.py','build/fixed_core.so']+[p.relative_to(HERE).as_posix() for p in (HERE/'backend').glob('*.cpp')]
    record=dict(status='NATIVE_FIXED_MULTIPLIER_BUILD_PASS' if run.returncode==0 else 'BUILD_FAILURE',returncode=run.returncode,command=command,compiler=binding(COMPILER),compiler_version=subprocess.check_output([str(COMPILER),'--version'],text=True),source_bindings=before,candidate_files={x:binding(HERE/x) for x in names if (HERE/x).exists()},new_he_execution=False,security_bits=None)
    (HERE/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'status':record['status'],'returncode':run.returncode,'source_files':len(before)}),flush=True)
    assert run.returncode==0,run.stderr.decode(errors='replace')
if __name__=='__main__':main()
