"""Compile only the exact cache-quotient replacement; retain the failed version."""
from pathlib import Path
from hashlib import sha256
import json,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
OLD=HERE.parent/'native-cached-matrix-v1'
COMPILER=Path('/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-g++')


def binding(p):
    d=p.read_bytes();return dict(bytes=len(d),sha256=sha256(d).hexdigest())


def main():
    assert not (HERE/'build.json').exists(),'Preserve earlier build'
    paths=[HERE/n for n in ('PLAN.md','PROOF.md','prepare.py','check_preparation.py','check_formula.py','formula.json')]
    paths += [OLD/n for n in ('matrix.cpp','arithmetic.hpp','matrix_binding.py','build/matrix.so','group_public.py','RESULTS.md','public-check.json')]
    before={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    original=(OLD/'matrix.cpp').read_text()
    helper='''static U fast_quotient(U w,U p) {
    const U base=U(1)<<60,mask=base-1,c=base-p;
    const Wide t=(Wide(w)*c)<<4;
    const U a=U(t>>60);
    const Wide s=(U(t)&mask)+Wide(a)*c;
    const U d=U(s>>60),v=(U(s)&mask)+d*c;
    return (w<<4)+a+d+U(v>=p);
}
'''
    needle='extern "C" void* jet_matrix_create('
    assert original.count(needle)==1
    modified=original.replace(needle,helper+needle)
    old='U((Wide(values[leaf])<<64)/p)'
    assert modified.count(old)==1
    modified=modified.replace(old,'fast_quotient(values[leaf],p)')
    test='''
extern "C" int jet_fast_quotient_check(const U* input,U* output,size_t n,U p) {
    const U base=U(1)<<60;
    if(!input||!output||n>1000000||p>base||p<=base-(U(1)<<31))return 1;
    if(overlap(input,n,output,n))return 2;
    for(size_t i=0;i<n;++i)if(input[i]>=p)return 3;
    for(size_t i=0;i<n;++i)output[i]=fast_quotient(input[i],p);
    return 0;
}
'''
    modified+=test
    assert modified.replace(helper,'').replace('fast_quotient(values[leaf],p)',old).removesuffix(test)==original
    (HERE/'matrix_fast.cpp').write_text(modified)
    (HERE/'arithmetic.hpp').write_bytes((OLD/'arithmetic.hpp').read_bytes())
    binding_source=(OLD/'matrix_binding.py').read_text()
    assert binding_source.count("LIBRARY=HERE/'build/matrix.so'")==1
    binding_source=binding_source.replace("LIBRARY=HERE/'build/matrix.so'","LIBRARY=HERE/'build/matrix_fast.so'").replace('class CachedMatrix:','class FastCachedMatrix:')
    (HERE/'fast_binding.py').write_text(binding_source)
    (HERE/'build').mkdir(exist_ok=True)
    command=[str(COMPILER),'-std=c++17','-O3','-DNDEBUG','-fPIC','-shared',str(HERE/'matrix_fast.cpp'),'-o',str(HERE/'build/matrix_fast.so')]
    run=subprocess.run(command,capture_output=True,timeout=120)
    (HERE/'build.stdout.txt').write_bytes(run.stdout);(HERE/'build.stderr.txt').write_bytes(run.stderr)
    assert before=={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    out=dict(status='FAST_CACHE_QUOTIENT_BUILD_PASS' if run.returncode==0 else 'BUILD_FAILURE',actual_exit_code=run.returncode,
             command=command,compiler=binding(COMPILER),source_bindings=before,
             artifacts={n:binding(HERE/n) for n in ('matrix_fast.cpp','arithmetic.hpp','fast_binding.py','build/matrix_fast.so') if (HERE/n).exists()},
             unchanged_runtime_algorithm_source=True,unchanged_cache_layout=True,
             source_delta='One cache-preparation quotient expression, its exact helper and a public scalar-check entrypoint',
             new_he_execution=False)
    (HERE/'build.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({k:v for k,v in out.items() if k in ('status','actual_exit_code','source_delta')},indent=2));sys.exit(run.returncode)


if __name__=='__main__':main()
