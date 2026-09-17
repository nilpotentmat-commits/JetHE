"""Build the isolated matrix helper and preserve the measured libraries."""
from pathlib import Path
from hashlib import sha256
import json,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];READY=HERE.parent
FIXED=READY/'native-fixed-multipliers-v1'
COMPILER=Path('/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-g++')


def binding(p):
    d=p.read_bytes();return dict(bytes=len(d),sha256=sha256(d).hexdigest())


def main():
    assert not (HERE/'build.json').exists(),'Preserve earlier build'
    inputs=[p for p in HERE.iterdir() if p.suffix in ('.py','.cpp','.md')]
    inputs += [READY/'native-batched-hasse-v1'/n for n in ('IMPLEMENTATION_PLAN.md','PROOF.md','selection.json')]
    inputs += [FIXED/'backend/composition_native_core.cpp',FIXED/'build/fixed_core.so',FIXED/'fixed_crypto.py',
               FIXED/'fixed_binding.py',READY/'native-stage-gadgets-v1/stage_public.py']
    before={p.relative_to(ROOT).as_posix():binding(p) for p in inputs}
    source=(FIXED/'backend/composition_native_core.cpp').read_text()
    arithmetic=source[source.index('static U add('):source.index('static U signed_residue(')]
    (HERE/'arithmetic.hpp').write_text(arithmetic)
    (HERE/'build').mkdir(exist_ok=True)
    command=[str(COMPILER),'-std=c++17','-O3','-DNDEBUG','-fPIC','-shared',str(HERE/'matrix.cpp'),'-o',str(HERE/'build/matrix.so')]
    run=subprocess.run(command,capture_output=True,timeout=120)
    (HERE/'build.stdout.txt').write_bytes(run.stdout);(HERE/'build.stderr.txt').write_bytes(run.stderr)
    assert before=={p.relative_to(ROOT).as_posix():binding(p) for p in inputs}
    out=dict(status='ISOLATED_CACHED_MATRIX_BUILD_PASS' if run.returncode==0 else 'BUILD_FAILURE',actual_exit_code=run.returncode,
             command=command,compiler=binding(COMPILER),source_bindings=before,
             artifacts={n:binding(HERE/n) for n in ('arithmetic.hpp','build/matrix.so') if (HERE/n).exists()},
             preserved_native_library=binding(FIXED/'build/fixed_core.so'),new_he_execution=False)
    (HERE/'build.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({k:v for k,v in out.items() if k in ('status','actual_exit_code','preserved_native_library')},indent=2))
    sys.exit(run.returncode)


if __name__=='__main__':main()
