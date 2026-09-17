"""Native public trace and sampled spectral matrix checks. No PKE or timing arm."""
from array import array
from collections import Counter
from hashlib import sha256
from pathlib import Path
import json,os,resource,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;READY=HERE.parent;ROOT=HERE.parents[3]
FIXED=READY/'native-fixed-multipliers-v1';STAGE=READY/'native-stage-gadgets-v1'
sys.path.insert(0,str(READY/'same-algebra-one-prime-workflow-v1'))
import common
sys.path[:0]=[str(HERE),str(FIXED),str(STAGE)]
from fixed_crypto import SlimRing
from composition_full_run import Cipher,Bank,Bundle,assert_public
import stage_public,matrix_public
from matrix_arithmetic import rectangular


def binding(p):
    data=p.read_bytes();return dict(bytes=len(data),sha256=sha256(data).hexdigest())


def digest(arrays):
    h=sha256()
    for a in arrays:h.update(a)
    return h.hexdigest()


def fixture_digest(bundle):
    return digest([v for c in bundle.inputs.values() for v in c.components]
                  +[v for b in bundle.banks.values() for row in b.rows for v in row]
                  +[v for c in bundle.public_keys for v in c.components])


def main():
    assert not (HERE/'public-check.json').exists(),'Preserve previous check'
    resource.setrlimit(resource.RLIMIT_AS,(3<<30,3<<30))
    resource.setrlimit(resource.RLIMIT_CPU,(240,240));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.sched_setaffinity(0,{0})
    frozen=json.loads((FIXED/'verification.json').read_text())['source_bindings']
    for name,want in frozen.items():assert binding(ROOT/name)==want,name
    own={p.relative_to(ROOT).as_posix():binding(p) for p in HERE.iterdir() if p.suffix in ('.py','.md')}
    ring=SlimRing();counts=Counter();shape_records=[]
    assert str(ring.dll._name)==str(FIXED/'build/fixed_core.so')
    runtime={str(Path(ring.dll._name).relative_to(ROOT)):binding(Path(ring.dll._name)),
             str(Path(ring.terminal_dll._name).relative_to(ROOT)):binding(Path(ring.terminal_dll._name))}
    try:
        n=ring.dimension;salt=0
        def spectrum(a):
            nonlocal salt
            salt+=1
            return array('Q',((i*6364136223846793005+salt*1442695040888963407)%p
                             for p in ring.primes[:a] for i in range(n)))
        inputs={}
        for name in stage_public.INPUT_NAMES:
            key='h'+name[1:] if name.startswith('u') else 's0';a=stage_public.LIMBS[key]
            inputs[name]=Cipher(key,a,(spectrum(a),spectrum(a)))
        banks={}
        for name,src,dst,a,kind in stage_public.catalog():
            g=ring.gadget(a,stage_public.WIDTH_BY_VERTEX[dst])
            banks[name]=Bank(src,dst,a,kind,tuple((spectrum(a),spectrum(a)) for _ in range(g)))
        pks=tuple(Cipher(key,stage_public.LIMBS[key],(spectrum(stage_public.LIMBS[key]),spectrum(stage_public.LIMBS[key]))) for key in stage_public.PK_NAMES)
        bundle=Bundle(inputs,banks,pks);assert_public(bundle);origin=fixture_digest(bundle)
        baseline=stage_public.evaluate(ring,bundle,True)
        virtual=matrix_public.prepare(ring,bundle)
        observed={};candidate=matrix_public.evaluate(ring,bundle,virtual,True,observed)
        assert len(baseline)==len(candidate)==22
        for left,right in zip(baseline,candidate):
            assert (left.key,left.limbs,len(left.components))==(right.key,right.limbs,len(right.components))
            for x,y in zip(left.components,right.components):
                assert x==y;counts['complete_retained_state_words']+=len(x)
        assert fixture_digest(bundle)==origin
        baseline_hashes=[digest(x.components) for x in baseline]
        candidate_hashes=[digest(x.components) for x in candidate]
        for r in stage_public.TAIL:
            e=2*r;ell=256//e;a=stage_public.LIMBS[f'h{r}'];g=len(virtual[r][0])
            h0=ring.hasse_spectrum(observed[r]['current'].components[0],a,r)
            for channel,p in enumerate(ring.primes[:a]):
                alpha=pow((38,14,7)[channel],(p-1)//512,p)
                for u,zeta in ((0,0),(ell-1,255)):
                    A=[[virtual[r][i][j][v][channel*n+(u+ell*k)*256+zeta]
                        for i in range(e) for j in range(g)] for v in range(2) for k in range(e)]
                    for B in sorted(set((1,3,e,e+1))):
                        D=[]
                        for i in range(e):
                            for j in range(g):
                                first=observed[r]['compact'][j][channel*n+i*ell*256+u*256+zeta]
                                D.append([first]+[(first+((b+1)*65537+i*8191+j*997)*(b+3))%p for b in range(1,B)])
                        oracle=[]
                        for v in range(2):
                            for k in range(e):
                                loc=channel*n+(u+ell*k)*256+zeta
                                t=pow(alpha,2*(u+ell*k)+1,p);tr=pow(t,r,p)
                                values=[]
                                for b in range(B):
                                    value=0
                                    for j in range(g):
                                        identity=0
                                        for i in range(r):
                                            even=D[i*g+j][b];odd=D[(i+r)*g+j][b]
                                            value+=(even-tr*odd)*banks[f'h{r}_{i}'].rows[j][v][loc]
                                            identity+=pow(t,i,p)*odd
                                        value+=identity*banks[f'h{r}_identity'].rows[j][v][loc]
                                    values.append(value%p)
                                expected=(observed[r]['bank_result'][v][loc]-(h0[loc] if v==0 else 0))%p
                                assert values[0]==expected;counts['compiled_bank_coordinate_checks']+=1
                                oracle.append(values)
                        for s in range(e.bit_length()):
                            for cache in (False,True):
                                out,ops,public=rectangular(A,D,e,g,B,s,cache,p)
                                assert out==oracle
                                counts['matrix_output_residues']+=2*e*B
                                counts['matrix_configurations']+=1
                        shape_records.append(dict(order=r,limbs=a,channel=channel,u=u,zeta=zeta,batches=B,digits=g))
        assert fixture_digest(bundle)==origin
        assert [digest(x.components) for x in baseline]==baseline_hashes
        assert [digest(x.components) for x in candidate]==candidate_hashes
    finally:ring.close()
    for name,want in frozen.items():assert binding(ROOT/name)==want,name
    for name,want in own.items():assert binding(ROOT/name)==want,name
    for name,want in runtime.items():assert binding(ROOT/name)==want,name
    imported={Path(m.__file__).resolve() for m in tuple(sys.modules.values()) if getattr(m,'__file__',None) and Path(m.__file__).resolve().is_relative_to(ROOT)}
    sources={p.relative_to(ROOT).as_posix():binding(p) for p in imported}
    sources.update(own)
    out=dict(status='NATIVE_PAID_SPECTRAL_MATRIX_PUBLIC_CHECK_PASS',new_he_execution=False,
             new_arithmetic_binary=False,performance_benchmark=False,security_bits=None,
             public_fixture_sha256=origin,trace_states=22,counts=dict(counts),shapes=shape_records,
             source_bindings=sources,protected_measured_source_bindings=frozen,runtime_bindings=runtime,
             baseline_trace_sha256=baseline_hashes,candidate_trace_sha256=candidate_hashes,
             fixture_type='PUBLIC_CIPHERTEXT_SHAPED_ARRAYS_NOT_PKE',
             scope='Full native virtual-row trace; scalar matrix variants checked on sampled native coordinates')
    (HERE/'public-check.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({k:v for k,v in out.items() if k in ('status','counts','trace_states','new_he_execution','scope')},indent=2))


if __name__=='__main__':main()
