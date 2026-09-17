"""Public arithmetic correspondence and an explicitly limited kernel screen."""
from array import array
from collections import Counter
import ctypes as C
from hashlib import sha256
import json
import os
from pathlib import Path
from random import Random
import resource
from statistics import median
import sys
from time import perf_counter

HERE=Path(__file__).resolve().parent
FAST=HERE.parents[1]/'jethe-throughput-redesign-2026-09-13'
ROOT=HERE.parents[3]
STAGE=HERE.parent/'native-stage-gadgets-v1'
TENSOR=HERE.parent/'native-tensor-axis-v1'
sys.path[:0]=[str(HERE),str(HERE.parent/'same-algebra-one-prime-workflow-v1'),str(STAGE),str(TENSOR)]
import common
from tensor_crypto import SlimRing as BaselineRing
from extension_crypto import SlimRing as CandidateRing
from fast_crypto_v1 import encrypt
from composition_full_run import Cipher
from composition_native import P,pointer

def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())

def main():
    assert not (HERE/'public-check.json').exists(),'Preserve previous check'
    resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
    resource.setrlimit(resource.RLIMIT_CPU,(180,180))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.sched_setaffinity(0,{0})
    build=json.loads((HERE/'build.json').read_text())
    for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
    for name,want in build['candidate_files'].items():assert binding(HERE/name)==want,name
    baseline,candidate=BaselineRing(),CandidateRing()
    assert str(candidate.dll._name)==str(HERE/'build/extension_core.so')
    rng=Random(2026091401)
    counts=Counter()
    def equal(a,b,family):
        assert a==b,family
        counts[family]+=len(a) if hasattr(a,'__len__') else 1
    try:
        for channel,p in enumerate(baseline.primes):
            edges=[0,1,2,p-1,p-2,p//2,(1<<59)-1,1<<59]
            pairs=[(x,y) for x in edges for y in edges]
            pairs.extend((rng.randrange(p),rng.randrange(p)) for _ in range(25000))
            x=array('Q',(x for x,_ in pairs));y=array('Q',(y for _,y in pairs))
            z=array('Q',[0])*len(pairs)
            candidate.dll.jc_mul_check.argtypes=[P,P,P,C.c_uint,C.c_uint]
            candidate.dll.jc_mul_check.restype=C.c_int
            candidate.call('jc_mul_check',pointer(x,'Q'),pointer(y,'Q'),pointer(z,'Q'),len(pairs),channel)
            equal(list(z),[a*b%p for a,b in pairs],'modular_product_integer_oracle')
        # Include exact rejection endpoints and popcount endpoints.
        words=array('Q',[0,1,2,(1<<64)-1,(1<<64)-2,(1<<40)-1,1<<40])
        for p in baseline.primes:
            limit=((1<<64)//p)*p
            words.extend((limit-1,limit,min(limit+1,(1<<64)-1)))
        words.extend(rng.getrandbits(64) for _ in range(10000))
        for kind,prime in [(0,0),(1,0)]+[(2,p) for p in baseline.primes]:
            equal(baseline.sample_words(words,len(words),kind,prime),candidate.sample_words(words,len(words),kind,prime),'sampler_values')
        n=baseline.dimension
        # Every supported native relative length, including length one.
        for length in (1,2,4,8,16,32,64,128,256):
            for channel,p in enumerate(baseline.primes):
                values=array('Q',(rng.randrange(p) for _ in range(length*256)))
                for inverse in (False,True):
                    x=baseline.transform(values,channel,inverse,length)
                    y=candidate.transform(values,channel,inverse,length)
                    equal(x,y,'all_length_transform_words')
                # An independent polynomial evaluation oracle uses a sparse
                # public coefficient vector, not either implementation's NTT.
                if length in (1,2,8,16):
                    sparse={(i*7%length,i*29%256):i*13-40 for i in range(8)}
                    source=array('Q',[0])*(length*256)
                    for (i,j),value in sparse.items():source[i*256+j]=value%p
                    actual=candidate.transform(source,channel,False,length)
                    gen=(38,14,7)[channel]
                    alpha=pow(gen,(p-1)//(2*length),p);beta=pow(gen,(p-1)//257,p)
                    for k in sorted({0,length-1}):
                        for e in (0,127,255):
                            expected=sum(value*pow(alpha,(2*k+1)*i,p)*pow(beta,(e+1)*(j+1),p) for (i,j),value in sparse.items())%p
                            assert actual[k*256+e]==expected
                            counts['independent_sparse_evaluations']+=1
        coeff=array('q',((i*7919)%(1<<24)-(1<<23) for i in range(n)))
        for a in (2,3):
            x=baseline.lift(coeff,a);y=candidate.lift(coeff,a);equal(x,y,'lift_words')
            baseline.validate(x,a);candidate.validate(y,a)
            for channel in range(a):
                part=x[channel*n:(channel+1)*n]
                b=baseline.transform(part,channel,True);c=candidate.transform(part,channel,True)
                equal(b,c,'inverse_transform_words')
                equal(candidate.transform(c,channel),part,'transform_roundtrip_words')
            equal(baseline.point(x,x,a),candidate.point(y,y,a),'point_words')
            for scale in (0,44,88):equal(baseline.scale(x,a,scale),candidate.scale(y,a,scale),'scale_words')
            for r in (1,2,4,8):
                equal(baseline.hasse_spectrum(x,a,r),candidate.hasse_spectrum(y,a,r),'hasse_words')
                bc,bf=baseline.hoist(coeff,a,r);cc,cf=candidate.hoist(coeff,a,r)
                equal(bc,cc,'hoist_words');equal(bf,cf,'hoist_words')
                for index in range(2*r):
                    equal(baseline.relative_point(bc,x,a,r,index),candidate.relative_point(cc,y,a,r,index),'relative_words')
                if r>1:
                    for index in range(r+1):equal(baseline.paid_multiplier(bc,a,r,index),candidate.paid_multiplier(cc,a,r,index),'paid_words')
            equal(baseline.drop(x,a),candidate.drop(y,a),'drop_words')
            q=baseline.moduli[a];w=45 if a==3 else 40
            values={0,1,-1,q//2,-q//2+1}
            for j in range(baseline.gadget(a,w)):
                for sign in (-1,1):
                    for offset in (-1,0,1):
                        v=sign*((1<<(w-1))*(1<<(w*j))+offset)
                        if abs(v)<=q//2:values.add(v)
            selected=sorted(values);full=[selected[i%len(selected)] for i in range(n)]
            spectrum=array('Q')
            for channel,p in enumerate(baseline.primes[:a]):spectrum.extend(baseline.transform(array('Q',(v%p for v in full)),channel))
            bd=baseline.digits(spectrum,a,w);cd=candidate.digits(spectrum,a,w)
            for b,c in zip(bd,cd):equal(b.tolist(),c.tolist(),'gadget_words')
            assert all(sum(int(d[i])<<(w*j) for j,d in enumerate(cd))==value for i,value in enumerate(full))
            counts['gadget_integer_reconstructions']+=n
            bits=bytearray(i%2 for i in range(n));errors=[(i%73)-36 for i in range(n)]
            phase=baseline.lift(array('q',(m+2*e for m,e in zip(bits,errors))),a)
            equal(baseline.phase_check(phase,bits,36,a),candidate.phase_check(phase,bits,36,a),'phase_bound_results')
        for length,jobs in ((16,3),(256,16)):
            f=array('H',(rng.randrange(65536) for _ in range(length*jobs)))
            g=array('H',(rng.randrange(65536) for _ in range(length*jobs)))
            for i in range(jobs):g[i*length]=0
            for horner in (False,True):equal(baseline.series(f,g,length,jobs,horner),candidate.series(f,g,length,jobs,horner),'field_output_symbols')
        u=array('q',(i%3-1 for i in range(n)))
        e0=array('q',(i%41-20 for i in range(n)));e1=array('q',((i*17)%41-20 for i in range(n)))
        mu=bytearray(i%2 for i in range(n))
        class PublicCoins:
            def ternary(self,label):return u
            def error(self,label):return e0 if label.endswith('e0') else e1
        for a in (2,3):
            pk=Cipher('public_fixture',a,tuple(array('Q',(rng.randrange(p) for p in baseline.primes[:a] for _ in range(n))) for _ in range(2)))
            b=encrypt(baseline,PublicCoins(),pk,mu,'fixture');c=encrypt(candidate,PublicCoins(),pk,mu,'fixture')
            for x,y in zip(b.components,c.components):equal(x,y,'fused_encryption_words')
        # Six fixed public-kernel blocks at the top modulus, eight calls each.
        # Nothing here is fresh HE or a complete workflow observation.
        samples=[]
        for index,arm in enumerate(('baseline','candidate','candidate','baseline','baseline','candidate')):
            ring=baseline if arm=='baseline' else candidate
            start=perf_counter()
            for _ in range(8):value=encrypt(ring,PublicCoins(),pk,mu,'fixture')
            elapsed=perf_counter()-start
            assert value.components==b.components
            samples.append(dict(index=index,arm=arm,calls=8,seconds=elapsed))
        medians={a:median([r['seconds'] for r in samples if r['arm']==a]) for a in ('baseline','candidate')}
    finally:baseline.close();candidate.close()
    for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
    for name,want in build['candidate_files'].items():assert binding(HERE/name)==want,name
    result=dict(status='NATIVE_EXTENSION_AXIS_PUBLIC_CORRESPONDENCE_PASS',counts=dict(counts),kernel_samples=samples,
        kernel_block_medians=medians,kernel_baseline_over_candidate=medians['baseline']/medians['candidate'],
        advance_to_fresh_gate=medians['baseline']/medians['candidate']>=1.03,
        source_bindings=build['source_bindings'],candidate_bindings=build['candidate_files'],
        build_receipt=binding(HERE/'build.json'),checker=binding(Path(__file__)),
        new_he_execution=False,secret_vectors_sampled=0,security_bits=None,
        scope='Public deterministic arithmetic checks and fixed-coin kernel screen only; no new encrypted gate, complete-workflow speedup or law change. Baseline is the 102-row tensor-axis implementation.')
    (HERE/'public-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('source_bindings','candidate_bindings')}))

if __name__=='__main__':main()
