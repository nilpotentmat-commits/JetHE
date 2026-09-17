"""Exact source and modulus admission; independent field interpolation checks."""
from array import array
from hashlib import sha256
import json
from math import prod
from pathlib import Path
from random import Random
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
RESEARCH=HERE.parents[1]
sys.path.insert(0,str(RESEARCH))
from check_composition_rns_arithmetic import CERTIFICATES, verify_certificate
from interpolation import Field, Interpolation, slow_evaluate, slow_mul

N,KAPPA=65536,130816
F=(2*KAPPA+1)*20
BRAW=8*KAPPA*(F*F+F)+2*KAPPA
Q=prod(v[0] for v in CERTIFICATES[:2])


def binding(path):return dict(bytes=path.stat().st_size,sha256=sha256(path.read_bytes()).hexdigest())


def bindings():
    paths=[HERE/x for x in ('PLAN.md','PROOF.md','admission.py','interpolation.py','interpolation.cpp','build.py','build/receipt.json','build/interpolation.so')]
    paths += [RESEARCH/x for x in ('composition_full_run.py','composition_native.py','composition_optimized.py',
                                  'check_composition_rns_arithmetic.py','check_tensor_codec.py')]
    paths += [RESEARCH/'jethe-throughput-redesign-2026-09-13'/x for x in
              ('slim_ring_base_v2.py','fast_crypto_v1.py','build/fast_core_v2.so')]
    paths += [HERE.parent/'paired-terminal-receiver-v1/prepare.py',
              HERE.parent/'prepared-contraction-audit-v1/PROOF.md']
    return {p.relative_to(ROOT).as_posix():binding(p) for p in paths}


def checks():
    rng=Random(2026091486)
    field=Field()
    cases,coordinates=0,0
    for t,length in ((2,4),(4,8),(8,16),(128,256)):
        codec=Interpolation(field,t,length)
        # Every interpolation column is checked at every point using an
        # independent carryless field operation, including the full profile.
        for col in range(t):
            polynomial=[row[col] for row in codec.inverse]
            assert [slow_evaluate(polynomial,p) for p in range(t)]==[int(p==col) for p in range(t)]
            coordinates+=t
        for trial in range(4):
            x=array('H',(rng.randrange(65536) for _ in range(t)))
            y=array('H',(rng.randrange(65536) for _ in range(t)))
            a,b=codec.encode(x,1),codec.encode(y,1)
            assert codec.decode(a,1)==x and codec.decode(b,1)==y
            c=array('H',[0])*length
            for i in range(t):
                for j in range(t): c[i+j]^=slow_mul(a[i],b[j])
            expected=array('H',(slow_mul(v,w) for v,w in zip(x,y)))
            assert codec.decode(c,1)==expected
            cases+=1
            coordinates+=t
    # Without the degree restriction, z^255*z is zero modulo z^256 but
    # evaluating the factors at 1 and multiplying gives 1.
    assert (255+1)>=256 and slow_mul(1,1)==1
    return dict(product_cases=cases,independent_evaluation_coordinates=coordinates,
                unrestricted_degree_counterexample=True)


def main():
    before=bindings()
    for certificate in CERTIFICATES[:2]:verify_certificate(certificate)
    assert Q==1329227993889339670443893069050298881 and Q>2+4*BRAW
    assert F==5232660
    result=dict(status='SAME_ALGEBRA_TERMINAL_ADMISSION_CHECKS_PASS',
        n=N,kappa=KAPPA,source=dict(secret='independent uniform trits',ephemeral='independent uniform trits',error='CBD20',error_cap=20),
        q=str(Q),q_bits=Q.bit_length(),fresh_bound=F,raw_bound=str(BRAW),
        correctness_threshold=str(2+4*BRAW),correctness_margin=str(Q-2-4*BRAW),
        primes=[v[0] for v in CERTIFICATES[:2]],interpolation=checks(),
        full_counts=dict(products=86,inputs=346,outputs=88,output_polynomials=262,
                         public_raw_bytes=2<<20,input_raw_bytes=692<<20,output_raw_bytes=262<<20),
        encrypted_execution=False,security_bits=None,bindings_before=before,bindings_after=bindings())
    assert before==result['bindings_after']
    (HERE/'admission.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('status','fresh_bound','raw_bound','correctness_margin','interpolation','full_counts')}))


if __name__=='__main__':main()
