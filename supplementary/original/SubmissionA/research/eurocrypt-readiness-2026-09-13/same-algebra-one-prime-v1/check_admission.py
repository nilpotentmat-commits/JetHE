"""Exact conditional admission only; no secret sampling, HE or timing."""
import ast
from fractions import Fraction
from hashlib import sha256
import json
from math import gcd, isqrt, prod
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
RESEARCH=HERE.parents[1]
READY=HERE.parent


def binding(p):
    return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())


def main():
    source=RESEARCH/'check_composition_rns_arithmetic.py'
    assignments=[x for x in ast.parse(source.read_text()).body if isinstance(x,ast.Assign)
                 and any(isinstance(t,ast.Name) and t.id=='CERTIFICATES' for t in x.targets)]
    assert len(assignments)==1
    certificates=ast.literal_eval(assignments[0].value)
    p,g,factors=certificates[0]
    assert p==1152921504002872321
    assert prod(r**e for r,e in factors)==p-1
    for r,e in factors:
        assert r>=2 and e>=1 and all(r%d for d in range(2,isqrt(r)+1))
        assert gcd(pow(g,(p-1)//r,p)-1,p)==1
    assert pow(g,p-1,p)==1
    conductor=512*65535
    assert (p-1)%conductor==0
    root=pow(g,(p-1)//conductor,p)
    assert pow(root,conductor,p)==1
    assert all(pow(root,conductor//r,p)!=1 for r in (2,3,5,17,257))
    N,kappa,T,I,J=65536,130816,16,346,1024
    v=80*N+10
    squared=T*T*v
    F=isqrt(squared)+int(isqrt(squared)**2<squared)
    assert (F-1)**2<squared<=F**2
    B=8*kappa*(F*F+F)+2*kappa
    assert p>2+4*B and B>=F
    old_F=(2*kappa+1)*20
    old_B=8*kappa*(old_F*old_F+old_F)+2*kappa
    assert p<=2+4*old_B
    # Positive terms give a rigorous strict lower bound on exp(128).
    term=Fraction(1);exp_lower=term
    for k in range(1,513):
        term*=Fraction(128,k)
        exp_lower+=term
    prefactor=2*N*I*J
    assert exp_lower>prefactor*(1<<149)
    q3=prod(x[0] for x in certificates[:3])
    assert q3%p==0
    rho=Fraction((1<<64)%p,1<<64)
    catalogues=[]
    for batches in (1,2,1024):
        stop=N*(rho**8+Fraction(1+346*batches,1<<512))
        assert stop<Fraction(1,1<<223)
        catalogues.append(dict(batches=batches,source_gap_factor=2*(1+346*batches),
            uniform_prime_vectors=1,trit_vectors=1+346*batches,error_vectors=1+692*batches,
            stopped_word_budget=N*(17+3460*batches),strict_stop_exponent=223))
    paths=[HERE/x for x in ('PLAN.md','PROOF.md','RESULTS.md','REPRODUCE.md','check_admission.py')]
    paths += [source,READY/'manuscript/appendices/three-prime-proof.tex',
              READY/'same-algebra-terminal-v1/PROOF.md',READY/'same-algebra-terminal-v1/admission.json',
              READY/'same-algebra-source-alignment-v1/PROOF.md']
    result=dict(status='ONE_PRIME_SAME_ALGEBRA_CONDITIONAL_ADMISSION_CHECKS_PASS',
        n=N,kappa=kappa,q=p,q_bits=p.bit_length(),fresh_variance_proxy=v,threshold=T,
        fresh_cap=F,raw_cap=B,strict_centering_margin=p-2-4*B,
        old_all_coins_fresh_cap=old_F,old_all_coins_raw_cap=old_B,old_one_prime_admitted=False,
        fixed_batches=J,inputs_per_batch=I,ideal_correctness_strict_exponent=149,
        exponential_positive_terms=513,common_source_modulus=str(q3),catalogues=catalogues,
        raw_payload_bytes=dict(public=1<<20,inputs=346<<20,outputs=131<<20),
        bindings={p.relative_to(ROOT).as_posix():binding(p) for p in paths},
        new_he_execution=False,secret_vectors_sampled=0,security_bits=None,
        scope='Exact conditional fixed-batch admission and source/traffic accounting. General matrix/phase proof is written separately; no encrypted gate or one-prime timing exists.')
    (HERE/'admission.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('bindings','catalogues')},indent=2))


if __name__=='__main__':main()
