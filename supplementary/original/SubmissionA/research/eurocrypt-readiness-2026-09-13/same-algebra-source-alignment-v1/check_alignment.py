"""Exact projection, source-factor and honest stopped-interface accounting."""
from collections import Counter
from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
from math import comb,prod
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
READY=HERE.parent
RESEARCH=HERE.parents[1]
ROOT=HERE.parents[3]
sys.path.insert(0,str(RESEARCH))
from check_composition_rns_arithmetic import CERTIFICATES


def binding(path):return dict(bytes=path.stat().st_size,sha256=sha256(path.read_bytes()).hexdigest())


def bindings():
    files=[HERE/'PROOF.md',HERE/'check_alignment.py',READY/'source-scope.json',
           READY/'manuscript/appendices/three-prime-proof.tex',
           READY/'same-algebra-terminal-v1/PROOF.md',READY/'same-algebra-terminal-v1/admission.json',
           READY/'same-algebra-workflow-v1/common.py',READY/'same-algebra-workflow-v1/worker.py',
           RESEARCH/'composition_full_run.py',RESEARCH/'check_composition_rns_arithmetic.py',
           RESEARCH/'jethe-throughput-redesign-2026-09-13/backend-v2/fast_core_v1.cpp',
           RESEARCH/'jethe-throughput-redesign-2026-09-13/backend-v2/composition_native_core.cpp',
           READY/'manuscript/appendices/paired-terminal-receiver.tex']
    return {p.relative_to(ROOT).as_posix():binding(p) for p in files}


def mul(a,b):return (a[0]*b[0]-a[1]*b[1],a[0]*b[1]+a[1]*b[0])


def small_projection():
    big,small=35,5
    masks=list(product(range(big),repeat=2))
    fibers=Counter(tuple(v%small for v in a) for a in masks)
    assert len(fibers)==small**2 and set(fibers.values())=={(big//small)**2}
    sources=list(product((-1,0,1),repeat=2))
    checks=0
    for s in sources:
        for e in sources:
            for a in masks:
                body=tuple((x+y)%big for x,y in zip(mul(a,s),e))
                projected=tuple((x+y)%small for x,y in zip(mul(tuple(v%small for v in a),s),e))
                assert tuple(v%small for v in body)==projected
                # The root conversion a=-2A,b=2(A*s+e) commutes exactly.
                pk_a=tuple((-2*v)%big for v in a)
                pk_b=tuple((2*v)%big for v in body)
                phase=tuple((x+y)%big for x,y in zip(pk_b,mul(pk_a,s)))
                assert phase==tuple((2*v)%big for v in e)
                assert tuple(v%small for v in pk_a)==tuple((-2*v)%small for v in a)
                checks+=2
    return dict(ring='Z[x]/(x^2+1)',big_modulus=big,small_modulus=small,
                masks=len(masks),uniform_fibers=len(fibers),preimages_per_fiber=49,
                complete_declared_phase_checks=checks)


def encryption_embedding():
    q=5
    elements=list(product(range(q),repeat=2))
    mask_pairs=list(product(elements,repeat=2))
    def twice(a):return tuple(2*x%q for x in a)
    assert len({(twice(a),twice(b)) for a,b in mask_pairs})==len(mask_pairs)==625
    checks=0
    # These fixed error vectors check the algebra; source independence is part
    # of the ordinary game, not inferred from this small diagnostic fixture.
    e0,e1=(1,-1),(-1,0)
    for A0,A1 in mask_pairs:
        b,a=twice(A0),twice(A1) # masks are received, public key is induced
        for u in product((-1,0,1),repeat=2):
            body0=tuple((x+e)%q for x,e in zip(mul(A0,u),e0))
            body1=tuple((x+e)%q for x,e in zip(mul(A1,u),e1))
            for mu in product((0,1),repeat=2):
                target0=tuple((2*x+m)%q for x,m in zip(body0,mu))
                target1=twice(body1)
                assert target0==tuple((x+2*e+m)%q for x,e,m in zip(mul(b,u),e0,mu))
                assert target1==tuple((x+2*e)%q for x,e in zip(mul(a,u),e1))
                checks+=1
    for mu in product((0,1),repeat=2):
        images={(tuple((2*x+m)%q for x,m in zip(B0,mu)),twice(B1)) for B0,B1 in mask_pairs}
        assert len(images)==625
    return dict(public_key_mask_bijection_pairs=625,real_encryption_identities=checks,
                null_body_bijection_pairs=4*625,challenge_masks_chosen=False)


def main():
    before=bindings()
    source=json.loads((READY/'source-scope.json').read_text())
    control=json.loads((READY/'same-algebra-terminal-v1/admission.json').read_text())
    q2,q3=[prod(p[0] for p in CERTIFICATES[:a]) for a in (2,3)]
    assert q3%q2==0 and q3//q2==CERTIFICATES[2][0]
    assert int(source['source_modulus_decimal'])==q3 and int(source['lower_modulus_decimal'])==q2
    assert source['source_rows']==46 and int(control['q'])==q2
    counts={k:comb(40,20+k) for k in range(-20,21)}
    assert sum(counts.values())==2**40
    assert sum(k*v for k,v in counts.items())==0
    assert sum(k*k*v for k,v in counts.items())==10*2**40
    N=65536
    rhos=[Fraction(2**64%p[0],2**64) for p in CERTIFICATES[:2]]
    rho=max(rhos)
    assert rho<Fraction(1,2**30)
    rows=[]
    for J in (1,2):
        budget=N*(25+3460*J)
        native_budget=N*(3339+350*J)
        stop=N*(2*rho**8+Fraction(1+346*J,2**512))
        assert stop<Fraction(1,2**222)
        rows.append(dict(batches=J,control_inputs=346*J,native_inputs=35*J,
            control_source_gap_factor=2*(1+346*J),native_source_gap_factor=2*(9+35*J),
            control_word_budget=budget,native_word_budget=native_budget,
            control_uniform_prime_vectors=2,control_trit_vectors=1+346*J,control_error_vectors=1+692*J,
            exact_control_stop_upper=str(stop),strict_control_stop_exponent=222))
    assert rows[1]['control_word_budget']==455147520 and rows[1]['native_word_budget']==264699904
    assert (rows[1]['control_source_gap_factor'],rows[1]['native_source_gap_factor'])==(1386,158)
    result=dict(status='SAME_ALGEBRA_COMMON_SOURCE_ACCOUNTING_CHECKS_PASS',
        q2=str(q2),q3=str(q3),exact_quotient=q3//q2,source_rows=46,
        rho2=[str(v) for v in rhos],catalogues=rows,small_projection=small_projection(),
        encryption_embedding=encryption_embedding(),
        CBD20=dict(support=[-20,20],total_mass_denominator=str(2**40),mean=0,variance=10),
        common_sufficient_ordinary_source_premise=True,equal_scheme_reduction_losses=False,
        security_bits=None,cryptanalysis_executed=False,new_he_execution=False,
        formal_proof_checked=False,bindings_before=before,bindings_after=bindings())
    assert before==result['bindings_after']
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('status','exact_quotient','small_projection','common_sufficient_ordinary_source_premise','equal_scheme_reduction_losses')}))


if __name__=='__main__':main()
