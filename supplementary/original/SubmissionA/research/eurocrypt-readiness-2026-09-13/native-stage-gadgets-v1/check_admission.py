"""Exact profile, finite-row minimum and source inventory; no HE imports."""
from fractions import Fraction
from hashlib import sha256
import json
from math import factorial
from pathlib import Path
from bounds import *
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
def main():
    trace=trace_spec();g=[digits(a,w) for a,w in zip(CHAIN,WIDTHS)]
    assert g==[4,4,3,3,2]
    families=[2,12,8,6,2];rows=sum(f*d for f,d in zip(families,g))
    pairs=sum(f*d*a for f,d,a in zip(families,g,CHAIN));pub=pairs+sum(CHAIN)
    incoming=[1,8,37,12,16,9,10,9,5]
    assert (rows,pairs,pub,sum(incoming),max(incoming))==(102,284,297,107,37)
    lower=sum((Fraction(225,2)**j/factorial(j) for j in range(513)),Fraction())
    assert Fraction(1024*59*2*N,1)/lower<Fraction(1,2**129)
    exclusion=[optimistic_exclusion(which) for which in ('prefix','h8','h2')]
    paths=[Path(__file__),HERE/'bounds.py',HERE/'PLAN.md',HERE/'PROOF.md',
        HERE.parent/'manuscript/appendices/three-prime-proof.tex',HERE.parent/'source-scope.json']
    result=dict(status='NATIVE_STAGE_GADGETS_CONDITIONAL_ADMISSION_PASS',widths=WIDTHS,chain=CHAIN,digits=g,
        trace=[dict(state=n,key=k,limbs=a,components=c,error_bound=str(b),strict_margin=str(Q[a]-2-4*b)) for n,k,a,c,b in trace],
        evaluated_states=22,fresh_gate_states=57,ideal_fixed_batches=1024,ideal_failure_strict_exponent=129,
        optimistic_exclusions=exclusion,restricted_minimum_rows=rows,restricted_minimum_row_prime_pairs=pairs,
        public_raw_bytes=pub<<20,input_raw_bytes=103<<20,output_raw_bytes=3<<20,
        secrets=9,owner_public_keys=5,setup_error_vectors=107,setup_small_vectors=116,
        incoming_rows=incoming,common_sufficient_source='q3/37',previous_q3_46_still_sufficient=True,
        two_batch_source_gap_factor=158,two_batch_word_budget=N*(8*(pub+79)+247),
        bindings={p.relative_to(ROOT).as_posix():binding(p) for p in paths},
        new_he_execution=False,security_bits=None,
        scope='Fixed chain and stage widths under the existing sufficient fixed-input proof. Exact restricted row minimum; no global runtime optimum, measured gain or source-security certificate.')
    (HERE/'admission.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('trace','bindings','optimistic_exclusions')}))
if __name__=='__main__':main()
