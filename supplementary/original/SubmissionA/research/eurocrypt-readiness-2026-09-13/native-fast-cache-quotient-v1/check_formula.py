"""Public exact integer quotient checks; no performance or crypto experiment."""
from hashlib import sha256
from math import isqrt
from pathlib import Path
from random import Random
import json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]


def binding(p):
    d=p.read_bytes();return dict(bytes=len(d),sha256=sha256(d).hexdigest())


def quotient(w,b,c):
    p=b-c;t=16*w*c;a,t0=divmod(t,b);s=t0+a*c;d,s0=divmod(s,b);v=s0+d*c
    assert 0<=v<2*p and d<=64
    result=16*w+a+d+int(v>=p)
    assert result==(16*b*w)//p and result<16*b
    return result


def main():
    paths=[HERE/n for n in ('PLAN.md','PROOF.md','check_formula.py')]
    paths += [HERE.parent/'native-cached-matrix-v1'/n for n in ('RESULTS.md','matrix.cpp','public-check.json','verification.json')]
    before={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    small=0;profiles=[]
    for k in range(6,13):
        b=1<<k;maxc=min(2*isqrt(b),(b-1)//67)
        for c in range(maxc+1):
            for w in range(b-c):quotient(w,b,c);small+=1
        profiles.append(dict(bits=k,maximum_c=maxc))
    rng=Random(2026091456);native=0;b=1<<60;constants=(0,1,2,603974655,1040175615,1342160895,(1<<31)-1)
    rows=[]
    for c in constants:
        p=b-c
        values={0,1,2,p-1,p-2,p//2,(1<<59)-1,1<<59}
        values.update(x for k in range(60) for x in ((1<<k)-1,1<<k,(1<<k)+1) if x<p)
        values.update(rng.randrange(p) for _ in range(40000))
        for w in sorted(values):
            value=quotient(w,b,c);assert value==(w<<64)//p;native+=1
        rows.append(dict(c=c,p=p,checked_values=len(values)))
    assert before=={p.relative_to(ROOT).as_posix():binding(p) for p in paths}
    out=dict(status='EXACT_CACHE_QUOTIENT_FORMULA_CHECKS_PASS',small_exhaustive_cases=small,small_profiles=profiles,
             native_cases=native,native_constants=rows,source_bindings=before,new_he_execution=False,timing_claim=False,
             independently_verified_proof=False)
    (HERE/'formula.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in out.items() if k in ('status','small_exhaustive_cases','native_cases','new_he_execution','timing_claim')},indent=2))


if __name__=='__main__':main()
