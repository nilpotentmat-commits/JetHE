"""Public plaintext congruences; no ciphertexts, encryption or security experiment."""
from pathlib import Path
from hashlib import sha256
from time import perf_counter
import json
import random
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]


def mul(a,b,L):
    out=0
    while b:
        low=b&-b;out^=a<<(low.bit_length()-1);b^=low
    return out&((1<<L)-1)


def compose(f,g,L):
    out=0
    for i in reversed(range(L)):out=mul(out,g,L)^((f>>i)&1)
    return out


def automorphism(x,u,L):
    image=sum(1<<j for j in range(L) if (j&u)==j)^1
    return compose(x,image,L)


def hasse(x,r,L):
    return sum(1<<(i-r) for i in range(r,L) if ((i&r)==r) and ((x>>i)&1))


def main():
    assert not (HERE/'boundary-check.json').exists()
    started=perf_counter();rng=random.Random(2026091501);cases=[]
    for L in (2,4,8,16):
        limit=(1<<L)-1
        for r in (1<<j for j in range(L.bit_length()-1)):
            mask=(1<<r)-1;gate_checks=0;composition_checks=0
            assert hasse(1<<r,r,L)==1 and hasse(0,r,L)==0
            for fixture in range(200):
                x=rng.randrange(1<<L);y=x^((rng.randrange(1<<L)<<r)&limit)
                pairs=[(x,y)]
                for depth in range(20):
                    a,b=pairs[rng.randrange(len(pairs))];c,d=pairs[rng.randrange(len(pairs))]
                    constant=rng.randrange(1<<L);u=rng.randrange(L)*2+1
                    for left,right in ((a^c,b^d),(mul(a,c,L),mul(b,d,L)),
                                       (a^constant,b^constant),(automorphism(a,u,L),automorphism(b,u,L))):
                        assert (left^right)&mask==0
                        pairs.append((left,right));gate_checks+=1
                f=rng.randrange(1<<L);fp=f^((rng.randrange(1<<L)<<r)&limit)
                g=(rng.randrange(1<<L)<<1)&limit
                gp=g^((rng.randrange(1<<L)<<r)&limit)
                assert (compose(f,g,L)^compose(fp,gp,L))&mask==0
                composition_checks+=1
            # Small exhaustive composition pairs prevent a randomized-only boundary check.
            exhaustive=0
            if L<=4:
                for f in range(1<<L):
                    for g in range(0,1<<L,2):
                        for df in range(0,1<<L,1<<r):
                            for dg in range(0,1<<L,1<<r):
                                assert (compose(f,g,L)^compose(f^df,g^dg,L))&mask==0
                                exhaustive+=1
            cases.append(dict(length=L,order=r,gate_pairs=gate_checks,
                              sampled_composition_pairs=composition_checks,
                              exhaustive_composition_pairs=exhaustive,Hasse_counterexample=True))
    files=[HERE/'ARITHMETIC_INTERFACE_BOUNDARY.md',Path(__file__).resolve(),
           ROOT/'SubmissionA/research/core-resolution/SECURITY_ROOT_CAUSES.md']
    sources={p.relative_to(ROOT).as_posix():dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest()) for p in files}
    out=dict(status='PLAINTEXT_ARITHMETIC_INTERFACE_BOUNDARY_PASS',cases=cases,source_bindings=sources,
             gate_pairs=sum(x['gate_pairs'] for x in cases),
             sampled_composition_pairs=sum(x['sampled_composition_pairs'] for x in cases),
             exhaustive_composition_pairs=sum(x['exhaustive_composition_pairs'] for x in cases),
             wall_seconds=perf_counter()-started,new_he_execution=False,
             full_composition_impossibility_claimed=False,arbitrary_ciphertext_lower_bound=False,
             mathematical_proof_verified_by_program=False)
    (HERE/'boundary-check.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in out.items() if k not in ('cases','source_bindings')}))


if __name__=='__main__':main()
