"""Integer bounds for fixed-input correctness with a stated probability budget."""
from math import isqrt, prod
from pathlib import Path
import sys
R=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(R/'existing-results-revision-2026-09-13'))
from check_current_interface_hasse_comparison_v1 import PRIMES
N,K,T,WIDTH=65536,130816,15,44
CHAIN=(3,3,3,2,2)
Q=[1]+[prod(PRIMES[:a]) for a in range(1,5)]

def root(n,d=1):
    x=isqrt(n//d)
    return x+(x*x*d<n)

FRESH=root(T*T*(80*N+10))
def delta(a,banks=1,hasse=False):
    g=(Q[a].bit_length()+WIDTH-1)//WIDTH
    return root(T*T*(60 if hasse else 40*banks)*N*(1<<(2*(WIDTH-1)))*g)

def product_bound(B):
    A=1+2*B
    C=root(T*T*40*N*A*A)
    return K*B+(K+1)//2+root(T*T*(16*N*C*C+120*N*A*A),3)

def trace_spec():
    B=FRESH+15*K*((1+2*FRESH)*FRESH+FRESH)+(15*K+1)//2
    out=[('prefix_raw','s0',3,3,B)]
    B+=delta(3,2)
    out.append(('prefix','s1',3,2,B))
    last=3
    for stage,r in enumerate((8,4,2,1)):
        a=CHAIN[stage+1]
        if a!=last:
            B=(2*B-1+(K+2)*PRIMES[a])//(2*PRIMES[a])
            out.append((f'drop{r}',f's{stage+1}',a,2,B))
        H=B+delta(a,hasse=True)
        bypass=B+delta(a)
        out.append((f'hasse{r}',f'h{r}',a,2,H))
        out.append((f'bypass{r}','h1' if r==1 else f's{stage+2}',a,2,bypass))
        raw=product_bound(H)
        out.append((f'product{r}_raw',f'h{r}',a,3,raw))
        if r!=1:
            raw+=delta(a,2)
            out.append((f'product{r}',f's{stage+2}',a,2,raw))
        B=bypass+raw+1
        out.append((f'tail{r}','h1' if r==1 else f's{stage+2}',a,3 if r==1 else 2,B))
        last=a
    assert len(out)==22
    assert all(Q[a]>2+4*b for _,_,a,_,b in out)
    return out

if __name__=='__main__':
    import json
    from decimal import Decimal,localcontext
    with localcontext() as c:
        c.prec=60
        log2_bound=Decimal(2*N*59*1024).ln()/Decimal(2).ln()-Decimal(T*T)/2/Decimal(2).ln()
    print(json.dumps(dict(status='SLIM_EXACT_BOUND_SCREEN_PASS',fresh=FRESH,width=WIDTH,chain=CHAIN,
        trace=trace_spec(),minimum_whole_margin_bits=min((Q[a]//(2+4*b)).bit_length()-1 for _,_,a,_,b in trace_spec()),
        log2_failure_union_bound_1024_fixed_batches=str(log2_bound),security_bits=None),indent=2))
