

"""Exact stage-specific sufficient bounds and optimistic exclusions."""
from math import isqrt,prod
N,K,T,FRESH=65536,130816,15,34347
PRIMES=(1152921504002872321,1152921503566671361,1152921503264686081)
Q=[1]+[prod(PRIMES[:a]) for a in range(1,4)]
CHAIN=(3,3,3,2,2)
WIDTHS=(45,45,60,40,60)
WIDTH_BY_VERTEX=dict(s1=45,h8=45,s2=45,h4=60,s3=60,h2=40,s4=40,h1=60)
def root(n,d=1):
    x=isqrt(n//d)
    return x+(x*x*d<n)
def digits(a,w):return (Q[a].bit_length()+w-1)//w
def delta(a,w,banks=1,hasse=False):
    return root(T*T*(60 if hasse else 40*banks)*N*(1<<(2*(w-1)))*digits(a,w))
def product_bound(B):
    A=1+2*B;C=root(T*T*40*N*A*A)
    return K*B+(K+1)//2+root(T*T*(16*N*C*C+120*N*A*A),3)
def dropped(B,a):return (2*B-1+(K+2)*PRIMES[a])//(2*PRIMES[a])
def prefix_raw():return FRESH+15*K*((1+2*FRESH)*FRESH+FRESH)+(15*K+1)//2
def trace_spec():
    B=prefix_raw();out=[('prefix_raw','s0',3,3,B)]
    B+=delta(3,WIDTHS[0],2);out.append(('prefix','s1',3,2,B));last=3
    for stage,r in enumerate((8,4,2,1)):
        a,w=CHAIN[stage+1],WIDTHS[stage+1]
        if a!=last:
            B=dropped(B,a);out.append((f'drop{r}',f's{stage+1}',a,2,B))
        H=B+delta(a,w,hasse=True);bypass=B+delta(a,w)
        out.extend(((f'hasse{r}',f'h{r}',a,2,H),(f'bypass{r}','h1' if r==1 else f's{stage+2}',a,2,bypass)))
        raw=product_bound(H);out.append((f'product{r}_raw',f'h{r}',a,3,raw))
        if r!=1:raw+=delta(a,w,2);out.append((f'product{r}',f's{stage+2}',a,2,raw))
        B=bypass+raw+1;out.append((f'tail{r}','h1' if r==1 else f's{stage+2}',a,3 if r==1 else 2,B));last=a
    assert len(out)==22 and all(Q[a]>2+4*b for _,_,a,_,b in out)
    return out
def optimistic_exclusion(which):
    B=prefix_raw()+delta(3,60,2) if which=='prefix' else 0
    begin=0 if which in ('prefix','h8') else 2
    last=3 if begin==0 else 2
    trace=[]
    for stage in range(begin,4):
        a=CHAIN[stage+1]
        if a!=last:B=dropped(B,a)
        H=B+delta(a,60,hasse=True) if (which=='h8' and stage==0) or (which=='h2' and stage==2) else B
        B=B+product_bound(H)+1
        trace.append(dict(stage=stage,limbs=a,bound=B,strict_margin=Q[a]-2-4*B));last=a
    assert trace[-1]['strict_margin']<0
    return dict(excluded=which,trace=trace)
