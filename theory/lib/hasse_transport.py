"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

import random

class Ring:
    """Integral basis t^i b^j, 0<=i<L, 1<=j<=4, with Phi_5(b)=0."""
    def __init__(self, length):
        self.L=length
        self.N=4*length

    def zero(self):
        return [0]*self.N

    def one(self):
        return [-1]*4+[0]*(self.N-4)

    def add(self, *values):
        return [sum(x) for x in zip(*values)]

    def scale(self, value, scalar):
        return [scalar*x for x in value]

    def mod(self, value, q):
        return [x%q for x in value]

    def shift(self, value, power):
        out=self.zero()
        for i in range(self.L):
            j=i+power
            sign=-1 if (j//self.L)&1 else 1
            j%=self.L
            for v in range(4):out[4*j+v]+=sign*value[4*i+v]
        return out

    def mul(self, a, b):
        out=self.zero()
        for i,x in enumerate(a):
            if not x:continue
            ti,bi=divmod(i,4)
            for j,y in enumerate(b):
                if not y:continue
                tj,bj=divmod(j,4)
                t=ti+tj;sign=-1 if t>=self.L else 1;t%=self.L
                odd=(bi+bj+2)%5
                if odd:out[4*t+odd-1]+=sign*x*y
                else:
                    for v in range(4):out[4*t+v]-=sign*x*y
        return out

    def hasse(self, a, r):
        out=self.zero()
        for i in range(self.L):
            if i&r:out[4*(i-r):4*(i-r+1)]=a[4*i:4*(i+1)]
        return out

    def relative(self, a, e, residue):
        out=self.zero()
        for i in range(0,self.L,e):out[4*i:4*(i+1)]=a[4*(i+residue):4*(i+residue+1)]
        return out


def digits(a,q,base,g):
    values=[x%q for x in a]
    values=[x-q if x>q//2 else x for x in values]
    result=[[0]*len(a) for _ in range(g)]
    for i,x in enumerate(values):
        value=x
        for j in range(g):
            d=value%base
            if d>base//2 or (d==base//2 and value<0):d-=base
            result[j][i]=d;value=(value-d)//base
        assert value==0
        assert sum(result[j][i]*base**j for j in range(g))==x
    return result


def payloads(ring,s,r,paid):
    if paid:return [s]+[ring.hasse(ring.shift(s,i),r) for i in range(r)]
    return [ring.hasse(ring.shift(s,i),r) for i in range(2*r)]


def multipliers(ring,d,r,paid):
    if not paid:return [ring.relative(d,2*r,i) for i in range(2*r)]
    out=[ring.hasse(d,r)]
    for i in range(r):
        u=ring.relative(d,2*r,i);v=ring.relative(d,2*r,i+r)
        out.append(ring.add(u,ring.scale(ring.shift(v,r),-1)))
    return out


def rows(ring,ps,k,q,base,g,rng):
    result=[]
    for payload in ps:
        group=[]
        for j in range(g):
            a=[rng.randrange(q) for _ in range(ring.N)]
            eps=[rng.randrange(-1,2) for _ in range(ring.N)]
            b=ring.mod(ring.add(ring.scale(payload,base**j),ring.scale(ring.mul(a,k),-1),ring.scale(eps,2)),q)
            group.append((b,a,eps))
        result.append(group)
    return result


def apply(ring,c0,c1,bank,q,base,g,r,paid,scaled=False):
    # A scaled gadget is inverted on the source coefficient, once per array.
    ds=digits(ring.scale(c1,-2) if scaled else c1,q,base,g)
    out=[ring.hasse(c0,r),ring.zero()]
    extra=ring.zero()
    for j,d in enumerate(ds):
        for i,mult in enumerate(multipliers(ring,d,r,paid)):
            b,a,eps=bank[i][j]
            out[0]=ring.add(out[0],ring.mul(mult,b))
            out[1]=ring.add(out[1],ring.mul(mult,a))
            extra=ring.add(extra,ring.mul(mult,eps))
    return [ring.mod(x,q) for x in out],extra


def raw(ring,c,d,q):
    return [ring.mod(ring.mul(c[0],d[0]),q),
            ring.mod(ring.add(ring.mul(c[0],d[1]),ring.mul(c[1],d[0])),q),
            ring.mod(ring.mul(c[1],d[1]),q)]


def case(length,q,r,fixture):
    ring=Ring(length);rng=random.Random((length<<32)+(q<<10)+(r<<4)+fixture)
    base=4;g=1
    while base**g<q:g+=1
    g+=1
    s=[rng.randrange(-1,2) for _ in range(ring.N)]
    k=[rng.randrange(-1,2) for _ in range(ring.N)]
    mu=[rng.randrange(2) for _ in range(ring.N)]
    error=[rng.randrange(-2,3) for _ in range(ring.N)]
    c1=[rng.randrange(q) for _ in range(ring.N)]
    c0=ring.mod(ring.add(mu,ring.scale(error,2),ring.scale(ring.mul(c1,s),-1)),q)
    delta=(q-1)//2
    assert (-2*delta)%q==1
    cprime=[ring.mod(ring.scale(x,delta),q) for x in (c0,c1)]
    assert ring.mod(ring.add(cprime[0],ring.mul(cprime[1],s)),q)==ring.mod(ring.add(ring.scale(mu,delta),ring.scale(error,-1)),q)
    variants=[]
    for paid in (False,True):
        ps=payloads(ring,s,r,paid)
        bank=rows(ring,ps,k,q,base,g,rng)
        output,extra=apply(ring,c0,c1,bank,q,base,g,r,paid)
        noise=ring.add(ring.hasse(error,r),extra)
        expected=ring.mod(ring.add(ring.hasse(mu,r),ring.scale(noise,2)),q)
        assert ring.mod(ring.add(output[0],ring.mul(output[1],k)),q)==expected
        bound=2+(3 if paid else 2)*(7*length*g*2)//2
        assert max(map(abs,noise))<=bound
        scaled_bank=[[(ring.mod(ring.scale(b,delta),q),ring.mod(ring.scale(a,delta),q),eps)
                     for b,a,eps in group] for group in bank]
        converted,extra2=apply(ring,*cprime,scaled_bank,q,base,g,r,paid,scaled=True)
        assert extra2==extra
        assert converted==[ring.mod(ring.scale(x,delta),q) for x in output]
        assert ring.mod(ring.add(converted[0],ring.mul(converted[1],k)),q)==ring.mod(ring.add(ring.scale(ring.hasse(mu,r),delta),ring.scale(noise,-1)),q)
        assert len(bank)*g==((r+1) if paid else 2*r)*g
        variants.append(dict(paid=paid,rows=len(bank)*g,max_noise=max(map(abs,noise)),bound=bound))
    other=[[rng.randrange(q) for _ in range(ring.N)] for _ in range(2)]
    other_scaled=[ring.mod(ring.scale(x,delta),q) for x in other]
    left=[ring.mod(ring.scale(x,-2),q) for x in raw(ring,cprime,other_scaled,q)]
    right=[ring.mod(ring.scale(x,delta),q) for x in raw(ring,[c0,c1],other,q)]
    assert left==right
    # Independent direct counterexample to treating Hasse as a ring homomorphism.
    monomial=ring.shift(ring.one(),r)
    zero_c0=ring.scale(ring.shift(ring.one(),2*r),-1)
    assert ring.add(zero_c0,ring.mul(monomial,monomial))==ring.zero()
    naive=ring.mod(ring.add(ring.hasse(zero_c0,r),ring.mul(ring.hasse(monomial,r),monomial)),q)
    assert naive==ring.mod(monomial,q) and any(naive)
    return dict(length=length,q=q,order=r,fixture=fixture,dimension=ring.N,gadget_length=g,
                variants=variants,phase_coefficients=5*ring.N,converted_components=4*ring.N,
                raw_product_coefficients=3*ring.N,naive_map_counterexample=True)


def count_rows():
    out=[]
    for d in range(1,21):
        for k in range(1,d+1):
            x=1<<k;tau=d-k;e=1<<tau;g=d+1
            orders=[1<<j for j in reversed(range(tau))]
            reference=2*g+sum((2*r+3)*g for r in orders)
            paid=2*g+sum((r+4)*g for r in orders)
            assert reference==g*(2*e+3*tau)
            assert paid==g*(e+1+4*tau)<=reference
            out.append(dict(d=d,k=k,reference_rows=reference,paid_rows=paid,
                            products=x-1+tau,inputs=2*x-1+tau,keys=2*tau+2,layers=tau+1))
    return out
