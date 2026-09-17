"""Public additive-subspace CRT for the W1/W2 terminal comparator.

Elementary sparse polynomial division/CRT, not a claimed new FFT algorithm.
No keys, encryption, benchmark, or security qualification. No file writes.
"""
from random import Random
import json
from check_fused_composition_frontier import FastField


class AdditiveCRT:
    def __init__(self,log_size):
        assert 1<=log_size<=16
        self.field=FastField();self.log_size=log_size;self.size=1<<log_size
        # V_i is monic and vanishes exactly on span(1,2,...,2^(i-1)).
        self.polynomials=[{1:1}];self.split=[];self.inverse_split=[]
        for i in range(log_size):
            previous=self.polynomials[-1];c=self.sparse_evaluate(previous,1<<i)
            assert c!=0
            current={2*j:self.field.mul(a,a) for j,a in previous.items()}
            for j,a in previous.items():current[j]=current.get(j,0)^self.field.mul(c,a)
            self.polynomials.append({j:a for j,a in current.items() if a})
            self.split.append(c);self.inverse_split.append(self.power(c,65534))
        self.offsets={}
        for level in range(1,log_size+1):
            for alpha in range(0,self.size,1<<level):
                self.offsets[level,alpha]=self.sparse_evaluate(self.polynomials[level-1],alpha)

    def power(self,a,n):
        out=1
        while n:
            if n&1:out=self.field.mul(out,a)
            a=self.field.mul(a,a);n>>=1
        return out

    def sparse_evaluate(self,poly,x):
        out=0
        for degree,coefficient in poly.items():out^=self.field.mul(coefficient,self.power(x,degree))
        return out

    def forward(self,coefficients):
        assert 0<len(coefficients)<=self.size and all(0<=x<65536 for x in coefficients)
        field=self.field
        def visit(f,level,alpha):
            if not level:return [f[0] if f else 0]
            d=1<<(level-1);work=list(f)+[0]*max(0,2*d-len(f));quotient=[0]*d
            divisor=self.polynomials[level-1]
            # f = quotient*V_(level-1) + remainder. Only sparse divisor terms.
            for i in range(2*d-1,d-1,-1):
                a=work[i];quotient[i-d]=a
                if a:
                    for degree,coefficient in divisor.items():work[i-d+degree]^=field.mul(a,coefficient)
                assert work[i]==0
            c0=self.offsets[level,alpha];c1=c0^self.split[level-1]
            left=[work[i]^field.mul(c0,quotient[i]) for i in range(d)]
            right=[work[i]^field.mul(c1,quotient[i]) for i in range(d)]
            return visit(left,level-1,alpha)+visit(right,level-1,alpha+d)
        return visit(list(coefficients),self.log_size,0)

    def inverse(self,values):
        assert len(values)==self.size and all(0<=x<65536 for x in values)
        field=self.field
        def visit(level,alpha):
            if not level:return [values[alpha]]
            d=1<<(level-1);left=visit(level-1,alpha);right=visit(level-1,alpha+d)
            q=[field.mul(a^b,self.inverse_split[level-1]) for a,b in zip(left,right)]
            out=left+[0]*d;c0=self.offsets[level,alpha]
            for i,a in enumerate(q):
                out[i]^=field.mul(c0,a)
                if a:
                    for degree,coefficient in self.polynomials[level-1].items():out[i+degree]^=field.mul(a,coefficient)
            return out
        return visit(self.log_size,0)


def horner(field,f,x):
    out=0
    for a in reversed(f):out=field.mul(out,x)^a
    return out


def truncated_product(field,a,b,length):
    out=[0]*length
    for i,x in enumerate(a):
        for j,y in enumerate(b[:length-i]):out[i+j]^=field.mul(x,y)
    return out


def check():
    rng=Random(2026090842);profiles=[]
    for log_size in (1,2,4,5,9,11):
        codec=AdditiveCRT(log_size);k=codec.size;field=codec.field
        # Full-degree inverse check and an independent direct-Horner oracle.
        f=[rng.randrange(65536) for _ in range(k)]
        values=codec.forward(f);assert codec.inverse(values)==f
        points=range(k) if k<=32 else sorted(set([0,1,k-1]+[rng.randrange(k) for _ in range(32)]))
        assert all(values[x]==horner(field,f,x) for x in points)
        assert all(codec.sparse_evaluate(codec.polynomials[-1],x)==0 for x in range(k))
        profiles.append(dict(points=k,full_degree_roundtrip_coefficients=k,direct_horner_points=len(points),vanishing_roots_checked=k))
    tasks=[]
    for length,family in ((16,'W1'),(256,'W1'),(256,'W2-shallow'),(256,'W2-deep')):
        deep=family=='W2-deep'
        degree=(8 if deep else 2)*(length-1);log_size=degree.bit_length();codec=AdditiveCRT(log_size);field=codec.field
        terms=4 if deep else 1
        width=2 if family=='W1' else 3
        inputs=[[rng.randrange(65536) for _ in range(length)] for _ in range(width*terms)]
        expected=None;values=None
        for i in range(terms):
            a,b=inputs[width*i:width*i+2]
            c=[0]*length if width==2 else inputs[width*i+2]
            term=[x^y for x,y in zip(truncated_product(field,a,b,length),c)]
            expected=term if expected is None else truncated_product(field,expected,term,length)
            av,bv,cv=map(codec.forward,(a,b,c))
            v=[field.mul(x,y)^z for x,y,z in zip(av,bv,cv)]
            values=v if values is None else [field.mul(x,y) for x,y in zip(values,v)]
        recovered=codec.inverse(values)
        assert recovered[:length]==expected and all(x==0 for x in recovered[degree+1:])
        tasks.append(dict(family=family,length=length,depth=3 if deep else 1,points=codec.size,independent_inputs=len(inputs),output_coefficients=length))
    return dict(status='PUBLIC_ADDITIVE_CRT_PASS',field_polynomial='0x1100b',profiles=profiles,tasks=tasks,
        algorithm='Sparse subspace-polynomial division and recursive CRT; O(K log^2 K) field operations',
        encrypted_execution=False,benchmark=False,security_certified=False)


if __name__=='__main__':print(json.dumps(check(),indent=2))
