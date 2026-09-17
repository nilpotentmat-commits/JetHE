"""Small exact scalar matrix algorithms and instrumented arithmetic counts."""

class Ops:
    def __init__(self,q):self.q=q;self.products=0;self.additions=0
    def mul(self,x,y):self.products+=1;return x*y%self.q
    def add(self,x,y,sign=1):self.additions+=1;return (x+sign*y)%self.q


def add(A,B,ops,sign=1):
    return [[ops.add(x,y,sign) for x,y in zip(a,b)] for a,b in zip(A,B)]


def parts(A):
    h=len(A)//2
    return [r[:h] for r in A[:h]],[r[h:] for r in A[:h]],[r[:h] for r in A[h:]],[r[h:] for r in A[h:]]


def prepare(A,s,ops):
    if s==0:return ('leaf',A)
    a,b,c,d=parts(A)
    left=(add(a,d,ops),add(c,d,ops),a,d,add(a,b,ops),add(c,a,ops,-1),add(b,d,ops,-1))
    return ('node',tuple(prepare(x,s-1,ops) for x in left))


def evaluate(tree,B,ops):
    if tree[0]=='leaf':
        A=tree[1];n=len(A)
        out=[]
        for row in A:
            result=[]
            for j in range(len(B[0])):
                value=ops.mul(row[0],B[0][j])
                for k in range(1,n):value=ops.add(value,ops.mul(row[k],B[k][j]))
                result.append(value)
            out.append(result)
        return out
    f,g,h,i=parts(B)
    right=(add(f,i,ops),f,add(g,i,ops,-1),add(h,f,ops,-1),i,add(f,g,ops),add(h,i,ops))
    p1,p2,p3,p4,p5,p6,p7=[evaluate(t,b,ops) for t,b in zip(tree[1],right)]
    c11=add(add(add(p1,p4,ops),p5,ops,-1),p7,ops)
    c12=add(p3,p5,ops);c21=add(p2,p4,ops)
    c22=add(add(add(p1,p2,ops,-1),p3,ops),p6,ops)
    return [a+b for a,b in zip(c11,c12)]+[a+b for a,b in zip(c21,c22)]


def rectangular(A,D,e,g,B,s,cache,q):
    runtime=Ops(q);public=Ops(q)
    if s==0:
        # g blocks of e-term dots, accumulated exactly as the ledger specifies.
        out=[[0]*B for _ in range(2*e)]
        for i in range(2*e):
            for j in range(B):
                for h in range(g):
                    value=runtime.mul(A[i][h*e],D[h*e][j])
                    for k in range(h*e+1,(h+1)*e):value=runtime.add(value,runtime.mul(A[i][k],D[k][j]))
                    out[i][j]=runtime.add(out[i][j],value)
        assert runtime.products==runtime.additions==2*g*e*e*B
        return out,runtime,public
    padded=((B+e-1)//e)*e
    out=[[0]*padded for _ in range(2*e)]
    cached={}
    if cache:
        for br in range(2):
            for bc in range(g):
                cached[br,bc]=prepare([row[bc*e:(bc+1)*e] for row in A[br*e:(br+1)*e]],s,public)
    for start in range(0,padded,e):
        for br in range(2):
            acc=[[0]*e for _ in range(e)]
            for bc in range(g):
                right=[[row[j] if j<B else 0 for j in range(start,start+e)] for row in D[bc*e:(bc+1)*e]]
                tree=cached[br,bc] if cache else prepare([row[bc*e:(bc+1)*e] for row in A[br*e:(br+1)*e]],s,runtime)
                acc=add(acc,evaluate(tree,right,runtime),runtime)
            for i in range(e):out[br*e+i][start:start+e]=acc[i]
    m=e//(1<<s);v=7**s;blocks=2*g*((B+e-1)//e)
    public_per=5*(v*m*m-e*e)//3
    assert runtime.products==blocks*v*m**3
    assert runtime.additions==blocks*(v*(m**3-m*m)+6*(v*m*m-e*e)+e*e-(public_per if cache else 0))
    assert public.additions==(2*g*public_per if cache else 0)
    return [row[:B] for row in out],runtime,public
