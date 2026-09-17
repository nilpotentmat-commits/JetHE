from array import array
import ctypes as C
from pathlib import Path
HERE=Path(__file__).resolve().parent
from prepare import Field,slow_mul

def tables(field,t=128,length=256):
    assert 1<=t<=128 and 2*t-1<=length<=256
    points=list(range(t))
    polynomial=[1]
    for point in points:
        nxt=[0]*(len(polynomial)+1)
        for i,c in enumerate(polynomial):
            nxt[i]^=field.mul(point,c)
            nxt[i+1]^=c
        polynomial=nxt
    interpolation=[[0]*t for _ in points]
    for col,point in enumerate(points):
        quotient=[0]*t
        quotient[-1]=1
        for j in range(t-1,0,-1):
            quotient[j-1]=polynomial[j]^field.mul(point,quotient[j])
        assert polynomial[0]^field.mul(point,quotient[0])==0
        denominator=0
        for c in reversed(quotient):
            denominator=field.mul(denominator,point)^c
        assert denominator
        inv=field.exp[65535-field.log[denominator]]
        assert field.mul(denominator,inv)==1
        for row,c in enumerate(quotient):
            interpolation[row][col]=field.mul(c,inv)
    evaluation=[]
    for point in points:
        row=[1]
        for _ in range(length-1): row.append(field.mul(row[-1],point))
        evaluation.append(row)
    return interpolation,evaluation


class Interpolation:
    def __init__(self,field,t=128,length=256):
        self.t,self.length=t,length
        self.inverse,self.evaluation=tables(field,t,length)
        self.inverse_flat=array('H',(x for row in self.inverse for x in row))
        self.evaluation_flat=array('H',(x for row in self.evaluation for x in row))
        self.logs=array('H',(max(0,x) for x in field.log))
        self.exps=array('H',field.exp)
        self.dll=C.CDLL(str(HERE.parent/'build/interpolation.so'))
        self.dll.sa_matrix.argtypes=[C.c_void_p]*5+[C.c_uint]*3
        self.dll.sa_matrix.restype=C.c_int

    def apply(self,value,matrix,rows,cols,jobs):
        assert isinstance(value,array) and value.typecode=='H' and len(value)==cols*jobs
        assert len(matrix)==rows*cols and 1<=jobs<=16
        out=array('H',[0])*(rows*jobs)
        def ptr(a): return (C.c_uint16*len(a)).from_buffer(a)
        assert self.dll.sa_matrix(ptr(value),ptr(out),ptr(matrix),ptr(self.logs),ptr(self.exps),rows,cols,jobs)==0
        return out

    def encode(self,value,jobs=16):
        compact=self.apply(value,self.inverse_flat,self.t,self.t,jobs)
        out=array('H',[0])*(jobs*self.length)
        for lane in range(jobs):
            out[lane*self.length:lane*self.length+self.t]=compact[lane*self.t:(lane+1)*self.t]
        return out

    def decode(self,value,jobs=16):
        return self.apply(value,self.evaluation_flat,self.t,self.length,jobs)

