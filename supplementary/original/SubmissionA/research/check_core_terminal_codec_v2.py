"""Balanced W1/W2 public execution check; preserves the earlier V1 receipt.

V1's depth field described the intended balanced circuit, while its four
factor test multiplied sequentially. This check executes the balanced DAG.
"""
from hashlib import sha256
from pathlib import Path
from random import Random
import json
import core_terminal_codec as core


def check():
    rng=Random(2026090843);tasks=[]
    for length,family in ((16,'W1'),(256,'W1'),(256,'W2-shallow'),(256,'W2-deep')):
        deep=family=='W2-deep';degree=(8 if deep else 2)*(length-1)
        codec=core.AdditiveCRT(degree.bit_length());field=codec.field
        count=4 if deep else 1;width=2 if family=='W1' else 3
        inputs=[[rng.randrange(65536) for _ in range(length)] for _ in range(width*count)]
        factors=[];values=[];products=adds=0
        for i in range(count):
            a,b=inputs[width*i:width*i+2]
            c=[0]*length if width==2 else inputs[width*i+2]
            f=core.truncated_product(field,a,b,length)
            av,bv=map(codec.forward,(a,b));v=[field.mul(x,y) for x,y in zip(av,bv)];products+=1
            if width==3:
                f=[x^y for x,y in zip(f,c)];cv=codec.forward(c);v=[x^y for x,y in zip(v,cv)];adds+=1
            factors.append(f);values.append(v)
        depth=1;level_widths=[count]
        while len(factors)>1:
            assert len(factors)%2==0
            factors=[core.truncated_product(field,factors[i],factors[i+1],length) for i in range(0,len(factors),2)]
            values=[[field.mul(x,y) for x,y in zip(values[i],values[i+1])] for i in range(0,len(values),2)]
            products+=len(factors);depth+=1;level_widths.append(len(factors))
        recovered=codec.inverse(values[0])
        assert recovered[:length]==factors[0] and all(x==0 for x in recovered[degree+1:])
        assert (products,adds,depth)==((7,4,3) if deep else (1,0 if width==2 else 1,1))
        tasks.append(dict(family=family,length=length,points=codec.size,independent_inputs=len(inputs),
            executed_products=products,executed_additions=adds,executed_multiplicative_depth=depth,
            product_level_widths=level_widths,output_coefficients=length))
    sources=[Path(__file__),Path(core.__file__)]
    return dict(status='BALANCED_CORE_TERMINAL_CRT_PASS',tasks=tasks,
        source_sha256={p.name:sha256(p.read_bytes()).hexdigest() for p in sources},
        field_polynomial='0x1100b',encrypted_execution=False,benchmark=False,security_certified=False,
        storage_scope='O(K) live CRT workspace and O(K+log^2K) CRT constants, plus the fixed GF65536 log/exponent/Frobenius tables and their initialization')


if __name__=='__main__':print(json.dumps(check(),indent=2))
