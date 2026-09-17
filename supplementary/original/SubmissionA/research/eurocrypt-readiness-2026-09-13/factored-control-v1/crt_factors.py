"""Explicit public sparse factors for the existing monomial additive CRT.

No encryption or file writes. Field matrices are compiled before input values.
"""
from functools import lru_cache
from pathlib import Path
import sys

RESEARCH = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(RESEARCH))
from core_terminal_codec import AdditiveCRT
from check_fused_composition_frontier import FastField

FIELD = FastField()

def add(row,column,value):
    if value:
        value ^= row.get(column,0)
        if value:
            row[column] = value
        else:
            row.pop(column,None)

def freeze(rows):
    return tuple(tuple(sorted(row.items())) for row in rows)

def identity(size):
    return tuple(((i,1),) for i in range(size))

def apply(matrix,values):
    assert len(matrix)==len(values)
    out = []
    for row in matrix:
        value = 0
        for column,scalar in row:
            value ^= FIELD.mul(scalar,values[column])
        out.append(value)
    return out

def compose(after,before):
    assert len(after)==len(before)
    rows = []
    for row in after:
        result = {}
        for middle,a in row:
            for column,b in before[middle]:
                add(result,column,FIELD.mul(a,b))
        rows.append(result)
    return freeze(rows)

@lru_cache(maxsize=None)
def elementary(size,direction):
    assert size>=1 and size&(size-1)==0 and size<=256
    assert direction in ('forward','inverse')
    if size==1:
        return ()
    codec = AdditiveCRT(size.bit_length()-1)
    layers = []
    levels = range(codec.log_size,0,-1) if direction=='forward' else range(1,codec.log_size+1)
    for level in levels:
        d = 1<<(level-1)
        lower = [(e,v) for e,v in codec.polynomials[level-1].items() if e<d]
        assert all(1<=e<=d//2 for e,v in lower)
        first,second = [dict() for _ in range(size)],[dict() for _ in range(size)]
        for base in range(0,size,2*d):
            c0 = codec.offsets[level,base]
            c1 = c0 ^ codec.split[level-1]
            inv = codec.inverse_split[level-1]
            for i in range(d):
                low,high = base+i,base+d+i
                add(first[low],low,1)
                if direction=='forward':
                    # q=h+T(h); lower terms have degree at most d/2, so T^2=0.
                    add(first[high],high,1)
                    for e,v in lower:
                        if i<e:
                            add(first[high],base+2*d+i-e,v)
                    for target,c in ((low,c0),(high,c1)):
                        add(second[target],low,1)
                        add(second[target],high,c)
                        for e,v in lower:
                            if i>=e:
                                add(second[target],base+d+i-e,v)
                else:
                    # q=(left+right)/split; reconstruct left+c0*q+q*V.
                    add(first[high],low,inv)
                    add(first[high],high,inv)
                    add(second[low],low,1)
                    add(second[low],high,c0)
                    add(second[high],high,1)
                    for e,v in lower:
                        if i>=e:
                            add(second[low],base+d+i-e,v)
                        if i<e:
                            add(second[high],base+2*d+i-e,v)
        for role,matrix in (('quotient',freeze(first)),('reconstruct',freeze(second))):
            if matrix!=identity(size):
                layers.append((f'{direction}-level{level}-{role}',matrix))
    return tuple(layers)

@lru_cache(maxsize=None)
def factors(size,direction,width):
    assert width in (1,2,4,8,16)
    original = elementary(size,direction)
    out = []
    for start in range(0,len(original),width):
        matrix = identity(size)
        names = []
        for name,next_matrix in original[start:start+width]:
            names.append(name)
            matrix = compose(next_matrix,matrix)
        if matrix!=identity(size):
            out.append(('+'.join(names),matrix))
    return tuple(out)

def transform(values,direction,width=1):
    for name,matrix in factors(len(values),direction,width):
        values = apply(matrix,values)
    return list(values)

def check():
    results = []
    checked = 0
    for log_size in range(9):
        size = 1<<log_size
        full = identity(size)
        for _,matrix in elementary(size,'forward'):
            full = compose(matrix,full)
        # Every matrix entry is checked against monomial evaluation.
        for point,row in enumerate(full):
            want = {}
            power = 1
            for exponent in range(size):
                if power:
                    want[exponent] = power
                power = FIELD.mul(power,point)
            assert dict(row)==want,(size,point)
            checked += size
        inverse = identity(size)
        for _,matrix in elementary(size,'inverse'):
            inverse = compose(matrix,inverse)
        assert compose(inverse,full)==identity(size),size
        for width in (1,2,4,8,16):
            for direction,want in (('forward',full),('inverse',inverse)):
                actual = identity(size)
                for _,matrix in factors(size,direction,width):
                    actual = compose(matrix,actual)
                assert actual==want,(size,direction,width)
        results.append(dict(points=size,
            forward_elementary_layers=len(elementary(size,'forward')),
            inverse_elementary_layers=len(elementary(size,'inverse')),
            layers_by_fusion_width={str(w):[len(factors(size,d,w)) for d in ('forward','inverse')]
                                    for w in (1,2,4,8,16)}))
        print(f'CRT matrix verified at {size} points',flush=True)
    return dict(status='SPARSE_CRT_FACTORS_PASS',monomial_matrix_entries=checked,
                complete_inverse_products=9,fusion_policies=5,profiles=results,
                scope='Exact field-matrix identities; no HE, noise admission or timing advantage.')

if __name__=='__main__':
    import json
    print(json.dumps(check(),indent=2))
