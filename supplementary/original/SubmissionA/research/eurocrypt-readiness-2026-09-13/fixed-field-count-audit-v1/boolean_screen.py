"""Exact public Boolean coefficient-function ranks; no encryption or secret input."""
from pathlib import Path
from time import perf_counter
import json
HERE=Path(__file__).resolve().parent


def powers(length):
    rows=[None]*length
    rows[0]=[{0}]+[set() for _ in range(length-1)]
    total=1
    for degree in range(1,length):
        stride=degree & -degree
        previous=rows[degree-stride]
        current=[set() for _ in range(length)]
        for j,terms in enumerate(previous):
            if not terms:continue
            for v in range(1,(length-1-j)//stride+1):
                target=current[j+stride*v]
                bit=1 << (v-1)
                for monomial in terms:
                    value=monomial | bit
                    if value in target:target.remove(value)
                    else:target.add(value)
        total+=sum(map(len,current))
        assert total<=2_000_000,'Predeclared symbolic-size cap'
        rows[degree]=current
    return rows,total


def rank(supports):
    basis={}
    for support in supports:
        value=set(support)
        while value:
            pivot=max(value)
            if pivot in basis:value.symmetric_difference_update(basis[pivot])
            else:
                basis[pivot]=value
                break
    return len(basis)


def binary_rank(values):
    basis={}
    for value in values:
        while value:
            pivot=value.bit_length()-1
            if pivot in basis:value^=basis[pivot]
            else:
                basis[pivot]=value
                break
    return len(basis)


def truth_table_check(length,rows):
    # Independent successive polynomial multiplication in F2[z]/z^L.
    tables={(i,j):0 for i in range(1,length) for j in range(1,length)}
    for assignment in range(1 << (length-1)):
        g=assignment<<1
        value=1
        for i in range(1,length):
            product=0
            for v in range(1,length):
                if (g>>v)&1:product^=value<<v
            value=product & ((1<<length)-1)
            for j in range(1,length):
                expected=(value>>j)&1
                actual=sum((assignment & mask)==mask for mask in rows[i][j])&1
                assert actual==expected,(length,assignment,i,j)
                tables[i,j]|=expected<<assignment
    return binary_rank(tables.values()),(1 << (length-1))*(length-1)**2


def main():
    assert not (HERE/'boolean-screen.json').exists(),'Preserve previous diagnostic'
    started=perf_counter();results=[]
    for length in (2,4,8,16,32,64):
        rows,terms=powers(length)
        supports=[row for group in rows[1:] for row in group[1:] if row]
        dimension=rank(supports)
        check=None
        if length<=8:
            tr,checks=truth_table_check(length,rows)
            assert tr==dimension
            check=dict(rank=tr,coefficient_values=checks)
        result=dict(length=length,nonzero_rows=len(supports),dimension=dimension,
                    large_field_dimension=(length*length-1)//3,
                    symbolic_occurrences=terms,truth_table=check)
        results.append(result);print(json.dumps(result),flush=True)
    record=dict(status='BOOLEAN_COEFFICIENT_RANK_DIAGNOSTIC_PASS',results=results,
                wall_seconds=perf_counter()-started,new_he_execution=False,
                new_security_attack=False,security_bits=None,
                scope='Exact finite Boolean polynomial-function ranks only; no asymptotic lower bound inferred.')
    (HERE/'boolean-screen.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
