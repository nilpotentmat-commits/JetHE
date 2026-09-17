"""Finite stress cases for the written general-bilinear span argument."""
from hashlib import sha256
from itertools import product
import json
from math import ceil
from pathlib import Path
from random import Random
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
PC=HERE.parent/'prepared-contraction-audit-v1'
sys.path.insert(0,str(PC))
from check_contraction import Field, rank, function_ranks, horner, numeric_powers


def add(a,b): return [x^y for x,y in zip(a,b)]


def stress(binary):
    field=Field(2,7)
    rng=Random(202609141+binary)
    domain=list(product(range(4),repeat=2))
    r,t,outdim=(3,2,7) if binary else (2,3,5)
    q=2 if binary else 4
    # Arbitrary nonlinear owner maps mixing both job coordinates, including
    # nonzero constants. The opposite owner is not an argument to a map.
    maps=[[[rng.randrange(q) for _ in range(n)] for _ in domain] for n in (r,r,t,t)]
    A,B,C,D=maps
    tensor=[[[rng.randrange(q) for _ in range(t)] for _ in range(r)] for _ in range(outdim)]
    recovery=[[rng.randrange(4) for _ in range(outdim)] for _ in range(4)]
    def beta(a,b):
        return [sum_xor(field.mul(c,field.mul(a[i],b[j]))
                        for i,row in enumerate(slab) for j,c in enumerate(row)) for slab in tensor]
    def recover(v):
        return [sum_xor(field.mul(a,b) for a,b in zip(row,v)) for row in recovery]
    rows=[]
    for f in range(len(domain)):
        targets=[[] for _ in recovery]
        for g in range(len(domain)):
            direct=add(add(beta(add(A[f],B[g]),add(C[f],D[g])),
                           beta(add(A[0],B[g]),add(C[0],D[g]))),
                       add(beta(add(A[f],B[0]),add(C[f],D[0])),
                           beta(add(A[0],B[0]),add(C[0],D[0]))))
            predicted=add(beta(add(A[f],A[0]),add(D[g],D[0])),
                          beta(add(B[g],B[0]),add(C[f],C[0])))
            assert direct==predicted
            for row,value in zip(targets,recover(direct)): row.append(value)
        rows.extend(targets)
    generators=[[table[g][i]^table[0][i] for g in range(len(domain))]
                for table,width in ((B,r),(D,t)) for i in range(width)]
    dimension=rank(generators,field)
    assert rank(generators+rows,field)==dimension<=r+t
    if binary:
        squared=[[field.mul(v,v) for v in row] for row in rows]
        assert rank(generators+rows+squared,field)==dimension
    return dict(binary=binary,all_input_pairs=len(domain)**2,operand_widths=[r,t],
                output_width=outdim,recovered_K_coordinates=4,
                inner_generator_rank=dimension,mixed_output_rank=rank(rows,field),
                frobenius_stable_generator_span=binary)


def sum_xor(values):
    out=0
    for v in values: out^=v
    return out


def ramified():
    field=Field(2,7)
    rng=Random(20260914130)
    from check_contraction import convolution
    checks=0
    for _ in range(64):
        vectors=[[rng.randrange(4) for _ in range(4)] for _ in range(8)]
        A,A0,B,B0,C,C0,D,D0=vectors
        def mul(a,b):return convolution(a,b,field,4)
        direct=add(add(mul(add(A,B),add(C,D)),mul(add(A0,B),add(C0,D))),
                   add(mul(add(A,B0),add(C,D0)),mul(add(A0,B0),add(C0,D0))))
        expected=add(mul(add(A,A0),add(D,D0)),mul(add(B,B0),add(C,C0)))
        assert direct==expected
        checks+=4
    # Degree overflow destroys the unrestricted interpolation shortcut.
    a=[0,0,0,1]
    assert mul(a,a)==[0]*4 and sum_xor(a)==1
    return dict(truncated_product_mixed_coefficients=checks,
                unrestricted_product_evaluation_counterexample=True)


def ledger():
    h,L,s=16,256,16
    H=h*(L*L-1)//3
    T=h*s*L*L//4
    values=[]
    for symbols in (4096,2048):
        w=s*symbols
        values.append(dict(K_capacity=symbols,binary_capacity=w,
            mixed_K_calls=ceil(H/(2*symbols)),mixed_binary_calls=ceil(T/(2*w)),
            separated_K_calls=ceil(H/symbols),separated_binary_calls=ceil(T/w),
            initial_inner_K=ceil(H/symbols),initial_inner_binary=ceil(T/w),
            initial_outer_K=ceil(h*(L-1)/symbols),initial_outer_binary=ceil(h*s*(L-1)/w)))
    assert [(v['mixed_K_calls'],v['mixed_binary_calls']) for v in values]==[(43,32),(86,64)]
    assert [(v['initial_inner_K']+v['initial_outer_K'],v['initial_inner_binary']+v['initial_outer_binary']) for v in values]==[(87,65),(173,130)]
    return dict(h=h,L=L,s=s,coefficient_dimension=H,frobenius_dimension=T,carriers=values)


def main():
    paths=[HERE/'PROOF.md',HERE/'check_carriers.py',PC/'PROOF.md',PC/'check_contraction.py']
    def bind():return {p.relative_to(ROOT).as_posix():dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest()) for p in paths}
    before=bind()
    result=dict(status='BILINEAR_CARRIER_FINITE_AND_CAPACITY_CHECKS_PASS',
                general_bilinear=[stress(False),stress(True)],ramified=ramified(),
                inherited_small_target_ranks=function_ranks(),ledger=ledger(),
                formal_proof_checked=False,encrypted_execution=False,
                total_time_lower_bound=False,security_bits=None,bindings_before=before,bindings_after=bind())
    assert result['bindings_before']==result['bindings_after']
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('status','general_bilinear','ledger')}))


if __name__=='__main__':main()
