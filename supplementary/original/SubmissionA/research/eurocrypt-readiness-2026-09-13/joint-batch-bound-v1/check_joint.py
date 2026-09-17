"""Finite joint-function and mixed-difference checks; no HE or proof certification."""
from pathlib import Path
from hashlib import sha256
from random import Random
import json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent; READY=HERE.parent; ROOT=HERE.parents[3]
WITNESS=READY/'fixed-field-count-audit-v1'
sys.path.insert(0,str(WITNESS))
import check_additive_witness as witness
import boolean_screen as boolean


def binding(p):
    data=p.read_bytes();return dict(bytes=len(data),sha256=sha256(data).hexdigest())


def selected_functions(length):
    powers,_=boolean.powers(length)
    _,polys=witness.witness_polynomials(length)
    chosen=[]
    for _,valuation,poly in polys:
        values=witness.symbolic_evaluate(poly,powers,length)
        chosen.extend(values[valuation:])
    assert all(row and 0 not in row for row in chosen)
    expected=(5*length*length+4*(length.bit_length())*length)//64
    assert len(chosen)==boolean.rank(chosen)==expected
    return chosen


def mixed_checks():
    rng=Random(2026091501); records=[]
    for case in range(8):
        # Four private bits per owner, interpreted as two two-bit batches.
        size=16; output=3; prims=[]
        for index in range(2):
            left=3+case%3;right=2+(case+index)%3; middle=3+index
            def table(width):
                data=[rng.randrange(1<<width) for _ in range(size)]
                # Force a cross-batch nonlinear coordinate, including a constant.
                for x in range(size):data[x]=(data[x]&~1)|(((x&1)*((x>>2)&1))^1)
                return data
            A,B,C,D=table(left),table(left),table(right),table(right)
            tensor=[[rng.randrange(1<<right) for _ in range(left)] for _ in range(middle)]
            recovery=[rng.randrange(1<<middle) for _ in range(output)]
            prims.append((left,right,A,B,C,D,tensor,recovery))
        bypassF=[rng.randrange(1<<output) for _ in range(size)]
        bypassG=[rng.randrange(1<<output) for _ in range(size)]
        def beta(x,y,tensor):
            value=0
            for o,rows in enumerate(tensor):
                bit=0
                for i,row in enumerate(rows):
                    if (x>>i)&1:bit^=(row&y).bit_count()&1
                value|=bit<<o
            return value
        def recover(value,rows):
            return sum(((value&row).bit_count()&1)<<i for i,row in enumerate(rows))
        def evaluate(f,g):
            result=bypassF[f]^bypassG[g]
            for _,_,A,B,C,D,tensor,recovery in prims:
                result^=recover(beta(A[f]^B[g],C[f]^D[g],tensor),recovery)
            return result
        generators=[]
        for left,right,A,B,C,D,_,_ in prims:
            for values,width in ((B,left),(D,right)):
                generators.extend(sum((((values[g]^values[0])>>j)&1)<<g for g in range(size)) for j in range(width))
        span=boolean.binary_rank(generators);targets=[];checked=0
        for f in range(size):
            row=[]
            for g in range(size):
                actual=evaluate(f,g)^evaluate(f,0)^evaluate(0,g)^evaluate(0,0)
                expected=0
                for _,_,A,B,C,D,tensor,recovery in prims:
                    expected^=recover(beta(A[f]^A[0],D[g]^D[0],tensor)^beta(B[g]^B[0],C[f]^C[0],tensor),recovery)
                assert actual==expected,(case,f,g);row.append(actual);checked+=output
            targets.extend(sum(((row[g]>>j)&1)<<g for g in range(size)) for j in range(output))
        assert boolean.binary_rank(generators+targets)==span
        records.append(dict(case=case,batches=2,primitives=2,recovered_bit_values=checked,
                            centered_generators=len(generators),generator_rank=span,target_functions=len(targets)))
    return records


def main():
    assert not (HERE/'check.json').exists(),'Preserve earlier execution'
    context=[HERE/'PLAN.md',HERE/'PROOF.md',Path(__file__),READY/'JOINT_BATCH_COMPARISON_PLAN.md',
             WITNESS/'check_additive_witness.py',WITNESS/'boolean_screen.py',
             READY/'ciphertext-length-audit-v1/PROOF.md',READY/'batched-hasse-matrix-v1/PROOF.md']
    context += [READY/'checkpoint-v36'/name for name in (
        'manuscript/appendices/fixed-field-carrier-bound.tex',
        'manuscript/appendices/prepared-contraction-bounds.tex',
        'manuscript/appendices/joint-hasse-work.tex')]
    sources={p.relative_to(ROOT).as_posix():binding(p) for p in context}
    ranks=[]
    for length in (8,16,32,64):
        rows=selected_functions(length)
        for batches in (1,2,3,5):
            joint=[{m<<(a*(length-1)) for m in row} for a in range(batches) for row in rows]
            rank=boolean.rank(joint);assert rank==batches*len(rows)
            # Pull back all blocks along the diagonal g_a=g_0.
            diagonal=boolean.rank(rows*batches);assert diagonal==len(rows)
            constants=boolean.rank([{0} for _ in range(batches)]);assert constants==1
            record=dict(length=length,batches=batches,one_block_witness=len(rows),joint_rank=rank,
                        diagonal_promise_rank=diagonal,uncentered_constants_rank=constants)
            ranks.append(record);print(json.dumps(record),flush=True)
    mixed=mixed_checks()
    # Capacity counts only, never timings or numerical security.
    counts=[]
    for length in (256,1024,1<<20):
        d=length.bit_length()-1;c=(5*length*length+4*(d+1)*length)//64
        for batches in (1,2,16,1024):
            counts.append(dict(length=length,batches=batches,h=16,s=16,capacity=256*length,
                inner_width=16*batches*c,mixed_calls=(batches*c+32*length-1)//(32*length),
                inner_carriers=(batches*c+16*length-1)//(16*length),
                outer_carriers=(batches*(length-1)+length-1)//length))
    for name,want in sources.items():assert binding(ROOT/name)==want,name
    record=dict(status='JOINT_BATCH_FUNCTION_CHECKS_PASS',rank_cases=ranks,mixed_cases=mixed,count_cases=counts,
                total_joint_witnesses=sum(x['joint_rank'] for x in ranks),
                mixed_recovered_bit_values=sum(x['recovered_bit_values'] for x in mixed),
                source_bindings=sources,new_he_execution=False,new_timing=False,new_security_attack=False,
                mathematical_proof_verified_by_program=False,security_bits=None)
    (HERE/'check.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(status=record['status'],rank_cases=len(ranks),mixed_cases=len(mixed),count_cases=len(counts),
                         total_joint_witnesses=record['total_joint_witnesses'],mixed_recovered_bit_values=record['mixed_recovered_bit_values']),indent=2))


if __name__=='__main__':main()
