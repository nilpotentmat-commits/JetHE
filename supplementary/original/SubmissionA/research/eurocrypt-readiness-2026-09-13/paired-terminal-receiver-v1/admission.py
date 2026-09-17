"""Exact deterministic admission and independent small-period phase checks."""
from hashlib import sha256
import json
from math import gcd,isqrt
from pathlib import Path
from random import Random

HERE=Path(__file__).resolve().parent
READY,ROOT=HERE.parent,HERE.parents[3]
N,S,Q=32768,96,(1 << 89)-1
KAPPA=4*N-3
F=2*KAPPA*S*S+S
BRAW=8*KAPPA*(F*F+F)+2*KAPPA


def bindings():
    paths=[HERE/x for x in ('PLAN.md','PROOF.md','admission.py')]
    paths += [READY/'prepared-contraction-audit-v1/verification.json',
              READY/'conventional-product-audit-v1/PROOF.md',
              READY/'receiver-kernels-v1/arithmetic.py',READY/'receiver-kernels-v1/codec.py',
              READY/'control-sampler-v1/sample_vectors.py',READY/'control-sampler-v1/table-receipt.json']
    return {p.relative_to(ROOT).as_posix():dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest()) for p in paths}


def prime(p):
    return p>=2 and all(p % d for d in range(2,isqrt(p)+1))


def lucas_lehmer(exponent):
    assert prime(exponent)
    value,modulus=4,(1 << exponent)-1
    chain=[]
    for _ in range(exponent-2):
        value=(value*value-2) % modulus
        chain.append(str(value))
    assert value==0
    return chain


def mul(a,b):
    n=len(a)
    assert len(b)==n
    p,out=2*n+1,[0]*n
    for i,x in enumerate(a,1):
        for j,y in enumerate(b,1):
            for index in (i+j,abs(i-j)):
                index %= p
                index=min(index,p-index)
                if index:
                    out[index-1]+=x*y
                else:
                    out=[v-2*x*y for v in out]
    return out


def add(*vectors):
    return [sum(x) for x in zip(*vectors)]


def scale(a,c):
    return [c*x for x in a]


def center(a,q):
    return [(x+q//2) % q-q//2 for x in a]


def phase_checks():
    rng=Random(202609140089)
    cases,coefficient_checks,product_norm_entries=0,0,0
    for p in (3,5,7,11,17,23,41):
        assert prime(p)
        n=(p-1)//2
        kappa=4*n-3
        norm=[0]*n
        for i in range(n):
            for j in range(n):
                a,b=[int(i==v) for v in range(n)],[int(j==v) for v in range(n)]
                norm=add(norm,[abs(x) for x in mul(a,b)])
                product_norm_entries+=n
        assert norm==[kappa]*n
        assert all(abs((x-(x % 2))//2)<=2*kappa for x in range(-4*kappa,4*kappa+1))
        fresh=2*kappa+1
        rawcap=8*kappa*(fresh*fresh+fresh)+2*kappa
        q=(1 << (2+4*rawcap).bit_length())-1
        assert q>2+4*rawcap
        for _ in range(12):
            secret,error=[[rng.randrange(-1,2) for _ in range(n)] for _ in range(2)]
            mask=[rng.randrange(q) for _ in range(n)]
            body=[x % q for x in add(scale(mul(mask,secret),-1),scale(error,2))]
            ciphertexts,chosen=[],[]
            for _ in range(4):
                u,e0,e1=[[rng.randrange(-1,2) for _ in range(n)] for _ in range(3)]
                message=[rng.randrange(2) for _ in range(n)]
                E=add(mul(error,u),e0,mul(e1,secret))
                assert max(map(abs,E))<=fresh
                c0=[x % q for x in add(mul(body,u),scale(e0,2),message)]
                c1=[x % q for x in add(mul(mask,u),scale(e1,2))]
                assert center(add(c0,mul(c1,secret)),q)==add(message,scale(E,2))
                ciphertexts.append((c0,c1));chosen.append((message,E))
            a=[add(ciphertexts[0][i],ciphertexts[1][i]) for i in range(2)]
            b=[add(ciphertexts[2][i],ciphertexts[3][i]) for i in range(2)]
            low,high=mul(a[0],b[0]),mul(a[1],b[1])
            middle=add(mul(add(*a),add(*b)),scale(low,-1),scale(high,-1))
            assert middle==add(mul(a[0],b[1]),mul(a[1],b[0]))
            M1,E1=add(chosen[0][0],chosen[1][0]),add(chosen[0][1],chosen[1][1])
            M2,E2=add(chosen[2][0],chosen[3][0]),add(chosen[2][1],chosen[3][1])
            signal=mul(M1,M2)
            before=add(mul(M1,E2),mul(M2,E1),scale(mul(E1,E2),2))
            canonical=[x % 2 for x in signal]
            carry=[(x-y)//2 for x,y in zip(signal,canonical)]
            full=add(before,carry)
            assert max(map(abs,signal))<=4*kappa
            assert max(map(abs,carry))<=2*kappa and max(map(abs,full))<=rawcap
            recovered=center(add(low,mul(middle,secret),mul(high,mul(secret,secret))),q)
            assert recovered==add(canonical,scale(full,2))
            assert [x % 2 for x in recovered]==canonical
            coefficient_checks+=n
            cases+=1
    return dict(rings=7,mixed_raw_product_cases=cases,raw_output_coefficients=coefficient_checks,
                product_constant_tensor_entries=product_norm_entries,cryptographic_coins=False)


def main():
    before=bindings()
    assert prime(65537) and gcd(Q,2*65537)==1
    chain=lucas_lehmer(89)
    assert Q>2+4*BRAW
    assert BRAW>=2*F and Q>2*(2+4*F)
    selected=dict(n=N,conductor=65537,source_cap=S,kappa=KAPPA,q=str(Q),q_bits=Q.bit_length(),
                  fresh_cap=str(F),mixed_error_cap=str(2*F),raw_cap=str(BRAW),
                  strict_threshold=str(2+4*BRAW),strict_margin=str(Q-(2+4*BRAW)),
                  coefficient_bytes=12,inputs=348,raw_products=86,bypasses=4,
                  finite_source_vectors=1046,uniform_polynomials=1,
                  public_payload_bytes=2*N*12,input_payload_bytes=696*N*12,output_payload_bytes=266*N*12,
                  predicted_ring_products=dict(public_key=1,encryption=696,raw_tensors=258,
                                               input_validation=348,secret_square=1,terminal_decryption=176),
                  predicted_total_ring_products=1480,uniform_failure_upper_exponent=89*256-15)
    assert sum(selected['predicted_ring_products'].values())==1480
    result=dict(status='PAIRED_UNSCALED_TERMINAL_ADMISSION_CHECKS_PASS',selected=selected,
                lucas_lehmer_exponent=89,lucas_lehmer_chain=chain,small=phase_checks(),
                new_he_execution=False,security_bits=None,source_hardness_established=False,
                bindings_before=before,bindings_after=bindings())
    assert before==result['bindings_after']
    (HERE/'admission.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('status','selected','small','new_he_execution','security_bits')},indent=2))


if __name__=='__main__':
    main()
