"""Exact PUBLIC algebra fixtures. No encryption, source sampling or timing claim."""
from hashlib import sha256
from importlib.util import spec_from_file_location, module_from_spec
from math import log2, ceil
from pathlib import Path
from random import Random
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
READY = HERE.parent
ROOT = HERE.parents[3]


def binding(p):
    data = p.read_bytes()
    return dict(bytes=len(data), sha256=sha256(data).hexdigest())


def sources():
    paths = [HERE / x for x in ('PLAN.md', 'PROOF.md', 'check_matrix.py')]
    paths += [READY / 'prefix-reuse-audit-v1' / x for x in ('PROOF.md', 'check_reuse.py')]
    paths += [READY.parent / 'check_gaussian_family_resources.py']
    paths += [READY / 'manuscript' / x for x in (
        'sections/prepared-composition.tex', 'appendices/resource-ledgers.tex',
        'appendices/fast-prepared-work.tex', 'appendices/gaussian-security-family.tex')]
    paths += sorted(p for p in (HERE / 'sources').iterdir() if p.is_file())
    return {p.relative_to(ROOT).as_posix(): binding(p) for p in paths}


def reference_product(a, b, L, p, q):
    """Ordinary unreduced bivariate convolution, then monic long division."""
    m = p - 1
    work = [[0] * (2*m-1) for _ in range(2*L-1)]
    left = [(i//m, i % m, v) for i, v in enumerate(a) if v]
    right = [(i//m, i % m, v) for i, v in enumerate(b) if v]
    for ti, bi, v in left:
        for tj, bj, w in right:
            work[ti+tj][bi+bj] += v*w
    for row in work:
        for j in range(2*m-2, m-1, -1):
            value = row[j]
            row[j] = 0
            for k in range(m):
                row[j-m+k] -= value
    for i in range(2*L-2, L-1, -1):
        for j in range(m):
            work[i-L][j] -= work[i][j]
    return tuple(work[i][j] % q for i in range(L) for j in range(m))


class Ring:
    def __init__(self, L, p, q):
        self.L, self.p, self.q = L, p, q
        self.m, self.n = p-1, L*(p-1)
        self.zero = (0,) * self.n
        self.multiplies = self.additions = 0

    def add(self, a, b, sign=1):
        self.additions += 1
        return tuple((v+sign*w) % self.q for v, w in zip(a, b))

    def mul(self, a, b):
        """Cyclic b^p=1 folding followed by Phi_p quotient, independently."""
        self.multiplies += 1
        work = [[0]*self.p for _ in range(self.L)]
        left = [(i//self.m, i % self.m, v) for i, v in enumerate(a) if v]
        right = [(i//self.m, i % self.m, v) for i, v in enumerate(b) if v]
        for ti, bi, v in left:
            for tj, bj, w in right:
                t = ti+tj
                work[t % self.L][(bi+bj) % self.p] += v*w*(1 if t < self.L else -1)
        return tuple((row[j]-row[-1]) % self.q for row in work for j in range(self.m))

    def oracle(self, a, b):
        return reference_product(a, b, self.L, self.p, self.q)


def fixture(ring, rng, sparse=False):
    if not sparse:
        return tuple(rng.randrange(ring.q) for _ in range(ring.n))
    out = [0]*ring.n
    for _ in range(12):
        out[rng.randrange(ring.n)] = rng.randrange(ring.q)
    return tuple(out)


def split(a, e, ring):
    return [tuple(a[(e*j+i)*ring.m+v] for j in range(ring.L//e) for v in range(ring.m))
            for i in range(e)]


def join(parts, e, ring):
    return tuple(parts[i % e][(i//e)*ring.m+v] for i in range(ring.L) for v in range(ring.m))


def embed(a, i, e, ring):
    out = [0]*ring.n
    for j in range(ring.L//e):
        for v in range(ring.m):
            out[(e*j+i)*ring.m+v] = a[j*ring.m+v]
    return tuple(out)


def digits(a, q, width, g):
    base = 1 << width
    result = [[] for _ in range(g)]
    for value in a:
        z = value if value <= q//2 else value-q
        for j in range(g):
            digit = (z+base//2) % base-base//2
            result[j].append(digit % q)
            z = (z-digit)//base
        assert z == 0
    return [tuple(row) for row in result]


def hasse(a, r, ring):
    out = [0]*ring.n
    for i in range(ring.L):
        if i & r:
            out[(i-r)*ring.m:(i-r+1)*ring.m] = a[i*ring.m:(i+1)*ring.m]
    return tuple(out)


def madd(A, B, ring, sign=1):
    return [[ring.add(a, b, sign) for a, b in zip(ar, br)] for ar, br in zip(A, B)]


def square(A, B, ring):
    n = len(A)
    if n == 1:
        return [[ring.mul(A[0][0], B[0][0])]]
    h = n//2
    def quarters(M):
        return ([row[:h] for row in M[:h]], [row[h:] for row in M[:h]],
                [row[:h] for row in M[h:]], [row[h:] for row in M[h:]])
    a,b,c,d = quarters(A)
    f,g,h0,i = quarters(B)
    add = lambda x,y: madd(x,y,ring)
    sub = lambda x,y: madd(x,y,ring,-1)
    p1 = square(add(a,d), add(f,i), ring)
    p2 = square(add(c,d), f, ring)
    p3 = square(a, sub(g,i), ring)
    p4 = square(d, sub(h0,f), ring)
    p5 = square(add(a,b), i, ring)
    p6 = square(sub(c,a), add(f,g), ring)
    p7 = square(sub(b,d), add(h0,i), ring)
    c11 = add(sub(add(p1,p4),p5),p7)
    c12 = add(p3,p5)
    c21 = add(p2,p4)
    c22 = add(add(sub(p1,p2),p3),p6)
    return [x+y for x,y in zip(c11,c12)] + [x+y for x,y in zip(c21,c22)]


def joint(states, keys, e, width, g, ring):
    small = Ring(ring.L//e, ring.p, ring.q)
    B = len(states)
    A = [[None]*(e*g) for _ in range(2*e)]
    for i in range(e):
        for j in range(g):
            for v in range(2):
                for u, part in enumerate(split(keys[i][j][v], e, ring)):
                    A[v*e+u][i*g+j] = part
    D = [[small.zero]*B for _ in range(e*g)]
    shared = []
    for z, state in enumerate(states):
        grouped = [digits(a,ring.q,width,g) for a in split(state[1],e,ring)]
        full = [join([grouped[i][j] for i in range(e)],e,ring) for j in range(g)]
        assert full == digits(state[1],ring.q,width,g)
        shared.append(full)
        for i in range(e):
            for j in range(g):
                D[i*g+j][z] = grouped[i][j]
    padded = ((B+e-1)//e)*e
    C = [[small.zero]*padded for _ in range(2*e)]
    for start in range(0,padded,e):
        for br in range(2):
            acc = [[small.zero]*e for _ in range(e)]
            for bc in range(g):
                left = [row[bc*e:(bc+1)*e] for row in A[br*e:(br+1)*e]]
                right = [[row[z] if z<B else small.zero for z in range(start,start+e)]
                         for row in D[bc*e:(bc+1)*e]]
                acc = madd(acc,square(left,right,small),small)
            for u in range(e):
                C[br*e+u][start:start+e] = acc[u]
    s = e.bit_length()-1
    mults = 2*g*((B+e-1)//e)*7**s
    adds = 2*g*((B+e-1)//e)*(6*(7**s-e*e)+e*e)
    assert small.multiplies == mults and small.additions == adds
    outputs=[]
    for z,state in enumerate(states):
        out = [join([C[v*e+u][z] for u in range(e)],e,ring) for v in range(2)]
        out[0] = ring.add(out[0],hasse(state[0],e//2,ring))
        outputs.append(out)
    return outputs, shared, dict(multiplies=mults, additions=adds, padded_batches=padded)


def external(d, bank, ring):
    return [sum_polys([ring.oracle(x,row[v]) for x,row in zip(d,bank)],ring) for v in range(2)]


def sum_polys(values, ring):
    return tuple(sum(v[i] for v in values) % ring.q for i in range(ring.n))


def direct(state, keys, e, width, g, ring):
    # Direct oracle never uses compact multiplication or Strassen.
    c1parts = split(state[1],e,ring)
    terms = [[],[]]
    for i in range(e):
        embedded = embed(c1parts[i],0,e,ring)
        d = digits(embedded,ring.q,width,g)
        value = external(d,keys[i],ring)
        for v in range(2):
            terms[v].append(value[v])
    return [ring.add(sum_polys(terms[0],ring),hasse(state[0],e//2,ring)),
            sum_polys(terms[1],ring)]


def raw(a,b,ring):
    return [ring.oracle(a[0],b[0]),
            ring.add(ring.oracle(a[0],b[1]),ring.oracle(a[1],b[0])),
            ring.oracle(a[1],b[1])]


def rekey(raw_value, banks, width, g, ring):
    outs = [external(digits(raw_value[i+1],ring.q,width,g),banks[i],ring) for i in range(2)]
    return [sum_polys([raw_value[0],outs[0][0],outs[1][0]],ring),ring.add(outs[0][1],outs[1][1])]


def algebra_cases():
    configurations = [(q,e,L,p,B,w) for q in (2,9,15,17)
                      for e,L,p,B,w in ((2,4,3,1,1),(4,8,5,3,2),(8,16,3,9,2))]
    configurations += [(17,8,8,5,8,3),(9,2,2,257,3,2)]
    records=[]
    checked=0
    for index,(q,e,L,p,B,width) in enumerate(configurations):
        ring=Ring(L,p,q)
        rng=Random(963141+index)
        g=(q.bit_length()+width-1)//width+1
        sample=lambda: fixture(ring,rng,p==257)
        states=[[sample(),sample()] for _ in range(B)]
        keys=[[[sample(),sample()] for _ in range(g)] for _ in range(e)]
        for _ in range(3):
            a,b=sample(),sample()
            assert ring.mul(a,b)==ring.oracle(a,b)
            assert join(split(a,e,ring),e,ring)==a
        # A wrap-boundary witness tests S-linearity, including the negative sign.
        a=[0]*ring.n; a[(L-e)*ring.m]=1
        b=sample()
        assert hasse(ring.oracle(a,b),e//2,ring)==ring.oracle(a,hasse(b,e//2,ring))
        output,shared,count=joint(states,keys,e,width,g,ring)
        expected=[direct(c,keys,e,width,g,ring) for c in states]
        assert output==expected
        checked += 2*B*ring.n
        records.append(dict(q=q,e=e,L=L,p=p,batches=B,radix_bits=width,gadget=g,
                            sparse=p==257,coefficients_compared=2*B*ring.n,**count))
    return records,checked


def trace_cases():
    results=[]
    for q,L,p,k,B in ((9,8,3,1,3),(17,16,3,2,5)):
        ring=Ring(L,p,q); rng=Random(1711+q)
        width=2; g=(q.bit_length()+1)//2+1
        sample=lambda: fixture(ring,rng)
        bank=lambda: [[sample(),sample()] for _ in range(g)]
        pair=lambda: [sample(),sample()]
        tau=L.bit_length()-1-k
        # Prefix aggregation, two-bank rekey, and every subsequent retained state.
        states=[]
        prefix_banks=[bank(),bank()]
        for _ in range(B):
            a=pair(); acc=[a[0],a[1],ring.zero]
            for _ in range((1<<k)-1):
                prod=raw(pair(),pair(),ring)
                acc=[ring.add(x,y) for x,y in zip(acc,prod)]
            states.append(rekey(acc,prefix_banks,width,g,ring))
        equal_states=B
        equal_coefficients=2*B*ring.n
        for j in reversed(range(tau)):
            e=2*(1<<j)
            keys=[bank() for _ in range(e)]
            align_bank=bank(); product_banks=[bank(),bank()]
            following=[]
            transported,shared,_=joint(states,keys,e,width,g,ring)
            for z,state in enumerate(states):
                direct_h=direct(state,keys,e,width,g,ring)
                assert direct_h==transported[z]
                factor=pair()
                left_raw=raw(direct_h,factor,ring)
                right_raw=raw(transported[z],factor,ring)
                left_rekey=rekey(left_raw,product_banks,width,g,ring)
                right_rekey=rekey(right_raw,product_banks,width,g,ring)
                left_align=external(digits(state[1],q,width,g),align_bank,ring)
                right_align=external(shared[z],align_bank,ring)
                left_align[0]=ring.add(left_align[0],state[0])
                right_align[0]=ring.add(right_align[0],state[0])
                left_out=[ring.add(x,y) for x,y in zip(left_rekey,left_align)]
                right_out=[ring.add(x,y) for x,y in zip(right_rekey,right_align)]
                for left,right in ((left_raw,right_raw),(left_rekey,right_rekey),
                                   (left_align,right_align),(left_out,right_out)):
                    assert left==right
                equal_states+=5
                equal_coefficients+=11*ring.n
                following.append(right_out)
            states=following
        results.append(dict(q=q,L=L,p=p,prefix=k,tail=tau,batches=B,
                            retained_states=equal_states,coefficients_compared=equal_coefficients,
                            fixture_type='PUBLIC_CIPHERTEXT_SHAPED_ARRAYS_NOT_ENCRYPTION'))
    return results


def ledger_cases():
    spec=spec_from_file_location('preserved_reuse',READY/'prefix-reuse-audit-v1/check_reuse.py')
    reuse=module_from_spec(spec); spec.loader.exec_module(reuse)
    old=reuse.load_module()
    records=[]
    for lam in (256,257,512,1024,4096,65536):
        d=(lam-1).bit_length(); L=1<<d
        for k in range(1,d+1):
            synth=old.synthesize(lam,k,4)
            row=reuse.recount(lam,k,4,synth['modulus_bits']-1,synth['gadget'])
            assert row['admission']=='ALL_PRIMES_IN_INTERVAL_ADMITTED'
            tau=d-k; E=1<<tau; g=row['gadget']; M=(1<<k)-1; H=row['hint_rows']
            for B in sorted(set((1,max(1,E-1),E,E+1,2*E,L))):
                ranks=[1<<j for j in range(1,tau+1)]
                assert sum(ranks)==2*E-2
                other=H+2*tau+2+B*(7*M+5*tau+3+2*g*(2+3*tau))
                original=row['ring_products_setup']+B*row['ring_products_warm']
                removed=B*sum(2*e*g for e in ranks)
                assert other+removed==original
                matrix=[]
                for e in ranks:
                    s=e.bit_length()-1; blocks=2*g*((B+e-1)//e)
                    matrix.append(dict(e=e,base_dimension=row['dimension']//e,
                                       scalar_multiplies=blocks*7**s,
                                       scalar_additions=blocks*(6*(7**s-e*e)+e*e)))
                horizon=reuse.horizon(row,B)
                records.append(dict(parameter=lam,L=L,prefix=k,tail=tau,batches=B,
                                    threshold_met=B>=E,gadget=g,modulus_bits=row['modulus_bits'],
                                    full_ring_products_remaining=other,
                                    full_ring_products_removed=removed,matrix=matrix,
                                    source_rows=row['source_rows'],source_gap_factor=horizon['source_gap_factor'],
                                    failure_budget_strict_upper_exponent=horizon['failure_budget_strict_upper_exponent']))
    return records


def main():
    assert __debug__
    before=sources()
    algebra,coeffs=algebra_cases()
    traces=trace_cases()
    ledgers=ledger_cases()
    omega=log2(7); alpha=omega-2
    report=dict(status='PUBLIC_ALGEBRA_AND_LEDGER_CHECKS_PASS',new_he_execution=False,
                performance_benchmark=False,proof_verified_by_program=False,
                security_bits_assigned=False,source_bindings=before,
                algebra_cases=algebra,algebra_coefficients_compared=coeffs,
                trace_cases=traces,ledger_cases=ledgers,
                exponents=dict(omega=omega,alpha=alpha,prefix=alpha/(1+alpha),
                               batch_threshold=1/(1+alpha),per_batch=2-1/(omega-1)))
    assert before==sources()
    (HERE/'audit.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(status=report['status'],source_files=len(before),algebra_cases=len(algebra),
                          algebra_coefficients=coeffs,trace_cases=len(traces),
                          trace_states=sum(x['retained_states'] for x in traces),
                          trace_coefficients=sum(x['coefficients_compared'] for x in traces),
                          ledger_cases=len(ledgers),exponents=report['exponents']),indent=2))


if __name__=='__main__':
    main()
