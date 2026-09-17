"""Exact clear-function checks for prepared contraction; no cryptographic coins or HE."""
from hashlib import sha256
from itertools import product
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
READY, ROOT = HERE.parent, HERE.parents[3]


def bindings():
    paths = [HERE/x for x in ('PLAN.md','PROOF.md','RESULTS.md','REPRODUCE.md','check_contraction.py')]
    paths += [READY/'manuscript/sections/preliminaries.tex',
              READY/'manuscript/sections/resources.tex',
              READY/'manuscript/appendices/recovery-interface.tex',
              READY/'manuscript/appendices/prepared-contraction-bounds.tex']
    return {p.relative_to(ROOT).as_posix(): dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
            for p in paths}


def add_term(support, term):
    if term in support:
        support.remove(term)
    else:
        support.add(term)


def symbolic_powers(L):
    """Independent repeated truncated multiplication by sum X_v z^v."""
    previous = [{(0,)*(L-1)}]+[set() for _ in range(L-1)]
    result = {}
    for i in range(1,L):
        current = [set() for _ in range(L)]
        for j,support in enumerate(previous):
            for v in range(1,L-j):
                for monomial in support:
                    exponents = list(monomial)
                    exponents[v-1] += 1
                    add_term(current[j+v],tuple(exponents))
        for j,support in enumerate(current):
            if support:
                result[i,j] = support
        previous = current
    return result


def frob_exp(exponent, t, q):
    return 0 if exponent==0 else 1+((exponent*(1 << t)-1) % (q-1))


def frob_support(support,t,q):
    result = set()
    for monomial in support:
        add_term(result,tuple(frob_exp(e,t,q) for e in monomial))
    return result


def marker(u,j,L,t,q):
    exponents = [0]*(L-1)
    if j==u:
        exponents[0] = u
    else:
        exponents[0] = u-1
        exponents[j-u] = 1
    return tuple(frob_exp(e,t,q) for e in exponents)


def small_symbolic():
    records = []
    for L,s in ((2,2),(4,4),(8,6),(16,8)):
        q, rows = 1 << s, symbolic_powers(L)
        expected = {(i,j) for i in range(1,L) for j in range(i,L) if j % (i & -i)==0}
        assert set(rows)==expected and len(rows)==(L*L-1)//3
        monomials = set()
        for (i,j),support in rows.items():
            assert all(sum(x)==i and sum((v+1)*e for v,e in enumerate(x))==j for x in support)
            assert not (monomials & support)
            monomials.update(support)
        labels = [(u,j,t) for u in range(1,L,2) for j in range(u,L) for t in range(s)]
        marks = {marker(u,j,L,t,q):(u,j,t) for u,j,t in labels}
        assert len(marks)==len(labels)==s*L*L//4
        occurrences = 0
        for u,j,t in labels:
            support = frob_support(rows[u,j],t,q)
            marked = [marks[x] for x in support if x in marks]
            assert marked == [(u,j,t)]
            occurrences += 1
        records.append(dict(L=L,q=q,nonzero_coefficients=len(rows),
                            expanded_monomials=len(monomials),frobenius_unit_minor=occurrences))
    return records


class Field:
    def __init__(self,s,polynomial):
        self.s,self.q,self.polynomial = s,1 << s,polynomial
    def mul(self,a,b):
        out = 0
        while b:
            if b & 1:
                out ^= a
            b >>= 1
            a <<= 1
            if a & self.q:
                a ^= self.polynomial
        return out
    def power(self,a,n):
        result = 1
        while n:
            if n & 1:
                result = self.mul(result,a)
            a = self.mul(a,a)
            n >>= 1
        return result
    def inverse(self,a):
        assert a
        out = self.power(a,self.q-2)
        assert self.mul(a,out)==1
        return out


def rank(rows,field):
    basis = {}
    for original in rows:
        row = list(original)
        for col in range(len(row)):
            if not row[col]:
                continue
            if col in basis:
                factor = row[col]
                row = [x ^ field.mul(factor,y) for x,y in zip(row,basis[col])]
            else:
                inverse = field.inverse(row[col])
                basis[col] = [field.mul(inverse,x) for x in row]
                break
    return len(basis)


def evaluate(support,point,field):
    value = 0
    for monomial in support:
        term = 1
        for x,e in zip(point,monomial):
            term = field.mul(term,field.power(x,e))
        value ^= term
    return value


def function_ranks():
    records = []
    for s,poly,L in ((1,3,4),(2,7,4),(4,19,4),(2,7,2)):
        field = Field(s,poly)
        assert all(field.mul(x,field.inverse(x))==1 for x in range(1,field.q))
        powers = symbolic_powers(L)
        points = list(product(range(field.q),repeat=L-1))
        values = {key:[evaluate(support,point,field) for point in points] for key,support in powers.items()}
        base_rank = rank(list(values.values()),field)
        closed = [[field.power(v,1 << t) for v in row]
                  for (i,j),row in values.items() if i & 1 for t in range(s)]
        closed_rank = rank(closed,field)
        expected_base,expected_closed = (L*L-1)//3,s*L*L//4
        if field.q>=L:
            assert base_rank==expected_base
        else:
            assert base_rank < expected_base
        if field.q>=L*L:
            assert closed_rank==expected_closed
        else:
            assert closed_rank < expected_closed
        records.append(dict(q=field.q,L=L,all_inner_inputs=len(points),coefficient_function_rank=base_rank,
                            formal_nonzero_count=expected_base,frobenius_function_rank=closed_rank,
                            large_field_frobenius_formula=expected_closed))
    return records


def production_markers():
    """For every marker, test every possible inverse-Frobenius source polynomial."""
    L,q,s = 256,65536,16
    rows,preimages = 0,0
    digest = sha256()
    for u in range(1,L,2):
        for j in range(u,L):
            for t in range(s):
                indices = [(1,frob_exp(u,t,q))] if j==u else [
                    (v,frob_exp(e,t,q)) for v,e in ((1,u-1),(j-u+1,1)) if e]
                matches = []
                for undo in range(s):
                    source = [(v,frob_exp(e,(-undo) % s,q)) for v,e in indices]
                    degree = sum(e for _,e in source)
                    weight = sum(v*e for v,e in source)
                    preimages += 1
                    if not (degree & 1 and degree<=weight<L):
                        continue
                    # Multinomial coefficient is odd exactly when exponent bits are disjoint.
                    bits = 0
                    for _,e in source:
                        if bits & e:
                            break
                        bits |= e
                    else:
                        matches.append((degree,weight,undo))
                assert matches==[(u,j,t)]
                digest.update(bytes((u,j,t)))
                rows += 1
    assert rows==262144 and preimages==4194304
    return dict(L=L,q=q,scalar_coefficient_functions=(L*L-1)//3,
                frobenius_unit_minor_rows=rows,inverse_frobenius_occurrence_checks=preimages,
                ordered_row_labels_sha256=digest.hexdigest(),
                full_symbolic_polynomials_expanded=False,
                scope='Every selected marker has coefficient one in exactly its own Frobenius-polynomial row; finite corroboration of the general proof.')


def convolution(a,b,field,L):
    result = [0]*L
    for i,x in enumerate(a):
        for j,y in enumerate(b[:L-i]):
            result[i+j] ^= field.mul(x,y)
    return result


def numeric_powers(g,field):
    L = len(g)
    result = [[1]+[0]*(L-1)]
    for i in range(1,L):
        result.append(convolution(result[-1],g,field,L))
    return result


def horner(f,g,field):
    out = [0]*len(g)
    for coefficient in reversed(f):
        out = convolution(out,g,field,len(g))
        out[0] ^= coefficient
    return out


def paired(f,powers,field,omit=None):
    L = len(f)
    out,products = [f[0]]+[0]*(L-1),0
    for j in range(1,L):
        indices = [i for i in range(1,j+1) if j % (i & -i)==0]
        for start in range(0,len(indices),2):
            i = indices[start]
            if start+1==len(indices):
                out[j] ^= field.mul(f[i],powers[i][j])
            else:
                k = indices[start+1]
                x,y = powers[i][j],powers[k][j]
                out[j] ^= field.mul(f[i] ^ y,f[k] ^ x)
                if omit!='outer':
                    out[j] ^= field.mul(f[i],f[k])
                if omit!='inner':
                    out[j] ^= field.mul(x,y)
            products += 1
    return out,products


def clear_execution():
    field,L = Field(4,19),4
    choices = [[0]*L]+[[int(i==j) for i in range(L)] for j in range(L)]+[[1]*L]
    cases,coefficients,outer_failures,inner_failures = 0,0,0,0
    for point in product(range(field.q),repeat=L-1):
        g = [0]+list(point)
        powers = numeric_powers(g,field)
        for f in choices:
            expected = horner(f,g,field)
            result,count = paired(f,powers,field)
            assert result==expected and count==3
            outer_failures += paired(f,powers,field,'outer')[0]!=expected
            inner_failures += paired(f,powers,field,'inner')[0]!=expected
            cases += 1
            coefficients += L
    assert outer_failures and inner_failures
    dense = []
    for L,field in ((8,Field(6,67)),(16,Field(8,283))):
        for seed in range(16):
            f = [(7*i*i+13*seed+3*i*seed+1) % field.q for i in range(L)]
            g = [0]+[(11*i*i*i+5*seed+7*i*seed+3) % field.q for i in range(1,L)]
            powers = numeric_powers(g,field)
            result,count = paired(f,powers,field)
            assert result==horner(f,g,field)
            assert count==(2*L*L+3*L-8)//12
            dense.append(dict(L=L,q=field.q,fixture=seed,products=count))
    return dict(all_inner_GF16_inputs=4096,declared_outer_inputs=len(choices),
                GF16_full_compositions=cases,GF16_output_coefficients=coefficients,
                missing_outer_correction_failures=outer_failures,
                missing_inner_correction_failures=inner_failures,dense_cases=dense,
                scope='All GF16 inner inputs with six declared outer fixtures; not all outer inputs. Thirty-two additional deterministic dense cases.')


def ledger():
    profiles = []
    for L in (2,4,8,16,32,64,128,256,512,1024):
        t = [sum(j % (i & -i)==0 for i in range(1,j+1)) for j in range(1,L)]
        assert t==[j-((j//(j & -j))-1)//2 for j in range(1,L)]
        D,P = sum(t),sum((n+1)//2 for n in t)
        assert D==(L*L-1)//3
        if L>=4:
            assert sum(n & 1 for n in t)==L//2-1
            assert P==(2*L*L+3*L-8)//12
        else:
            assert P==1
        profiles.append(dict(L=L,D=D,P=P))
    h,S,L = 16,2048,256
    D,P = (L*L-1)//3,(2*L*L+3*L-8)//12
    ceil = lambda a,b:(a+b-1)//b
    C,B = ceil(h*P,S),ceil(h*L,S)
    selected = dict(h=h,L=L,q=65536,S=S,D=D,P=P,
                    field_linear_separated_minimum=ceil(h*D,S),
                    field_linear_mixed_lower=ceil(h*D,2*S),paired_upper=C,
                    binary_linear_separated_lower=ceil(h*L*L,4*S),
                    binary_linear_mixed_lower=ceil(h*L*L,8*S),
                    inputs=4*C+2*B,raw_three_component_products=C,
                    two_component_bypass_outputs=2*B,mixed_operand_additions=2*C,
                    public_key_polynomials=2,input_polynomials=2*(4*C+2*B),
                    output_polynomials=3*C+4*B,evaluation_key_polynomials=0)
    assert (selected['field_linear_separated_minimum'],selected['field_linear_mixed_lower'],
            selected['paired_upper'],selected['binary_linear_separated_lower'],
            selected['binary_linear_mixed_lower'])==(171,86,86,128,64)
    assert (selected['inputs'],selected['output_polynomials'])==(348,266)
    return dict(profiles=profiles,selected=selected,
                nonlinear_call_counts_only=True,modulus_admitted=False,concrete_security_qualified=False)


def main():
    before = bindings()
    result = dict(status='PREPARED_CONTRACTION_FUNCTION_AND_MODEL_CHECKS_PASS',
                  small_symbolic=small_symbolic(),finite_function_ranks=function_ranks(),
                  production=production_markers(),clear_execution=clear_execution(),ledger=ledger(),
                  new_he_execution=False,cryptographic_source_vectors_sampled=0,
                  performance_comparison=False,all_HE_lower_bound=False,security_bits=None,
                  formal_proof_checked=False,bindings_before=before,bindings_after=bindings())
    assert before==result['bindings_after']
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('status','small_symbolic','finite_function_ranks','production','ledger',
                                          'new_he_execution','performance_comparison','security_bits')},indent=2))


if __name__=='__main__':
    main()
