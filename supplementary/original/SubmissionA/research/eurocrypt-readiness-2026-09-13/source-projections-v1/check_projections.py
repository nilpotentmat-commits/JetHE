"""Exact CBD20 small-CRT-projection certificates; no cryptographic execution.

Integer/rational checks and public finite fixtures support the separate proof.
They do not establish whole-transcript hardness or a security level.
"""
import ast
from collections import Counter
from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
from math import comb, gcd, isqrt, prod
from pathlib import Path
from random import Random
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parents[1]
ROOT = RESEARCH.parents[1]
N, J, ETA = 256, 256, 20


def bind(p):
    return dict(bytes=p.stat().st_size, sha256=sha256(p.read_bytes()).hexdigest())


def literal(path, name):
    nodes = ast.parse(path.read_text(encoding='utf-8')).body
    hits = [n.value for n in nodes if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
    assert len(hits)==1
    return ast.literal_eval(hits[0])


def primitive_generator(p):
    assert p>2 and all(p%d for d in range(2,isqrt(p)+1))
    factors = [d for d in range(2,p) if (p-1)%d==0 and all(d%x for x in range(2,isqrt(d)+1))]
    return next(g for g in range(2,p) if all(pow(g,(p-1)//d,p)!=1 for d in factors))


def certified_profiles():
    path = RESEARCH/'check_composition_rns_arithmetic.py'
    certificates = literal(path,'CERTIFICATES')[:3]
    result = []
    for p,g,factors in certificates:
        assert prod(d**e for d,e in factors)==p-1
        assert all(all(d%x for x in range(2,isqrt(d)+1)) for d,e in factors)
        assert pow(g,p-1,p)==1
        assert all(gcd(pow(g,(p-1)//d,p)-1,p)==1 for d,e in factors)
        assert p.bit_length()==60 and (p-1)%(512*257)==0
        alpha,beta = pow(g,(p-1)//512,p),pow(g,(p-1)//257,p)
        assert pow(alpha,256,p)==p-1 and pow(beta,257,p)==1 and beta!=1
        result.append(dict(prime=p,generator=g,t_root=alpha,b_root=beta))
    scope = json.loads((HERE.parent/'source-scope.json').read_text())
    assert scope['source_modulus_bits']==180 and scope['source_rows']==46
    assert int(scope['source_modulus_decimal'])==prod(v['prime'] for v in result)
    assert sum(scope['incoming_rows'].values())==139
    for name,want in scope['source_hashes'].items():
        assert sha256((ROOT/name).read_bytes()).hexdigest()==want, name
    return result


def root_lower(q,k,precision=64):
    """Floor 2^precision * q^(-k/128), certified by integer powers."""
    target = 1 << (128*precision)
    qk = q**k
    lo,hi = 0,1 << precision
    while hi-lo>1:
        mid = (lo+hi)//2
        if mid**128*qk <= target:
            lo = mid
        else:
            hi = mid
    assert lo**128*qk <= target < (lo+1)**128*qk
    return Fraction(lo,1 << precision)


def quantitative(primes):
    # Strict elementary constants: pi>3.14 and ln(2)<347/500.
    # Machin's identity and alternating arctangent series certify the former.
    atan = lambda d,terms:sum((Fraction((-1)**i,(2*i+1)*d**(2*i+1)) for i in range(terms)),Fraction(0))
    pi_lower = 16*atan(5,20)-4*atan(239,3)
    assert pi_lower > Fraction(157,50)
    # The second follows from exp(347/500)>2, already at Taylor degree ten.
    x = Fraction(347,500)
    total,term = Fraction(1),Fraction(1)
    for j in range(1,11):
        term *= x/j
        total += term
    assert total>2
    coefficient = ETA*Fraction(157,50)**2/x
    rows = []
    for channels in (1,2,3):
        q = prod(primes[:channels])
        bits = q.bit_length()
        for k in range(1,13):
            lower = root_lower(q,k)
            nonzero = J//k
            # Alphabet <= q^k < 2^(bits*k), TV <= sqrt(alphabet)/2 * bias.
            bias_bits = coefficient*nonzero*lower
            tv_bits = bias_bits-Fraction(bits*k,2)+1
            integer_bits = tv_bits.numerator//tv_bits.denominator
            # Also certify a bound using only q < 2^bits (no decimal log).
            dyadic = coefficient*nonzero*root_lower(1 << bits,k)-Fraction(bits*k,2)+1
            rows.append(dict(channels=channels,modulus=str(q),modulus_bits=bits,
                positions_per_prime=k,nonzero_columns_minimum=nonzero,
                energy_lower=dict(numerator=str(lower.numerator*nonzero),denominator=str(lower.denominator)),
                strict_tv_bits=integer_bits,strict_dyadic_tv_bits=dyadic.numerator//dyadic.denominator,
                certified_bound_nonvacuous=integer_bits>0,
                rational_tv_exponent=dict(numerator=str(tv_bits.numerator),denominator=str(tv_bits.denominator))))
    selected = next(r for r in rows if r['channels']==3 and r['positions_per_prime']==3)
    assert selected['strict_dyadic_tv_bits']>=1028
    adverse = next(r for r in rows if r['channels']==3 and r['positions_per_prime']==4)
    assert 0 < adverse['strict_dyadic_tv_bits'] < 128
    assert 139 < 2**8
    return dict(profiles=rows,pi_lower_numerator=str(pi_lower.numerator),pi_lower_denominator=str(pi_lower.denominator),
                ln2_upper_taylor_numerator=str(total.numerator),
                ln2_upper_taylor_denominator=str(total.denominator),
                three_positions_per_prime_tv_bits=1028,
                forty_six_restricted_rows_tv_bits=1022,
                one_hundred_thirty_nine_restricted_setup_rows_tv_bits=1020,
                bound_scope='Three chosen CRT positions at each prime jointly, selected before observing that row body. Full masks and earlier restricted bodies may be used. No other body information or repeated extra probes.')


def bareiss(matrix):
    a = [row[:] for row in matrix]
    previous,sign = 1,1
    n = len(a)
    for k in range(n-1):
        if a[k][k]==0:
            pivot = next((i for i in range(k+1,n) if a[i][k]),None)
            if pivot is None:
                return 0
            a[k],a[pivot] = a[pivot],a[k]
            sign = -sign
        pivot = a[k][k]
        for i in range(k+1,n):
            for j in range(k+1,n):
                numerator = pivot*a[i][j]-a[i][k]*a[k][j]
                assert numerator%previous==0
                a[i][j] = numerator//previous
        for i in range(k+1,n):
            a[i][k] = 0
        previous = pivot
    return sign*a[-1][-1]


def norm_inverse_basis(v):
    n = len(v)
    # f = sum v_i t^(-i), using t^n=-1.
    f = [v[0]]+[-v[n-i] for i in range(1,n)]
    matrix = [[0]*n for _ in range(n)]
    for j in range(n):
        for i,c in enumerate(f):
            position = i+j
            matrix[position%n][j] += c*(-1 if position>=n else 1)
    return abs(bareiss(matrix))


def ntt(values,omega,p):
    n = len(values)
    a = values[:]
    j = 0
    for i in range(1,n):
        bit = n>>1
        while j&bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i<j:
            a[i],a[j] = a[j],a[i]
    size = 2
    while size<=n:
        step = pow(omega,n//size,p)
        for base in range(0,n,size):
            w = 1
            for j in range(size//2):
                u,v = a[base+j],a[base+j+size//2]*w%p
                a[base+j],a[base+j+size//2] = (u+v)%p,(u-v)%p
                w = w*step%p
        size *= 2
    return a


def check_frequency(n,odd,params,positions,coefficients,exact_norm):
    primes = [v['prime'] for v in params]
    q,k = prod(primes),max(map(len,positions))
    assert k>=1 and any(any(c) for c in coefficients)
    aps,bps = [],[]
    for prm,pos in zip(params,positions):
        p,a,b = (prm[x] for x in ('prime','t_root','b_root'))
        assert len(set(pos))==len(pos)
        aps.append([[pow(a,(2*h+1)*i,p) for i in range(n)] for h,j in pos])
        bps.append([[pow(b,j*s,p) for s in range(odd)] for h,j in pos])
    nonzero, norm_checks, spectra, energy_numerator = [],0,0,0
    for column in range(1,odd):
        v = []
        for i in range(n):
            x = sum((q//p)*sum(c*aa[i]*bb[column] for c,aa,bb in zip(cs,ap,bp))
                    for p,cs,ap,bp in zip(primes,coefficients,aps,bps))%q
            v.append(x-q if x>q//2 else x)
        nz = any(v)
        nonzero.append(nz)
        energy_numerator += sum(x*x for x in v)
        for prm,pos,cs,bp in zip(params,positions,coefficients,bps):
            p,a = prm['prime'],prm['t_root']
            inv = pow(a,-1,p)
            values = [v[i]*pow(inv,i,p)%p for i in range(n)]
            actual = ntt(values,inv*inv%p,p)
            expected = [0]*n
            for (h,j),c,bb in zip(pos,cs,bp):
                expected[h] = (expected[h]+n*(q//p)*c*bb[column])%p
            assert actual==expected
            if n<=8:
                direct = [sum(v[i]*pow(a,-(2*h+1)*i,p) for i in range(n))%p for h in range(n)]
                assert actual==direct
            spectra += n
        if nz and exact_norm:
            norm = norm_inverse_basis(v)
            assert norm>0 and norm%(q**max(0,n-k))==0
            assert sum(x*x for x in v)**n >= norm*norm
            assert sum(x*x for x in v)**n >= q**(2*max(0,n-k))
            norm_checks += 1
    assert sum(nonzero)>=(odd-1)//k
    assert all(any(nonzero[j:j+k]) for j in range(odd-k))
    # Check the total energy lower bound without irrational arithmetic.
    count = (odd-1)//k
    if k<=n:
        assert energy_numerator**n >= count**n*q**(2*(n-k))
    return dict(norm_checks=norm_checks,spectral_entries=spectra,
                nonzero_columns=sum(nonzero),energy_numerator=str(energy_numerator),denominator=str(q*q))


def fixtures(profiles):
    rng = Random(0xCBD20260913)  # Public deterministic fixtures, never crypto coins.
    records = []
    for n,odd,primes in ((2,3,[13]),(2,3,[13,37]),(4,3,[73]),(4,5,[41,241]),(8,3,[97,193])):
        params = [dict(prime=p,t_root=pow(primitive_generator(p),(p-1)//(2*n),p),
                       b_root=pow(primitive_generator(p),(p-1)//odd,p)) for p in primes]
        q = prod(primes)
        # Exhaust all single-character coefficient tuples for the smallest rings.
        if n==2:
            positions = [[(0,1)] for p in primes]
            for cs in product(*(range(p) for p in primes)):
                if not any(cs):
                    continue
                result = check_frequency(n,odd,params,positions,[[c] for c in cs],True)
                records.append(dict(kind='exhaustive_single',n=n,odd=odd,**result))
        for k in range(1,min(3,n)+1):
            for case in range(12):
                positions = [rng.sample(list(product(range(n),range(1,odd))),k) for p in primes]
                cs = [[rng.randrange(p) for _ in range(k)] for p in primes]
                if not any(any(c) for c in cs):
                    cs[0][0]=1
                result = check_frequency(n,odd,params,positions,cs,True)
                records.append(dict(kind='small_multi',n=n,odd=odd,k=k,**result))
    production = []
    for channels in (1,2,3):
        params = profiles[:channels]
        for k in (1,2,3,4):
            for shape in ('shared_t','distinct_t','last_prime_only'):
                positions = [[(0 if shape=='shared_t' else h,h+1) for h in range(k)] for p in params]
                cs = [[(j+1)*(i+1) for j in range(k)] for i in range(channels)]
                if shape=='last_prime_only':
                    cs = [[0]*k for i in range(channels-1)]+[cs[-1]]
                if shape=='shared_t' and k==3:
                    # Force two consecutive zero columns with a nonzero Vandermonde kernel.
                    for i,prm in enumerate(params):
                        p,b = prm['prime'],prm['b_root']
                        x,y,z = [pow(b,j,p) for j in (1,2,3)]
                        cs[i] = [(y*z*z-z*y*y)%p,(z*x*x-x*z*z)%p,(x*y*y-y*x*x)%p]
                        assert all(cs[i])
                result = check_frequency(256,257,params,positions,cs,False)
                production.append(dict(channels=channels,k=k,shape=shape,**result))
                print(json.dumps(dict(stage='production_frequency',channels=channels,k=k,shape=shape)),flush=True)
    return dict(small_fixtures=len(records),small_integer_norms=sum(r['norm_checks'] for r in records),
                small_spectral_entries=sum(r['spectral_entries'] for r in records),
                production_fixtures=production,
                production_spectral_entries=sum(r['spectral_entries'] for r in production),
                small_fixture_digest=sha256(json.dumps(records,sort_keys=True).encode()).hexdigest())


def cbd():
    pmf = {x:Fraction(comb(40,x+20),2**40) for x in range(-20,21)}
    direct = Counter()
    for a in range(21):
        for b in range(21):
            direct[a-b] += comb(20,a)*comb(20,b)
    assert all(pmf[x]==Fraction(direct[x],2**40) for x in pmf)
    assert sum(pmf.values())==1 and sum(x*x*p for x,p in pmf.items())==10
    # Exact characteristic polynomial: z^20 * E[z^X] = (1+z)^40 / 2^40.
    assert [direct[x] for x in range(-20,21)]==[comb(40,j) for j in range(41)]
    return dict(coefficient_masses=41,independent_bit_difference_pairs=441,
                characteristic_polynomial_coefficients=41,variance=10)


def exact_small_distributions():
    # Rank-four cyclotomic tensor, conductor 12, at split prime 13.
    # Direct integer convolution independently checks the projection conclusion.
    p,n,odd = 13,2,3
    g = primitive_generator(p)
    alpha,beta = pow(g,(p-1)//(2*n),p),pow(g,(p-1)//odd,p)
    weights = [comb(40,j) for j in range(41)]
    one = [sum(weights[j] for j in range(41) if (j-20)%p==r) for r in range(p)]
    denominator = 2**160
    records = []
    for h,b in product(range(n),range(1,odd)):
        coefficients = [pow(alpha,(2*h+1)*i,p)*pow(beta,b*j,p)%p
                        for i in range(n) for j in range(1,odd)]
        distribution = [1]+[0]*(p-1)
        for c in coefficients:
            after = [0]*p
            for x,a in enumerate(distribution):
                for r,w in enumerate(one):
                    after[(x+c*r)%p] += a*w
            distribution = after
        assert sum(distribution)==denominator
        tv = Fraction(sum(abs(p*v-denominator) for v in distribution),2*p*denominator)
        assert tv < Fraction(1,2**42)
        scaled = [distribution[(r*pow(2,-1,p))%p] for r in range(p)]
        assert sum(abs(p*v-denominator) for v in scaled)==2*p*denominator*tv
        records.append(dict(t_index=h,b_index=b,tv_numerator=str(tv.numerator),tv_denominator=str(tv.denominator)))
    # The full CRT is a bijection; full joint TV equals that of coefficient residues.
    size = p**(n*(odd-1))
    variation = sum(abs(size*prod(v)-denominator) for v in product(one,repeat=4))
    full_tv = Fraction(variation,2*size*denominator)
    assert full_tv > Fraction(1,8)
    return dict(rank=4,prime=13,scalar_projections=records,
                each_scalar_tv_below_2_minus42=True,
                full_vector_tv_numerator=str(full_tv.numerator),full_vector_tv_denominator=str(full_tv.denominator),
                full_vector_tv_greater_than_one_eighth=True,
                adverse_scope='Exact small-ring counterexample to inferring joint uniformity from all scalar marginals; not an attack on the production instance.')


def main():
    profiles = certified_profiles()
    files = [Path(__file__),HERE/'PLAN.md',RESEARCH/'check_composition_rns_arithmetic.py',
             RESEARCH/'composition_native.py',HERE.parent/'source-scope.json',
             RESEARCH/'jethe-throughput-redesign-2026-09-13/slim_ring_base_v2.py',
             RESEARCH/'jethe-throughput-redesign-2026-09-13/backend-v2/composition_native_core.cpp']
    for name in ('PROOF.md','RESULTS.md','REPRODUCE.md'):
        if (HERE/name).exists():
            files.append(HERE/name)
    before = {p.relative_to(ROOT).as_posix():bind(p) for p in files}
    result = dict(status='EXACT_CBD20_RESTRICTED_CRT_PROJECTION_CHECKS_PASS',
                  primes=profiles,source_law=cbd(),quantitative=quantitative([p['prime'] for p in profiles]),
                  exact_distribution_check=exact_small_distributions(),
                  fixtures=fixtures(profiles),
                  scope='Exact-law Fourier/norm argument with public arithmetic fixtures. Restricted projections only; no complete-view hardness, concrete security bits, source sampling or HE run.')
    after = {p.relative_to(ROOT).as_posix():bind(p) for p in files}
    assert before==after
    result.update(bindings_before=before,bindings_after=after)
    (HERE/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(dict(status=result['status'],tv_bits=result['quantitative']['three_positions_per_prime_tv_bits'],
                         norms=result['fixtures']['small_integer_norms'],
                         production_entries=result['fixtures']['production_spectral_entries'])),flush=True)


if __name__=='__main__':
    main()
