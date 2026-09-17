"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

from fractions import Fraction as Q
from math import isqrt, log2

def exact_upper_exponent(value):
    """Largest integer e for which value < 2^-e, without floating arithmetic."""
    assert 0 < value < 1
    exponent = value.denominator.bit_length()-value.numerator.bit_length()
    if value >= Q(1, 1 << exponent):
        exponent -= 1
    assert Q(1, 1 << (exponent+1)) <= value < Q(1, 1 << exponent)
    return exponent


def finite_constants():
    lower = 2*sum((Q(1, (2*j+1)*3**(2*j+1)) for j in range(8)), Q(0))
    upper = lower+Q(2, 17*3**17)/(1-Q(1, 9))
    assert Q(69, 100) < lower < upper < Q(7, 10)
    density = Q(24, 13)-1-Q(12762, 10000)/(12*Q(69, 100))
    assert density > Q(7, 20) > upper/2
    assert 4*upper < 3 and 2*upper < Q(3, 2)
    assert Q(6, 16)+Q(1, 8) == Q(1, 2)
    assert 4*512*256*Q(1, 1 << 512) < Q(1, 8)
    # This last expression decreases at successive integer lambda >= 256.
    assert Q(257, 4*256) < 1
    assert sum(j+1 for j in range(1, 257)) == 33152
    # Guard against confusing an exact power with a strict bound.
    assert exact_upper_exponent(Q(1, 256)) == 7
    assert exact_upper_exponent(Q(3, 1024)) == 8
    return dict(log2_lower=str(lower), log2_upper=str(upper),
                normalized_prime_density_lower_at_b12=str(density),
                prime_interval_minimum_exponent=12,
                general_monotonicity_and_distribution_arguments='PROOF.md',
                pi_lower_used='3', scalar_tail_prefactor_upper='1/2',
                prime_density_source='https://arxiv.org/pdf/1002.0442',
                primality_source='https://annals.math.princeton.edu/2004/160-2/p12')


def budget(row):
    lam, k, w = row['parameter'], row['prepared'], row['radix_bits']
    d = (lam-1).bit_length()
    L, tau = 1 << d, d-k
    N, M = 256*L, (1 << k)-1
    I = 2*M+1+tau
    g, b = row['gadget'], row['modulus_bits']-1
    # Recount vertex, ephemeral and error catalogues independently of their sums.
    H = g*(2*(1 << tau)+3*tau)
    secrets, ephemerals, errors = 2*(tau+1), I, H+tau+1+2*I
    G, U = secrets+ephemerals+errors, H+tau+1
    assert (I,H,G,U) == tuple(row[x] for x in
                              ('inputs','hint_rows','gaussian_polynomials','uniform_polynomials'))
    assert G == H+3*tau+3+3*I
    root = isqrt(lam*d*d)
    W = root+int(root*root != lam*d*d)+1
    J, p = 2*W+1, 8*d*d
    assert (W-2)**2 < lam*d*d <= (W-1)**2
    assert J <= 1 << (d+2)
    assert 4*J < 1 << p  # Down-rounded total remains positive.
    assert N <= 512*lam and N*4*Q(1, 1 << (2*lam)) < Q(1, 8)
    rho_terms = [('normalizers',16*N,2*lam), ('scalar_tails',N,4*d*d),
                 ('weights_and_cdf',5*N*J,8*d*d)]
    rho = sum((Q(n,1 << e) for _,n,e in rho_terms),Q(0))
    def total(scale):
        terms = [('prime_exhaustion',1,scale*d*d),
                 ('uniform_exhaustion',U*N,scale*d*d)]
        terms += [(name,G*n,e) for name,n,e in rho_terms]
        terms += [('ideal_primitive_cap',2*G*N,2*lam)]
        value = sum((Q(n,1 << e) for _,n,e in terms),Q(0))
        return dict(terms=[dict(name=name,coefficient=n,negative_power_of_two=e) for name,n,e in terms],
                    strict_upper_exponent=exact_upper_exponent(value),
                    log2_upper_budget_approx=round(log2(value.numerator)-log2(value.denominator),9)), value
    old, old_value = total(1)
    new, new_value = total(4)
    assert new_value < old_value
    assert new_value == (U*N+1)*Q(1,1 << (4*d*d))+G*rho+2*G*N*Q(1,1 << (2*lam))
    assert old_value-new_value == (U*N+1)*(Q(1,1 << (d*d))-Q(1,1 << (4*d*d)))
    # Worst-case source limits are charged explicitly; stopping is unchanged.
    source_work = dict(old_uniform_attempts_per_coordinate=d*d,
                       new_uniform_attempts_per_coordinate=4*d*d,
                       old_prime_candidate_limit=2*b*d*d,new_prime_candidate_limit=8*b*d*d,
                       maximum_uniform_ideal_bits=4*U*N*row['modulus_bits']*d*d,
                       gaussian_table_ideal_bits=G*N*p,
                       maximum_prime_ideal_bits=8*b*b*d*d)
    table_bits = 33152*J*(p+1)
    assert table_bits % 8 == 0
    return dict(**row, dimension=N, levels=d, gaussian_secrets=secrets,
                gaussian_ephemerals=ephemerals, gaussian_errors=errors,
                tables=dict(count=33152,W=W,offsets=J,precision=p,threshold_bits=p+1,
                            raw_threshold_bytes=table_bits//8),
                rho_terms=[dict(name=name,coefficient=n,negative_power_of_two=e) for name,n,e in rho_terms],
                rho_strict_upper_exponent=exact_upper_exponent(rho),
                old_budget=old,new_budget=new,bounded_source_ledger=source_work)
