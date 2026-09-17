"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

from math import gcd

def unit_determinant(matrix, modulus):
    a, determinant = [list(x) for x in matrix], 1
    for j in range(len(a)):
        pivot = next((i for i in range(j, len(a)) if gcd(a[i][j], modulus) == 1), None)
        assert pivot is not None
        if pivot != j:
            a[j], a[pivot] = a[pivot], a[j]
            determinant = -determinant
        diagonal = a[j][j] % modulus
        determinant = determinant*diagonal % modulus
        inverse = pow(diagonal, -1, modulus)
        for i in range(j+1, len(a)):
            factor = a[i][j]*inverse % modulus
            for k in range(j+1, len(a)):
                a[i][k] = (a[i][k]-factor*a[j][k]) % modulus
            a[i][j] = 0
    assert gcd(determinant, modulus) == 1
    return determinant


def production_minors():
    L, modulus, generator = 256, 1152921504002872321, 38
    t = pow(generator, (modulus-1)//(2*L), modulus)
    b = pow(generator, (modulus-1)//257, modulus)
    assert pow(t, L, modulus) == modulus-1 and pow(b, 257, modulus) == 1
    assert gcd(b-1, modulus) == gcd(t, modulus) == gcd(b, modulus) == 1
    assert sum(pow(b, i, modulus) for i in range(257)) % modulus == 0
    q3 = 1532495536896400456983759139388378955311724145690575361
    assert q3 % modulus == 0
    results, coefficients = [], 0
    for r in (1, 2, 4, 8, 16, 32, 64, 128):
        for pattern in range(4):
            def sign(i):
                return (-1)**(0 if pattern == 0 else i if pattern == 1 else i.bit_count() if pattern == 2 else (i*i+3*i+1)//2)
            def F_monomial(i):
                wrap, index = divmod(i, L)
                return ((-1)**wrap*sign(index)*pow(t, index-r, modulus)*b) % modulus if index & r else 0
            columns = [0]+list(range(r, 0, -1))
            for mode in ('paid', 'free'):
                first = ([F_monomial(r+j) for j in columns] if mode == 'paid' else
                         [pow(t, j, modulus)*b % modulus for j in columns])
                matrix = [first]+[[F_monomial(i+j) for j in columns] for i in range(r)]
                determinant = unit_determinant(matrix, modulus)
                want = (pow(sign(r)*b, r+1, modulus) if mode == 'paid' else
                        b*pow(sign(r)*b, r, modulus)) % modulus
                assert determinant == want
                coefficients += (r+1)**2
                results.append(dict(r=r, sign_pattern=pattern, mode=mode, size=r+1,
                                    unit_determinant=determinant))
    return dict(L=L, coefficient_rank=65536, odd_factor_residue_modulus=modulus,
                tested_minors=len(results), matrix_entries=coefficients, cases=results,
                scope='Unit-minor arithmetic in a residue ring of the actual q3; not a primality or security certificate.')
