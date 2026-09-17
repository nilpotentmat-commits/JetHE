"""Finite-check routines extracted from a preserved research source.
See ../provenance.json and ../README.md for scope and source hashes.
Run the portable ../run_checks.py entry point.
"""

from collections import Counter
from fractions import Fraction as F
from random import Random

COUNTS = Counter()


U0 = [(1,0,0,1),(0,0,1,1),(1,0,0,0),(0,0,0,1),
      (1,1,0,0),(-1,0,1,0),(0,1,0,-1)]


V0 = [(1,0,0,1),(1,0,0,0),(0,1,0,-1),(-1,0,1,0),
      (0,0,0,1),(1,1,0,0),(0,0,1,1)]


W0 = [(1,0,0,1,-1,0,1),(0,0,1,0,1,0,0),
      (0,1,0,1,0,0,0),(1,-1,1,0,0,1,0)]


U = [[F(x,2) for x in row] for row in U0]


V = [[F(2*x) for x in row] for row in V0]


W = [[F(x) for x in row] for row in W0]


D = 2


UI = [[int(D*x) for x in row] for row in U]


VI = [[int(D*x) for x in row] for row in V]


WI = [[int(D*x) for x in row] for row in W]


def check_tensor():
    for out in range(4):
        for left in range(4):
            for right in range(4):
                expected = int(left//2 == out//2 and right%2 == out%2
                               and left%2 == right//2)
                assert sum(W[out][r]*U[r][left]*V[r][right]
                           for r in range(7)) == expected
                COUNTS['tensor_coefficients'] += 1


def naive(a, b):
    return [[sum(a[i][k]*b[k][j] for k in range(len(a)))
             for j in range(len(a))] for i in range(len(a))]


def exact_kernel(a, b):
    n = len(a)
    assert n and n & (n-1) == 0
    if n == 1:
        return [[a[0][0]*b[0][0]]]
    h = n//2
    def blocks(m):
        return [[[m[h*x+i][h*y+j] for j in range(h)] for i in range(h)]
                for x in range(2) for y in range(2)]
    def linear(coeff, bs):
        return [[sum(coeff[k]*bs[k][i][j] for k in range(len(bs)))
                 for j in range(h)] for i in range(h)]
    aa, bb = blocks(a), blocks(b)
    products = [exact_kernel(linear(UI[r], aa), linear(VI[r], bb))
                for r in range(7)]
    result = [[0]*n for _ in range(n)]
    for z in range(4):
        num = linear(WI[z], products)
        for i in range(h):
            for j in range(h):
                assert num[i][j] % D**3 == 0
                COUNTS['exact_reconstruction_divisions'] += 1
                result[(z//2)*h+i][(z%2)*h+j] = num[i][j]//D**3
    return result


def packed_product(a, b, ell, q):
    e = len(a)
    ne = 256*ell
    bq = (q-1).bit_length()
    width = 2*bq+(e*ne-1).bit_length()+1
    bound = e*ne*(q-1)**2
    assert bound < 1 << width
    def encode(poly):
        return sum(v << (width*(513*i+j)) for (i,j),v in poly.items())
    aa = [[encode(poly) for poly in row] for row in a]
    bb = [[encode(poly) for poly in row] for row in b]
    cc = exact_kernel(aa, bb)
    result = []
    mask = (1 << width)-1
    for row in cc:
        rr = []
        for value in row:
            assert value >= 0
            coeff = [[0]*257 for _ in range(ell)]
            for i in range(2*ell-1):
                for j in range(513):
                    v = value & mask
                    value >>= width
                    assert v <= bound
                    coeff[i % ell][j % 257] += (-1 if i >= ell else 1)*v
            assert value == 0
            rr.append(tuple((coeff[i][j]-coeff[i][0]) % q
                            for i in range(ell) for j in range(1,257)))
        result.append(rr)
    return result


def oracle_product(a, b, ell, q):
    # Independent sparse convolution followed by monic polynomial long division.
    # In particular this does not use b^257=1 or the packed arithmetic.
    e = len(a)
    result = []
    for i in range(e):
        rr = []
        for j in range(e):
            p = [[0]*513 for _ in range(2*ell-1)]
            for k in range(e):
                for (x,u),v in a[i][k].items():
                    for (y,t),w in b[k][j].items():
                        p[x+y][u+t] += v*w
            for y in range(2*ell-2,ell-1,-1):
                for t in range(513):
                    p[y-ell][t] -= p[y][t]
            physical = []
            for y in range(ell):
                for t in range(512,255,-1):
                    lead = p[y][t]
                    if lead:
                        for z in range(257):
                            p[y][t-256+z] -= lead
                assert all(v == 0 for v in p[y][256:])
                c0 = p[y][0]
                physical.extend((p[y][t]-c0) % q for t in range(1,256))
                physical.append(-c0 % q)
            rr.append(tuple(physical))
        result.append(rr)
    return result
