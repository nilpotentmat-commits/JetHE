"""Original exact RNS primes and primitive-root certificates."""
from math import prod,gcd

CERTIFICATES = [
    (1152921504002872321, 38, [(2, 10), (3, 2), (5, 1), (17, 1), (47, 1), (257, 1), (2617, 1), (46559, 1)]),
    (1152921503566671361, 14, [(2, 9), (3, 1), (5, 1), (17, 1), (191, 1), (257, 1), (179896663, 1)]),
    (1152921503264686081, 7, [(2, 14), (3, 1), (5, 1), (17, 1), (257, 1), (1073758207, 1)]),
    (1152921503096916481, 13, [(2, 9), (3, 2), (5, 1), (17, 1), (257, 1), (11453420873, 1)]),
    (1152921503063362561, 31, [(2, 10), (3, 1), (5, 1), (11, 1), (17, 1), (29, 1), (257, 1), (601, 1), (89611, 1)]),
    (1152921502794931201, 11, [(2, 10), (3, 2), (5, 2), (17, 1), (257, 1), (1145342087, 1)]),
    (1152921502560053761, 13, [(2, 9), (3, 1), (5, 1), (17, 1), (23, 1), (109, 1), (257, 1), (1319, 1), (10391, 1)]),
    (1152921501922529281, 11, [(2, 12), (3, 1), (5, 1), (17, 1), (257, 1), (3911, 1), (1098193, 1)]),
]


def recover_garner(residues, primes, inverses):
    """Exact mixed-radix CRT; constants are precomputed outside each call."""
    digits, modular_products = [], 0
    for i, (residue, prime) in enumerate(zip(residues, primes)):
        digit = residue
        for j in range(i):
            digit = (digit - digits[j]) * inverses[j, i] % prime
            modular_products += 1
        digits.append(digit)
    value, growing_products = digits[-1], 0
    for i in range(len(primes) - 2, -1, -1):
        value = value * primes[i] + digits[i]
        growing_products += 1
    modulus = prod(primes)
    return (value if value <= modulus // 2 else value - modulus,
            modular_products, growing_products)

