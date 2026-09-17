"""Exact modulus-drop bound used by profile derivations."""

def drop_noise(B, kappa, prime):
    return (2 * B - 1 + (kappa + 2) * prime) // (2 * prime)

