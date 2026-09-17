"""Plaintext Hasse/Frobenius operations used by owner preparation."""

def hasse(x, r):
    out = [0] * len(x)
    for i, c in enumerate(x):
        if i & r:
            out[i - r] = c
    return out


def mixed_hasse(x, mask):
    out = [0] * len(x)
    for i, c in enumerate(x):
        if i & mask == mask:
            out[i - mask] = c
    return out


def frobenius(x, j, field):
    out = [0] * len(x)
    for i, c in enumerate(x[:len(x) >> j]):
        for _ in range(j):
            c = field.mul(c, c)
        out[i << j] = c
    return out

