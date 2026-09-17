"""Measured tensor codec, with its setup checks retained."""
from field import Field
E=256
MASK=(1<<E)-1

def power(field, value, exponent):
    result = 1
    while exponent:
        if exponent & 1:
            result = field.mul(result, value)
        value = field.mul(value, value)
        exponent >>= 1
    return result


def apply_matrix(rows, value):
    return sum(((row & value).bit_count() & 1) << i for i, row in enumerate(rows))


def inverse_matrix(rows):
    augmented = [row | (1 << (E + i)) for i, row in enumerate(rows)]
    for i in range(E):
        pivot = next(j for j in range(i, E) if (augmented[j] >> i) & 1)
        augmented[i], augmented[pivot] = augmented[pivot], augmented[i]
        for j in range(E):
            if j != i and (augmented[j] >> i) & 1:
                augmented[j] ^= augmented[i]
    assert all(row & MASK == 1 << i for i, row in enumerate(augmented))
    return [row >> E for row in augmented]


def setup():
    field = Field(16, 0x1100B)
    beta = next(root for candidate in range(2, 65536)
                if (root := power(field, candidate, 255)) != 1)
    assert power(field, beta, 257) == 1
    seen, representatives = set(), []
    for candidate in range(1, 257):
        if candidate not in seen:
            representatives.append(candidate)
            orbit, value = [], candidate
            while value not in orbit:
                orbit.append(value)
                value = 2 * value % 257
            assert len(orbit) == 16 and value == candidate
            assert seen.isdisjoint(orbit)
            seen.update(orbit)
    assert len(representatives) == 16 and len(seen) == 256
    roots = [power(field, beta, r) for r in representatives]
    columns = [0] * E
    for lane, root in enumerate(roots):
        value = root
        for j in range(E):
            columns[j] |= value << (16 * lane)
            value = field.mul(value, root)
    rows = [sum(((col >> i) & 1) << j for j, col in enumerate(columns))
            for i in range(E)]
    inverse = inverse_matrix(rows)
    for j, col in enumerate(columns):
        assert apply_matrix(rows, 1 << j) == col
        assert apply_matrix(inverse, col) == 1 << j
        assert apply_matrix(rows, apply_matrix(inverse, 1 << j)) == 1 << j
    return field, beta, representatives, roots, rows, inverse


def butterfly(values):
    result = list(values)
    length = len(values)
    assert length > 0 and length & (length - 1) == 0
    count, stride = 0, 1
    while stride < length:
        for base in range(0, length, 2 * stride):
            for i in range(base, base + stride):
                result[i] ^= result[i + stride]
                count += 1
        stride *= 2
    assert count == length * (length.bit_length() - 1) // 2
    return result, count


def decode(values, rows):
    shifted, _ = butterfly(values)
    return [apply_matrix(rows, value) for value in shifted]


def encode(values, inverse):
    return butterfly([apply_matrix(inverse, value) for value in values])[0]

