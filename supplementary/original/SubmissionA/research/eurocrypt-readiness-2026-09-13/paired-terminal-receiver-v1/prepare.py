"""Owner-separated preparation for the fixed paired terminal contraction.

The fixture is public test data, not encryption randomness. Neither owner's
preparation function accepts the other owner's input.
"""
from array import array
from hashlib import sha256
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parents[1]
sys.path.insert(0, str(RESEARCH))
import composition_fixture

SLOTS = 2048
FIELD_POLYNOMIAL = 0x1100B


def slow_mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a & 65536:
            a ^= FIELD_POLYNOMIAL
    return out


def slow_power(a, exponent):
    out = 1
    while exponent:
        if exponent & 1:
            out = slow_mul(out, a)
        a = slow_mul(a, a)
        exponent >>= 1
    return out


class Field:
    def __init__(self):
        self.generator = next(g for g in range(2, 50)
                              if all(slow_power(g, 65535 // p) != 1
                                     for p in (3, 5, 17, 257)))
        self.exp = [0] * 131070
        self.log = [-1] * 65536
        value = 1
        for i in range(65535):
            assert self.log[value] == -1
            self.exp[i] = value
            self.log[value] = i
            value = slow_mul(value, self.generator)
        assert value == 1 and all(v >= 0 for v in self.log[1:])
        self.exp[65535:] = self.exp[:65535]
        self.products = 0

    def mul(self, a, b):
        self.products += 1
        return self.exp[self.log[a] + self.log[b]] if a and b else 0


def records(jobs, length):
    assert length >= 2 and length & (length - 1) == 0
    out = []
    for job in range(jobs):
        for j in range(1, length):
            indices = [i for i in range(1, j + 1) if j % (i & -i) == 0]
            for at in range(0, len(indices), 2):
                out.append((job, j, indices[at],
                            indices[at + 1] if at + 1 < len(indices) else None))
    return out


def outer_prepare(fs, public_records, field):
    jobs, length = len(fs), len(fs[0])
    count = len(public_records)
    capacity = ((count + SLOTS - 1) // SLOTS) * SLOTS
    bypass_capacity = ((jobs * length + SLOTS - 1) // SLOTS) * SLOTS
    left, right = array('H', [0]) * capacity, array('H', [0]) * capacity
    bypass = array('H', [0]) * bypass_capacity
    for job, f in enumerate(fs):
        assert len(f) == length
        bypass[job * length] = f[0]
    for at, (job, j, i, k) in enumerate(public_records):
        left[at] = fs[job][i]
        if k is not None:
            right[at] = fs[job][k]
            bypass[job * length + j] ^= field.mul(left[at], right[at])
    return left, right, bypass


def inner_prepare(gs, public_records, field):
    jobs, length = len(gs), len(gs[0])
    capacity = ((len(public_records) + SLOTS - 1) // SLOTS) * SLOTS
    bypass_capacity = ((jobs * length + SLOTS - 1) // SLOTS) * SLOTS
    left, right = array('H', [0]) * capacity, array('H', [0]) * capacity
    bypass = array('H', [0]) * bypass_capacity
    cursor = 0
    for job, g in enumerate(gs):
        assert len(g) == length and g[0] == 0
        powers = [[0] * length for _ in range(length)]
        powers[0][0] = 1
        powers[1] = list(g)
        for i in range(2, length):
            if i % 2 == 0:
                half = powers[i // 2]
                for j in range(i // 2, (length + 1) // 2):
                    powers[i][2 * j] = field.mul(half[j], half[j])
            else:
                previous, target = powers[i - 1], powers[i]
                for e in range(i - 1, length, 2):
                    if previous[e]:
                        for v in range(1, length - e):
                            target[e + v] ^= field.mul(previous[e], g[v])
        while cursor < len(public_records) and public_records[cursor][0] == job:
            _, j, i, k = public_records[cursor]
            x = powers[i][j]
            y = powers[k][j] if k is not None else 0
            # (f_i+y)(f_k+x) cancels with the two owner-local corrections.
            left[cursor], right[cursor] = y, x
            if k is not None:
                bypass[job * length + j] ^= field.mul(x, y)
            cursor += 1
    assert cursor == len(public_records)
    return left, right, bypass


def independent_horner(fs, gs):
    """Small-length independent carryless-multiplication oracle."""
    length = len(fs[0])
    assert length <= 16
    answers = []
    for f, g in zip(fs, gs):
        value = [0] * length
        for coefficient in reversed(f):
            product = [0] * length
            for i, a in enumerate(value):
                for j, b in enumerate(g[:length - i]):
                    product[i + j] ^= slow_mul(a, b)
            product[0] ^= coefficient
            value = product
        answers.extend(value)
    return answers


def expected_values(fs, gs):
    if len(fs[0]) <= 16:
        return independent_horner(fs, gs), 'fresh independent Python Horner; carryless field arithmetic'
    assert len(fs) == 16 and len(fs[0]) == 256
    raw = (HERE.parent / 'compiled-receiver-v1' / 'expected.bin').read_bytes()
    assert sha256(raw).hexdigest() == 'd22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
    assert len(raw) == 8192
    return list(struct.unpack('<4096H', raw)), 'bound previously generated independent C++ Horner oracle'


def record_digest(public_records):
    raw = b''.join(struct.pack('<4H', job, j, i, 65535 if k is None else k)
                   for job, j, i, k in public_records)
    return sha256(raw).hexdigest()
