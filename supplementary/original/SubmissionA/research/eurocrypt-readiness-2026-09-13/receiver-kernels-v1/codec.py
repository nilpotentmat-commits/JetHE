"""Full GF(65536) <-> real-period binary codec from frozen prime CRT assets.

The prime-ring product tree is retained for a transparent reference codec.
It uses twice the real degree internally and claims no optimized cost.
"""
import gzip
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ASSETS = ROOT/'SubmissionA/research/core-resolution/packed-fermat-receiver-v1/prime-codec-assets-v1.json.gz'


def binary_remainder(value, modulus):
    degree = modulus.bit_length() - 1
    assert degree >= 0
    while value.bit_length() > degree:
        value ^= modulus << (value.bit_length() - degree - 1)
    return value


def binary_multiply(left, right):
    if left.bit_length() < right.bit_length():
        left, right = right, left
    if right.bit_length() <= 64:
        out = 0
        while right:
            bit = right & -right
            out ^= left << (bit.bit_length()-1)
            right ^= bit
        return out
    shift = (max(left.bit_length(), right.bit_length()) + 1) // 2
    mask = (1 << shift) - 1
    a, b, c, d = left & mask, left >> shift, right & mask, right >> shift
    low, high = binary_multiply(a, c), binary_multiply(b, d)
    middle = binary_multiply(a ^ b, c ^ d) ^ low ^ high
    return low ^ (middle << shift) ^ (high << (2*shift))


def binary_inverse(value, modulus):
    a, b, u, v = binary_remainder(value, modulus), modulus, 1, 0
    while a != 1:
        if not a:
            raise ValueError('Noninvertible binary polynomial.')
        shift = a.bit_length() - b.bit_length()
        if shift < 0:
            a, b, u, v = b, a, v, u
            shift = -shift
        a ^= b << shift
        u ^= v << shift
    return binary_remainder(u, modulus)


def bits_value(coefficients):
    return sum(int(value) << i for i, value in enumerate(coefficients))


class BinaryProduct:
    def __init__(self, backend):
        self.backend = backend
        self.spread = [b''.join(((v >> j) & 1).to_bytes(3, 'little') for j in range(8))
                       for v in range(256)]

    def __call__(self, a, b):
        if min(a.bit_length(), b.bit_length()) <= 256 or self.backend is None:
            return binary_multiply(a, b)
        # At most 65537 summands per coefficient; 24-bit digits cannot carry.
        assert max(a.bit_length(), b.bit_length()) <= 131074
        packed = [b''.join(self.spread[v] for v in x.to_bytes((x.bit_length()+7)//8, 'little'))
                  for x in (a, b)]
        raw = self.backend.multiply_bytes(*packed)
        parity = raw[::3]
        out = bytearray((len(parity)+7)//8)
        for i in range(len(out)):
            out[i] = sum((value & 1) << j for j, value in enumerate(parity[8*i:8*i+8]))
        return int.from_bytes(out, 'little')


class Codec:
    def __init__(self, backend=None):
        data = json.loads(gzip.decompress(ASSETS.read_bytes()))
        self.multiply = BinaryProduct(backend)
        self.field_modulus = bits_value(data['field_modulus_coefficients'])
        self.columns, self.inverses = data['leaf_basis_images'], data['leaf_inverse_rows']
        self.reps = data['representatives']
        self.zeta = data['zeta']
        assert self.reps == [pow(3, i, 65537) for i in range(2048)]
        self.moduli = [[bits_value(v) for v in data['leaf_modulus_coefficients']]]
        self.crt_inverses = []
        while len(self.moduli[-1]) > 1:
            values = self.moduli[-1]
            inverses, products = [], []
            for a, b in zip(values[::2], values[1::2]):
                inv = binary_inverse(a, b)
                assert binary_remainder(self.multiply(a, inv), b) == 1
                inverses.append(inv)
                products.append(self.multiply(a, b))
            self.crt_inverses.append(inverses)
            self.moduli.append(products)
        self.modulus = self.moduli[-1][0]
        assert self.modulus == (1 << 65537) - 1
        powers = [1]
        for _ in range(1, 16):
            powers.append(self.field_mul(powers[-1], data['subfield_generator']))
        self.embedding = [0] * 65536
        for i in range(1, 65536):
            bit = i & -i
            self.embedding[i] = self.embedding[i ^ bit] ^ powers[bit.bit_length()-1]
        self.unembed = {v: i for i, v in enumerate(self.embedding)}
        assert len(self.unembed) == 65536
        # Every leaf's coordinate map is checked on the complete 32-bit basis.
        for columns, inverse in zip(self.columns, self.inverses):
            assert len(columns) == len(inverse) == 32
            assert all(sum(((mask & column).bit_count() & 1) << i for i, mask in enumerate(inverse)) == 1 << j
                       for j, column in enumerate(columns))

    def field_mul(self, a, b):
        return binary_remainder(binary_multiply(a, b), self.field_modulus)

    def field_power(self, a, power):
        out = 1
        while power:
            if power & 1:
                out = self.field_mul(out, a)
            a = self.field_mul(a, a)
            power >>= 1
        return out

    def encode(self, slots):
        assert len(slots) == 2048 and all(0 <= x < 65536 for x in slots)
        words = [self.embedding[x] for x in slots]
        values = [sum(((mask & word).bit_count() & 1) << i for i, mask in enumerate(inverse))
                  for word, inverse in zip(words, self.inverses)]
        for moduli, inverses in zip(self.moduli[:-1], self.crt_inverses):
            values = [a ^ self.multiply(left, binary_remainder(self.multiply(a ^ b, inv), right))
                      for a, b, left, right, inv in zip(values[::2], values[1::2],
                                                      moduli[::2], moduli[1::2], inverses)]
        standard = values[0]
        assert standard.bit_length() <= 65536
        physical = standard ^ (self.modulus if standard & 1 else 0)
        assert physical & 1 == 0
        coefficients = [(physical >> i) & 1 for i in range(1, 65537)]
        assert coefficients == coefficients[::-1], 'Encoded subfield element is not real.'
        return coefficients[:32768]

    def decode(self, coefficients):
        assert len(coefficients) == 32768 and all(x in (0, 1) for x in coefficients)
        full = [0] + list(coefficients) + list(reversed(coefficients))
        values = [binary_remainder(bits_value(full), self.modulus)]
        for moduli in reversed(self.moduli[:-1]):
            values = [binary_remainder(values[i//2], modulus) for i, modulus in enumerate(moduli)]
        words = []
        for value, columns in zip(values, self.columns):
            word = 0
            for i, column in enumerate(columns):
                if (value >> i) & 1:
                    word ^= column
            words.append(self.unembed[word])
        return words

    def direct_slots(self, coefficients, slots):
        """Independent evaluation at original GF(2^32) roots; sparse slot oracle."""
        out = []
        for slot in slots:
            root = self.field_power(self.zeta, self.reps[slot])
            inverse = self.field_power(root, 65536)
            positive, negative, word = 1, 1, 0
            for value in coefficients:
                positive, negative = self.field_mul(positive, root), self.field_mul(negative, inverse)
                if value & 1:
                    word ^= positive ^ negative
            out.append(self.unembed[word])
        return out
