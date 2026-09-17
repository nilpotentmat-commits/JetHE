"""Exact real-period receiver kernels; arbitrary positive integer moduli.

Linux uses the installed GMP through its documented mpz import/export API.
The pure-Python backend is retained for independent small-ring checks.
This is functional research code, with no constant-time claim.
"""
import ctypes
import ctypes.util
from hashlib import sha256
from pathlib import Path


class MPZ(ctypes.Structure):
    _fields_ = [('alloc', ctypes.c_int), ('size', ctypes.c_int),
                ('limbs', ctypes.POINTER(ctypes.c_ulong))]


class GMP:
    def __init__(self):
        name = ctypes.util.find_library('gmp')
        if not name:
            raise RuntimeError('The production arithmetic check requires installed GMP.')
        self.lib = ctypes.CDLL(name)
        ptr = ctypes.POINTER(MPZ)
        signatures = {
            'init': ([ptr], None), 'clear': ([ptr], None),
            'mul': ([ptr, ptr, ptr], None),
            'import': ([ptr, ctypes.c_size_t, ctypes.c_int, ctypes.c_size_t,
                        ctypes.c_int, ctypes.c_size_t, ctypes.c_void_p], None),
            'export': ([ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_int,
                        ctypes.c_size_t, ctypes.c_int, ctypes.c_size_t, ptr], ctypes.c_void_p),
        }
        for key, (args, result) in signatures.items():
            fn = getattr(self.lib, '__gmpz_' + key)
            fn.argtypes, fn.restype = args, result
            setattr(self, key, fn)
        self.version = ctypes.c_char_p.in_dll(self.lib, '__gmp_version').value.decode()
        matches = {line.split()[-1] for line in Path('/proc/self/maps').read_text().splitlines()
                   if '/libgmp.so' in line}
        assert len(matches) == 1, matches
        self.path = Path(matches.pop()).resolve()

    def multiply_bytes(self, left, right):
        values = [MPZ() for _ in range(3)]
        for value in values:
            self.init(ctypes.byref(value))
        try:
            self.import_(values[0], left)
            self.import_(values[1], right)
            self.mul(ctypes.byref(values[2]), ctypes.byref(values[0]), ctypes.byref(values[1]))
            # An n-byte by m-byte product fits in n+m bytes, including zero.
            out = ctypes.create_string_buffer(len(left) + len(right))
            count = ctypes.c_size_t()
            self.export(out, ctypes.byref(count), -1, 1, -1, 0, ctypes.byref(values[2]))
            assert count.value <= len(out)
            return out.raw
        finally:
            for value in values:
                self.clear(ctypes.byref(value))

    def import_(self, value, raw):
        getattr(self, 'import')(ctypes.byref(value), len(raw), -1, 1, -1, 0, raw)

    def binding(self):
        return dict(path=str(self.path), version=self.version,
                    sha256=sha256(self.path.read_bytes()).hexdigest())


def centered(value, modulus):
    return (value + modulus // 2) % modulus - modulus // 2


def nearest(value, denominator):
    """Nearest integer, exact half-integers towards +infinity."""
    assert denominator > 0
    return (2 * value + denominator) // (2 * denominator)


def scale_round(values, numerator, denominator, modulus):
    return [nearest(numerator * x, denominator) % modulus for x in values]


def choose_radix(modulus, count):
    assert modulus >= 2 and count >= 2
    width = (modulus.bit_length() + count - 1) // count
    while True:
        radix = 1 << width
        if (radix//2-1) * ((radix**count-1)//(radix-1)) >= modulus//2:
            return radix
        width += 1


def decompose(values, modulus, radix, count):
    """Fixed-length balanced expansion, with modular reconstruction.

    The endpoint +radix^count/2 can produce a final -1 carry when every
    intermediate digit is balanced. Modular reconstruction, not a silent
    exact-integer assertion, handles that case when radix^count=modulus.
    """
    assert radix >= 2 and radix % 2 == 0 and radix ** count >= modulus
    current = [centered(x, modulus) for x in values]
    out = []
    for _ in range(count):
        digit = [centered(x, radix) for x in current]
        current = [(x - d) // radix for x, d in zip(current, digit)]
        out.append(digit)
    if radix ** count != modulus:
        assert not any(current), 'Requested digit count cannot encode these centered representatives.'
    assert all((sum(out[j][i] * radix ** j for j in range(count)) - x) % modulus == 0
               for i, x in enumerate(values))
    return out


class RealRing:
    """Basis rho_i = zeta^i + zeta^-i for 1 <= i <= (p-1)/2.

    The scalar one has all coordinates -1 since sum rho_i = -1.
    The caller supplies an odd prime conductor; primality is verified in
    the corresponding fixture/admission, not inferred from this class.
    """
    def __init__(self, prime=65537, backend=None):
        assert prime >= 3 and prime % 2
        self.p, self.n, self.backend = prime, (prime - 1) // 2, backend

    def add(self, a, b, modulus):
        assert len(a) == len(b) == self.n
        return [(x + y) % modulus for x, y in zip(a, b)]

    def scale(self, a, scalar, modulus):
        assert len(a) == self.n
        return [scalar * x % modulus for x in a]

    def scalar(self, value, modulus):
        return [-value % modulus] * self.n

    def auto(self, a, exponent, modulus):
        assert len(a) == self.n and exponent % self.p
        out = [0] * self.n
        for i, value in enumerate(a, 1):
            j = i * exponent % self.p
            out[min(j, self.p-j)-1] = value % modulus
        return out

    def embed(self, values, modulus):
        assert len(values) == self.n
        reduced = [x % modulus for x in values]
        return [0] + reduced + reduced[::-1]

    def mul(self, left, right, modulus):
        assert modulus >= 2
        a, b = self.embed(left, modulus), self.embed(right, modulus)
        # Every ordinary convolution coefficient is <= p*(modulus-1)^2.
        # Byte alignment adds padding; it never permits a carry into a neighbour.
        width = (self.p * (modulus-1)**2).bit_length()
        word = (width + 7) // 8
        packed = [b''.join(x.to_bytes(word, 'little') for x in v) for v in (a, b)]
        if self.backend:
            raw = self.backend.multiply_bytes(*packed)
        else:
            product = int.from_bytes(packed[0], 'little') * int.from_bytes(packed[1], 'little')
            raw = product.to_bytes(2 * self.p * word, 'little')
        view = memoryview(raw)
        def coefficient(j):
            return int.from_bytes(view[j*word:(j+1)*word], 'little')
        constant = coefficient(0) + coefficient(self.p)
        result = []
        for j in range(1, self.n+1):
            value = coefficient(j) + coefficient(j+self.p)
            opposite = coefficient(self.p-j) + coefficient(2*self.p-j)
            assert value == opposite
            result.append((value - constant) % modulus)
        return result

    def slow_mul(self, a, b, modulus):
        """Independent rho_i*rho_j=rho_(i+j)+rho_(i-j) oracle."""
        assert len(a) == len(b) == self.n
        out, constant = [0]*self.n, 0
        for i, x in enumerate(a, 1):
            for j, y in enumerate(b, 1):
                for index in ((i+j) % self.p, (i-j) % self.p):
                    if index:
                        out[min(index, self.p-index)-1] += x*y
                    else:
                        constant += 2*x*y
        return [(x-constant) % modulus for x in out]
