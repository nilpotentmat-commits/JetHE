"""Typed bindings for the separately compiled composition arithmetic core.

No HE policy or security qualification. Array lengths are checked BEFORE the
C ABI. The arithmetic backend supports the selected J256 and C4096 carriers.
"""
from array import array
import ctypes as C
from math import prod
from pathlib import Path

from check_composition_rns_arithmetic import CERTIFICATES

U, I, B, H = C.c_uint64, C.c_int64, C.c_uint8, C.c_uint16
P = C.c_void_p
DLL_PATH = Path(__file__).resolve().parent.parent/'build'/'composition_native_core.dll'


def pointer(values, typecode, size=None):
    assert isinstance(values, (array, memoryview))
    actual = values.typecode if isinstance(values, array) else values.format
    assert actual == typecode and (size is None or len(values) == size)
    return (C.c_char*(values.itemsize*len(values))).from_buffer(values)


class NativeRing:
    def __init__(self, length, limbs=4, conventional=False):
        assert 1 <= length <= 256 and length & (length-1) == 0
        assert 1 <= limbs <= 4 and (not conventional or length == 16)
        self.length, self.dimension, self.limbs = length, length*256, limbs
        self.conventional = conventional
        self.primes = [x[0] for x in CERTIFICATES[:limbs]]
        self.moduli = [1]+[prod(self.primes[:a]) for a in range(1, limbs+1)]
        self.dll = C.CDLL(str(DLL_PATH))
        declarations = {
            'jc_error': ([], C.c_char_p),
            'jc_create': ([C.c_uint]*3, P), 'jc_destroy': ([P], None),
            'jc_transform': ([P,P,P,C.c_uint,C.c_uint,C.c_uint], C.c_int),
            'jc_point': ([P,P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_validate': ([P,P,C.c_uint], C.c_int),
            'jc_lift': ([P,P,P,C.c_uint], C.c_int),
            'jc_digits': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_hasse': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_relative': ([P,P,P,C.c_uint,C.c_uint,C.c_uint], C.c_int),
            'jc_drop': ([P,P,P,C.c_uint], C.c_int),
            'jc_phase_check': ([P,P,P,P,P,C.c_uint], C.c_int),
            'jc_series_product': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_series_horner': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_scale': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_sample': ([P,U,P,U,C.c_uint,U,P], C.c_int),
        }
        for name, (args, result) in declarations.items():
            fn=getattr(self.dll,name);fn.argtypes=args;fn.restype=result
        self.handle = self.dll.jc_create(length, limbs, conventional)
        assert self.handle, self.dll.jc_error().decode()

    def close(self):
        if self.handle:
            self.dll.jc_destroy(self.handle)
            self.handle = None

    def call(self, name, *args):
        assert self.handle is not None
        if getattr(self.dll, name)(*args):
            raise AssertionError(name+': '+self.dll.jc_error().decode())

    def zeros(self, limbs):
        assert 1 <= limbs <= self.limbs
        return array('Q', [0])*(limbs*self.dimension)

    def spectrum(self, data, limbs, prefix=False):
        assert 1 <= limbs <= self.limbs
        assert isinstance(data, (array, memoryview))
        assert len(data) >= limbs*self.dimension if prefix else len(data) == limbs*self.dimension
        return pointer(data,'Q')

    def validate(self, data, limbs):
        self.call('jc_validate',self.handle,self.spectrum(data,limbs),limbs)

    def transform(self, source, channel, inverse=False, length=None):
        length = self.length if length is None else length
        assert 0 <= channel < self.limbs and 1 <= length <= self.length
        assert length & (length-1) == 0
        assert not self.conventional or length == self.length
        assert all(0 <= x < self.primes[channel] for x in source)
        out=array('Q',[0])*(length*256)
        self.call('jc_transform',self.handle,pointer(source,'Q',len(out)),pointer(out,'Q'),channel,inverse,length)
        return out

    def lift(self, coefficients, limbs):
        out=self.zeros(limbs)
        self.call('jc_lift',self.handle,pointer(coefficients,'q',self.dimension),pointer(out,'Q'),limbs)
        return out

    def point(self, a, b, limbs, operation=1):
        out=self.zeros(limbs)
        self.call('jc_point',self.handle,self.spectrum(a,limbs,True),self.spectrum(b,limbs,True),pointer(out,'Q'),limbs,operation)
        return out

    def add(self, a, b, limbs):
        self.spectrum(a,limbs);self.spectrum(b,limbs)
        return self.point(a,b,limbs,0)

    def sub(self, a, b, limbs):
        self.spectrum(a,limbs);self.spectrum(b,limbs)
        return self.point(a,b,limbs,2)

    def scale(self, value, limbs, exponent):
        assert 0 <= exponent <= 240
        out=self.zeros(limbs)
        self.call('jc_scale',self.handle,self.spectrum(value,limbs,True),pointer(out,'Q'),limbs,exponent)
        return out

    def gadget(self, limbs, width=48):
        assert width in (48,60) and 1 <= limbs <= self.limbs
        return (self.moduli[limbs].bit_length()+width-1)//width

    def digits(self, spectrum, limbs, width=48):
        out=array('q',[0])*(self.gadget(limbs,width)*self.dimension)
        self.call('jc_digits',self.handle,self.spectrum(spectrum,limbs),pointer(out,'q'),limbs,width)
        view=memoryview(out)
        return [view[j*self.dimension:(j+1)*self.dimension] for j in range(self.gadget(limbs,width))]

    def hasse_spectrum(self, spectrum, limbs, r):
        out=self.zeros(limbs)
        self.call('jc_hasse',self.handle,self.spectrum(spectrum,limbs),pointer(out,'Q'),limbs,r)
        return out

    def relative_spectrum(self, digit, index, r, limbs):
        out=self.zeros(limbs)
        self.call('jc_relative',self.handle,pointer(digit,'q',self.dimension),pointer(out,'Q'),limbs,index,r)
        return out

    def drop(self, spectrum, limbs):
        assert 2 <= limbs <= self.limbs
        out=self.zeros(limbs-1)
        self.call('jc_drop',self.handle,self.spectrum(spectrum,limbs),pointer(out,'Q'),limbs)
        return out

    def phase_check(self, spectrum, bits, bound, limbs):
        assert isinstance(bits, bytearray) and len(bits)==self.dimension
        assert 0 <= bound < 1<<256 and self.moduli[limbs] > 2+4*bound
        limit=(U*4)(*[(bound>>(64*j))&((1<<64)-1) for j in range(4)])
        result=(U*4)()
        self.call('jc_phase_check',self.handle,self.spectrum(spectrum,limbs),(B*len(bits)).from_buffer(bits),limit,result,limbs)
        return sum(int(result[j])<<(64*j) for j in range(4))

    def series(self, a, b, length, jobs=16, horner=False):
        assert 1 <= length <= 256 and 1 <= jobs <= 16
        out=array('H',[0])*(length*jobs)
        self.call('jc_series_horner' if horner else 'jc_series_product',pointer(a,'H',len(out)),pointer(b,'H',len(out)),pointer(out,'H'),length,jobs)
        return out

    def sample_words(self, words, wanted, kind, prime=0):
        assert len(words) >= wanted and wanted > 0
        out=array('q',[0])*wanted
        written=U()
        self.call('jc_sample',pointer(words,'Q'),len(words),pointer(out,'q'),wanted,kind,prime,C.byref(written))
        return out[:written.value]
