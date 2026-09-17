from array import array
import ctypes as C
from math import prod
from pathlib import Path
from composition_native import NativeRing,P,U,pointer,CERTIFICATES
from composition_optimized import OptimizedRing
LIBRARY=Path(__file__).resolve().parents[1]/"build/paid_hasse_core_v1.so"

class PaidHasseRing(OptimizedRing):
    def __init__(self, length=256, limbs=4):
        assert length in (16, 256) and 1 <= limbs <= 4
        self.length, self.dimension, self.limbs = length, length*256, limbs
        self.conventional = False
        self.primes = [x[0] for x in CERTIFICATES[:limbs]]
        self.moduli = [1]+[prod(self.primes[:a]) for a in range(1, limbs+1)]
        self.dll = C.CDLL(str(LIBRARY))
        self.handle = None
        declarations = {
            'jc_error': ([], C.c_char_p),
            'jc_paid_create': ([C.c_uint]*2, P), 'jc_paid_destroy': ([P], None),
            'jc_transform': ([P,P,P,C.c_uint,C.c_uint,C.c_uint], C.c_int),
            'jc_point': ([P,P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_validate': ([P,P,C.c_uint], C.c_int), 'jc_lift': ([P,P,P,C.c_uint], C.c_int),
            'jc_digits': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_hasse': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_relative': ([P,P,P,C.c_uint,C.c_uint,C.c_uint], C.c_int),
            'jc_drop': ([P,P,P,C.c_uint], C.c_int),
            'jc_phase_check': ([P,P,P,P,P,C.c_uint], C.c_int),
            'jc_series_product': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_series_horner': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_scale': ([P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_sample': ([P,U,P,U,C.c_uint,U,P], C.c_int),
            'jc_hoist': ([P,P,P,P,C.c_uint,C.c_uint], C.c_int),
            'jc_relative_point': ([P,P,P,P,C.c_uint,C.c_uint,C.c_uint], C.c_int),
            'jc_paid_multiplier': ([P,P,P,C.c_uint,C.c_uint,C.c_uint], C.c_int),
        }
        for name, (args, result) in declarations.items():
            fn = getattr(self.dll, name)
            fn.argtypes, fn.restype = args, result
        self.handle = self.dll.jc_paid_create(length, limbs)
        assert self.handle, self.dll.jc_error().decode()
        self.hoisted = []

    def close(self):
        if self.handle:
            self.dll.jc_paid_destroy(self.handle)
            self.handle = None

    def paid_multiplier(self, compact, limbs, r, index):
        assert r in (2, 4, 8) and 2*r <= self.length and 0 <= index <= r
        out = self.zeros(limbs)
        self.call('jc_paid_multiplier', self.handle, self.spectrum(compact, limbs),
                  pointer(out, 'Q'), limbs, r, index)
        return out

