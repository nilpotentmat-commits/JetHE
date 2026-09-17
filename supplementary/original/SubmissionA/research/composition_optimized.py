"""Explicit Linux binding to the separate shared-transform extension.

Inherited methods are frozen; no module-global DLL replacement or RNG patch.
"""
from array import array
import ctypes as C
from math import prod
from pathlib import Path
from composition_native import NativeRing,P,U,pointer,CERTIFICATES

LIBRARY=Path(__file__).resolve().parent.parent/'build'/'composition_optimized_core.so'


class OptimizedRing(NativeRing):
    def __init__(self,length=256,limbs=4):
        assert length in (16,256) and 1<=limbs<=4
        self.length,self.dimension,self.limbs=length,length*256,limbs
        self.conventional=False
        self.primes=[x[0] for x in CERTIFICATES[:limbs]]
        self.moduli=[1]+[prod(self.primes[:a]) for a in range(1,limbs+1)]
        self.dll=C.CDLL(str(LIBRARY));self.handle=None
        declarations={
            'jc_error':([],C.c_char_p),'jc_opt_create':([C.c_uint]*2,P),'jc_opt_destroy':([P],None),
            'jc_transform':([P,P,P,C.c_uint,C.c_uint,C.c_uint],C.c_int),
            'jc_point':([P,P,P,P,C.c_uint,C.c_uint],C.c_int),
            'jc_validate':([P,P,C.c_uint],C.c_int),'jc_lift':([P,P,P,C.c_uint],C.c_int),
            'jc_digits':([P,P,P,C.c_uint,C.c_uint],C.c_int),
            'jc_hasse':([P,P,P,C.c_uint,C.c_uint],C.c_int),
            'jc_relative':([P,P,P,C.c_uint,C.c_uint,C.c_uint],C.c_int),
            'jc_drop':([P,P,P,C.c_uint],C.c_int),'jc_phase_check':([P,P,P,P,P,C.c_uint],C.c_int),
            'jc_series_product':([P,P,P,C.c_uint,C.c_uint],C.c_int),
            'jc_series_horner':([P,P,P,C.c_uint,C.c_uint],C.c_int),
            'jc_scale':([P,P,P,C.c_uint,C.c_uint],C.c_int),
            'jc_sample':([P,U,P,U,C.c_uint,U,P],C.c_int),
            'jc_hoist':([P,P,P,P,C.c_uint,C.c_uint],C.c_int),
            'jc_relative_point':([P,P,P,P,C.c_uint,C.c_uint,C.c_uint],C.c_int),
        }
        for name,(args,result) in declarations.items():
            fn=getattr(self.dll,name);fn.argtypes=args;fn.restype=result
        self.handle=self.dll.jc_opt_create(length,limbs)
        assert self.handle,self.dll.jc_error().decode()
        self.hoisted=[]

    def close(self):
        if self.handle:self.dll.jc_opt_destroy(self.handle);self.handle=None

    def hoist(self,digit,limbs,r):
        compact,full=self.zeros(limbs),self.zeros(limbs)
        self.call('jc_hoist',self.handle,pointer(digit,'q',self.dimension),pointer(compact,'Q'),pointer(full,'Q'),limbs,r)
        self.hoisted.append((limbs,r))
        return compact,full

    def relative_point(self,compact,row,limbs,r,index):
        out=self.zeros(limbs)
        self.call('jc_relative_point',self.handle,self.spectrum(compact,limbs),self.spectrum(row,limbs),pointer(out,'Q'),limbs,r,index)
        return out
