"""Explicit fast bindings, identical encryption law and terminal interface."""
from array import array
import ctypes as C
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
LIGHT=HERE.parent/'lightweight-jethe-2026-09-13'
sys.path[:0]=[str(HERE),str(LIGHT),str(HERE.parent/'existing-results-revision-2026-09-13'),str(HERE.parent)]
from fast_ring_v1 import FastRing
from composition_native import pointer, P
from composition_full_run import Cipher, M
import terminal_v1


class FastTerminalRing(FastRing):
    terminal_multipliers=terminal_v1.TerminalRing.terminal_multipliers

    def __init__(self,length=256,limbs=4):
        super().__init__(length,limbs)
        self.terminal_dll=C.CDLL(str(LIGHT/'build/terminal_kernel_v1.so'))
        self.terminal_dll.jet_terminal_multipliers.argtypes=[P,P,P,P,C.c_uint,C.c_uint]
        self.terminal_dll.jet_terminal_multipliers.restype=C.c_int
        coeff=array('q',[0])*self.dimension
        coeff[256:512]=array('q',[-1])*256
        self.public_t=self.lift(coeff,min(2,limbs))


def encrypt(ring,coins,pk,mu,label):
    assert len(mu)==M and isinstance(mu,bytearray)
    u=coins.ternary('enc/'+label+'/u')
    e0=coins.error('enc/'+label+'/e0')
    e1=coins.error('enc/'+label+'/e1')
    fn=ring.dll.jc_encrypt_fused
    fn.argtypes=[P]*9+[C.c_uint]
    fn.restype=C.c_int
    a=pk.limbs
    out0,out1=ring.zeros(a),ring.zeros(a)
    ring.call('jc_encrypt_fused',ring.handle,ring.spectrum(pk.components[0],a),ring.spectrum(pk.components[1],a),
        pointer(u,'q',M),pointer(e0,'q',M),pointer(e1,'q',M),
        (C.c_uint8*M).from_buffer(mu),pointer(out0,'Q'),pointer(out1,'Q'),a)
    return Cipher(pk.key,a,(out0,out1))
