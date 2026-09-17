from array import array
import ctypes as C
from pathlib import Path
from composition_native import P,pointer
from composition_full_run import Cipher,M
LIGHT=Path(__file__).resolve().parents[1]

class FastTerminalRing:
    def terminal_multipliers(self, compact, a):
        assert a <= 2
        even, odd = self.zeros(a), self.zeros(a)
        code = self.terminal_dll.jet_terminal_multipliers(
            self.spectrum(compact, a), self.spectrum(self.public_t, a, True),
            pointer(even, 'Q'), pointer(odd, 'Q'), self.length, a)
        assert code == 0
        return even, odd

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

