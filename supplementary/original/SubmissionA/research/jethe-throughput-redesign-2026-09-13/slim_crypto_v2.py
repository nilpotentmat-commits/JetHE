"""Same sampler, 44-bit gadget, lower creation moduli; no global patching."""
from array import array
import ctypes as C
from fast_crypto_v1 import FastTerminalRing
from slim_ring_base_v2 import SlimRingBase
from composition_native import pointer, P
from composition_full_run import Bank

class SlimRing(SlimRingBase):
    terminal_multipliers=FastTerminalRing.terminal_multipliers
    def __init__(self):
        super().__init__(256,3)
        from fast_crypto_v1 import LIGHT
        self.terminal_dll=C.CDLL(str(LIGHT/'build/terminal_kernel_v1.so'))
        self.terminal_dll.jet_terminal_multipliers.argtypes=[P,P,P,P,C.c_uint,C.c_uint]
        self.terminal_dll.jet_terminal_multipliers.restype=C.c_int
        coeff=array('q',[0])*self.dimension
        coeff[256:512]=array('q',[-1])*256
        self.public_t=self.lift(coeff,2)
    def gadget(self,limbs,width=44):
        assert width==44 and 1<=limbs<=self.limbs
        return (self.moduli[limbs].bit_length()+43)//44
    def digits(self,spectrum,limbs,width=44):
        assert width==44
        out=array('q',[0])*(self.gadget(limbs)*self.dimension)
        self.call('jc_digits',self.handle,self.spectrum(spectrum,limbs),pointer(out,'q'),limbs,width)
        v=memoryview(out)
        return [v[j*self.dimension:(j+1)*self.dimension] for j in range(self.gadget(limbs))]

def make_bank(ring,coins,source,destination,payload,name,kind):
    a=destination.limbs
    assert source.key!=destination.key and a<=source.limbs
    rows=[]
    for j in range(ring.gadget(a)):
        mask=coins.uniform('hint/'+name+f'/{j}/a',a)
        error=coins.error('hint/'+name+f'/{j}/e')
        noise=ring.lift(array('q',(2*x for x in error)),a)
        b=ring.add(ring.sub(noise,ring.point(mask,destination.spectra,a),a),ring.scale(payload,a,44*j),a)
        rows.append((b,mask))
    return Bank(source.key,destination.key,a,kind,tuple(rows))
