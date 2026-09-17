"""Same sampler, explicit stage gadgets and unchanged creation moduli."""
from array import array
import ctypes as C
from fast_crypto_v1 import FastTerminalRing
from fixed_binding import SlimRingBase
from bounds import WIDTH_BY_VERTEX
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
    def gadget(self,limbs,width):
        assert width in (40,45,60) and 1<=limbs<=self.limbs
        return (self.moduli[limbs].bit_length()+width-1)//width
    def digits(self,spectrum,limbs,width):
        assert width in (40,45,60)
        out=array('q',[0])*(self.gadget(limbs,width)*self.dimension)
        self.call('jc_digits',self.handle,self.spectrum(spectrum,limbs),pointer(out,'q'),limbs,width)
        v=memoryview(out)
        return [v[j*self.dimension:(j+1)*self.dimension] for j in range(self.gadget(limbs,width))]

def make_bank(ring,coins,source,destination,payload,name,kind):
    a=destination.limbs
    width=WIDTH_BY_VERTEX[destination.key]
    assert source.key!=destination.key and a<=source.limbs
    rows=[]
    for j in range(ring.gadget(a,width)):
        mask=coins.uniform('hint/'+name+f'/{j}/a',a)
        error=coins.error('hint/'+name+f'/{j}/e')
        noise=ring.lift(array('q',(2*x for x in error)),a)
        b=ring.add(ring.sub(noise,ring.point(mask,destination.spectra,a),a),ring.scale(payload,a,width*j),a)
        rows.append((b,mask))
    return Bank(source.key,destination.key,a,kind,tuple(rows))

# Explicit stage width; the linear/quadratic bank evaluator is otherwise unchanged.
from composition_full_run import external,Cipher
def relin(ring,raw,linear,quadratic):
    assert len(raw.components)==3 and (linear.payload,quadratic.payload)==('linear','quadratic')
    assert (linear.source,linear.destination,linear.limbs)==(quadratic.source,quadratic.destination,quadratic.limbs)
    assert (raw.key,raw.limbs)==(linear.source,linear.limbs)
    a=raw.limbs;w=WIDTH_BY_VERTEX[linear.destination]
    one=external(ring,linear,ring.digits(raw.components[1],a,w),raw.key)
    two=external(ring,quadratic,ring.digits(raw.components[2],a,w),raw.key)
    return Cipher(linear.destination,a,(ring.add(raw.components[0],ring.add(one[0],two[0],a),a),ring.add(one[1],two[1],a)))
