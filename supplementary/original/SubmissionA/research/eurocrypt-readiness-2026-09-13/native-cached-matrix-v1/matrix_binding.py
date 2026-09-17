"""Own an immutable public matrix cache; retain the original HE backend."""
import ctypes as C
from hashlib import sha256
from pathlib import Path
from composition_native import P,pointer

HERE=Path(__file__).resolve().parent
LIBRARY=HERE/'build/matrix.so'


class CachedMatrix:
    def __init__(self,ring,banks,arm):
        assert arm in ('residue','quotient')
        self.ring=ring;self.arm=arm;self.handle=None
        self.dll=C.CDLL(str(LIBRARY))
        for name,args,result in (
            ('jet_matrix_error',[],C.c_char_p),('jet_matrix_create',[P,C.c_uint,C.c_size_t,C.c_uint],P),
            ('jet_matrix_destroy',[P],None),('jet_matrix_data',[P],P),('jet_matrix_words',[P],C.c_size_t),
            ('jet_matrix_apply',[P,P,C.c_uint,C.c_size_t,P,C.c_uint,C.c_uint],C.c_int),
            ('jet_matrix_mul_check',[P,P,P,C.c_size_t,C.c_uint,C.c_uint],C.c_int)):
            fn=getattr(self.dll,name);fn.argtypes=args;fn.restype=result
        rows=[]
        for i in range(9):
            bank=banks[f'h8_{i}' if i<8 else 'h8_identity']
            assert (bank.source,bank.destination,bank.limbs)==('s1','h8',3) and len(bank.rows)==4
            rows.extend(v for row in bank.rows for v in row)
        self._rows=tuple(rows)
        self._pointers=(P*72)(*(C.cast(ring.spectrum(v,3),P).value for v in rows))
        self.handle=self.dll.jet_matrix_create(self._pointers,72,3*ring.dimension,int(arm=='quotient'))
        assert self.handle,self.dll.jet_matrix_error().decode()
        self.words=self.dll.jet_matrix_words(self.handle)
        assert self.words*8==(336 if arm=='residue' else 672)*(1<<20)

    def close(self):
        if self.handle:self.dll.jet_matrix_destroy(self.handle);self.handle=None

    def digest(self):
        assert self.handle
        data=self.dll.jet_matrix_data(self.handle)
        return sha256((C.c_ubyte*(self.words*8)).from_address(data)).hexdigest()

    def apply(self,compact):
        assert self.handle and 1<=len(compact)<=16
        B=len(compact);assert all(len(row)==4 for row in compact)
        inputs=[v for row in compact for v in row]
        outputs=[self.ring.zeros(3) for _ in range(2*B)]
        ins=(P*len(inputs))(*(C.cast(self.ring.spectrum(v,3),P).value for v in inputs))
        outs=(P*len(outputs))(*(C.cast(self.ring.spectrum(v,3),P).value for v in outputs))
        code=self.dll.jet_matrix_apply(self.handle,ins,len(inputs),3*self.ring.dimension,outs,len(outputs),B)
        assert code==0,f'matrix apply error {code}'
        return [tuple(outputs[2*b:2*b+2]) for b in range(B)]
