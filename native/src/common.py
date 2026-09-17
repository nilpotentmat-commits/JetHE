from array import array
from pathlib import Path
import stage_public as native
from fixed_crypto import SlimRing
from fixed_binding import SlimRingBase
from fast_crypto_v1 import encrypt
from composition_full_run import Secret,Cipher,Bundle,Coins,keygen,encode_lanes,codec_setup,decode
from measure_composition_native import owner_inputs,FastField,fixture_inputs
from paid_hasse_experiment_v1 import expected_states,check_phase
from bounds import FRESH as NATIVE_FRESH
from interpolation import Interpolation
from prepare import outer_prepare,inner_prepare,records,record_digest
from composition_wire import send
READY=Path(__file__).resolve().parents[1]
EXPECTED_PATH=READY/"fixtures/expected.bin"
N=65536
NATIVE_Q=1152921504002872321*1152921503566671361
Q,F,BRAW=1152921504002872321,36636,1404684555427328
EXPECTED_SHA="d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3"

def public_product(ring,operands):
    """The same three-product raw multiplication at the admitted one limb."""
    f_left,f_right,g_left,g_right=operands
    assert all(ct.key=='root' and ct.limbs==1 and len(ct.components)==2 for ct in operands)
    a=tuple(ring.add(x,y,1) for x,y in zip(f_left.components,g_left.components))
    b=tuple(ring.add(x,y,1) for x,y in zip(f_right.components,g_right.components))
    low,high=ring.point(a[0],b[0],1),ring.point(a[1],b[1],1)
    middle=ring.sub(ring.sub(ring.point(ring.add(*a,1),ring.add(*b,1),1),low,1),high,1)
    return Cipher('root',1,(low,middle,high))


class SharedField(FastField):
    def __init__(self):
        super().__init__()
        # Public adapter only; inherited multiplication has no diagnostic counter.
        self.log,self.exp=self.logs,self.exponents


def decrypt(ring,ct,secret,square,rows,diagnostic=False):
    a=ct.limbs
    assert ct.key==secret.key and a in (1,2) and len(ct.components) in (2,3)
    phase=ring.add(ct.components[0],ring.point(ct.components[1],secret.spectra,a),a)
    if len(ct.components)==3:phase=ring.add(phase,ring.point(ct.components[2],square,a),a)
    residues=[ring.transform(phase[j*N:(j+1)*N],j,True) for j in range(a)]
    q=ring.moduli[a]
    bits=bytearray(N)
    if a==1:
        for i,value in enumerate(residues[0]):
            bits[i]=(value-q if value>q//2 else value)&1
    else:
        p0,p1=ring.primes[:2]
        inv=pow(p0,-1,p1)
        for i,(left,right) in enumerate(zip(*residues)):
            value=left+p0*((right-left)*inv%p1)
            bits[i]=(value-q if value>q//2 else value)&1
    words=[sum(bits[i*256+e]<<e for e in range(256)) for i in range(256)]
    values=decode(words,rows)
    lanes=array('H',((values[j]>>(16*lane))&65535 for lane in range(16) for j in range(256)))
    return (lanes,phase,bits) if diagnostic else lanes


class CountSink:
    def __init__(self):self.bytes=0
    def write(self,data):self.bytes+=len(data);return len(data)
    def flush(self):pass


def serialize(kind,records):
    arrays=[]
    frames=[]
    for name,components in records:
        for part,value in enumerate(components):
            arrays.append(value)
            frames.append(dict(record=name,part=part,words=len(value)))
    sink=CountSink()
    receipt=send(sink,b'JETSW002',dict(version=1,profile='one-prime-workflow-v1',kind=kind,frames=frames),arrays)
    assert sink.bytes==receipt['wire_bytes']
    return dict(raw_bytes=receipt['payload_bytes'],wire_bytes=receipt['wire_bytes'],polynomials=len(arrays),ciphertexts=len(records))

