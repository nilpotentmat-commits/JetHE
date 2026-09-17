from array import array
from collections import defaultdict
from contextlib import contextmanager
from time import perf_counter
from composition_fixture import inputs as fixture_inputs,metadata
from composition_full_run import *
from composition_public_evaluator import bank_catalog,packet_schema,PK_NAMES
from composition_wire import send

@contextmanager
def phase(times,name):
    start=perf_counter()
    try: yield
    finally: times[name]+=perf_counter()-start


class CountSink:
    def __init__(self):self.bytes=0
    def write(self,data):self.bytes+=len(data);return len(data)
    def flush(self):pass


def serialize(ring,kind,arrays):
    schema=packet_schema(ring,response=kind=='output')
    def selected(frame):
        name=frame['record'][0]
        return name=='tail1' if kind=='output' else name.startswith('input/') if kind=='inputs' else not name.startswith('input/')
    schema=dict(schema,packet_kind=kind,frames=[f for f in schema['frames'] if selected(f)])
    sink=CountSink();receipt=send(sink,b'JETMV001',schema,arrays)
    assert sink.bytes==receipt['wire_bytes']
    return receipt['wire_bytes']


def owner_inputs(ring,field,fs,gs,times):
    lanes={}
    with phase(times,'owner_f'):
        for mask in range(16):lanes[f'f{mask}']=array('H',(x for lane in range(16) for x in mixed_hasse(fs[lane],mask*16)))
    with phase(times,'owner_g'):
        u={}
        for j in range(8):
            value=array('H',(x for lane in range(16) for x in frobenius(gs[lane],j,field)))
            for lane in range(16):value[lane*L+(1<<j)]^=1
            u[1<<j]=value
        for mask in range(1,16):
            bit=mask&-mask;r=16*bit
            lanes[f'w{mask}']=u[r] if mask==bit else ring.series(lanes[f'w{mask^bit}'],u[r],L)
        for r in TAIL:lanes[f'u{r}']=u[r]
    return lanes


def decrypt(ring,ct,secret,rows):
    assert ct.limbs==2 and ct.key==secret.key
    phase_spectrum=ring.add(ct.components[0],ring.point(ct.components[1],secret.spectra,2),2)
    residues=[ring.transform(phase_spectrum[j*M:(j+1)*M],j,True) for j in range(2)]
    p0,p1=ring.primes[:2];q=p0*p1;inverse=pow(p0,-1,p1)
    bits=bytearray(M)
    for i,(a,b) in enumerate(zip(*residues)):
        x=a+p0*((b-a)*inverse%p1)
        bits[i]=(x-q if x>q//2 else x)&1
    words=[sum(bits[i*256+e]<<e for e in range(256)) for i in range(L)]
    decoded=decode(words,rows)
    return array('H',((decoded[j]>>(16*lane))&65535 for lane in range(16) for j in range(L)))

