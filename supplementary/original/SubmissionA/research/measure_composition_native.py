"""Fixed V1 engineering screen; frozen correspondence modules stay unchanged."""
from array import array
from collections import defaultdict
from contextlib import contextmanager
from hashlib import sha256
from time import perf_counter
import json
import resource
import sys

from composition_optimized import OptimizedRing
from composition_fixture import inputs as fixture_inputs, metadata
from composition_full_run import (L,M,TAIL,CHAIN,Secret,Bundle,Coins,codec_setup,
    FastField,mixed_hasse,frobenius,encode_lanes,decode,keygen,encrypt,make_bank)
from composition_public_evaluator import evaluate_optimized,packet_schema,bank_catalog,PK_NAMES
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


def setup_keys(ring):
    coins=Coins(ring)
    profiles=[('s0',4),('s1',4)]
    for stage,r in enumerate(TAIL):profiles.extend([(f'h{r}',CHAIN[stage+1]),(f's{stage+2}',CHAIN[stage+1])])
    keys={}
    for name,a in profiles:
        coeff=coins.ternary('secret/'+name);keys[name]=Secret(name,a,coeff,ring.lift(coeff,a))
    pks={name:keygen(ring,coins,keys[name]) for name in ('s0','h8','h4','h2','h1')}
    banks={}
    pairs=[('prefix','s0','s1')]+[(f'product{r}',f'h{r}',f's{stage+2}') for stage,r in enumerate(TAIL)]
    for prefix,src,dst in pairs:
        a=keys[dst].limbs
        for kind in ('linear','quadratic'):
            payload=keys[src].spectra if kind=='linear' else ring.point(keys[src].spectra,keys[src].spectra,a)
            name=prefix+'_'+kind;banks[name]=make_bank(ring,coins,keys[src],keys[dst],payload,name,kind)
    for stage,r in enumerate(TAIL):
        src,dst,result=f's{stage+1}',f'h{r}',f's{stage+2}'
        for i in range(2*r):
            payload=array('q',[0])*M
            for t in range(L):
                target=(t+i)%L;sign=-1 if t+i>=L else 1
                if target&r:payload[(target-r)*256:(target-r+1)*256]=array('q',(sign*x for x in keys[src].coefficients[t*256:(t+1)*256]))
            name=f'h{r}_{i}';banks[name]=make_bank(ring,coins,keys[src],keys[dst],ring.lift(payload,keys[dst].limbs),name,f'H{r}(t^{i}s)')
        name=f'align{r}';banks[name]=make_bank(ring,coins,keys[src],keys[result],keys[src].spectra,name,'linear')
    assert len(banks)==44 and sum(len(b.rows) for b in banks.values())==203
    return keys,pks,banks


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


def main():
    assert sys.argv[1:]==['--screen-v1']
    total_start=perf_counter();setup=defaultdict(float)
    with phase(setup,'public_context_codec'):
        ring=OptimizedRing();_,_,_,_,rows,inverse=codec_setup();field=FastField()
    with phase(setup,'keys_hints'):keys,pks,banks=setup_keys(ring)
    with phase(setup,'public_key_serialization'):
        arrays=[x for name,*_ in bank_catalog() for row in banks[name].rows for x in row]
        arrays.extend(x for name in PK_NAMES for x in pks[name].components)
        key_serialized=serialize(ring,'keys',arrays);del arrays
    print(json.dumps(dict(event='native_measurement_setup_complete',seconds=dict(setup))),flush=True)
    fs,gs=fixture_inputs();flat_f=array('H',(x for v in fs for x in v));flat_g=array('H',(x for v in gs for x in v))
    oracle=ring.series(flat_f,flat_g,L,horner=True)
    assert sha256(oracle.tobytes()).hexdigest()=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
    batches=[]
    for index in range(2):
        batch_start=perf_counter();times=defaultdict(float)
        lanes=owner_inputs(ring,field,fs,gs,times)
        with phase(times,'codec'):plain={name:encode_lanes(value,inverse) for name,value in lanes.items()}
        with phase(times,'encryption'):
            coins=Coins(ring)
            inputs={name:encrypt(ring,coins,pks['h'+name[1:] if name.startswith('u') else 's0'],plain[name],name) for name in lanes}
        public=Bundle(inputs,banks,tuple(pks.values()))
        with phase(times,'serialization'):
            input_serialized=serialize(ring,'inputs',[x for ct in inputs.values() for x in ct.components])
        with phase(times,'evaluation'):trace=evaluate_optimized(ring,public);result=trace[-1]
        with phase(times,'serialization'):output_serialized=serialize(ring,'output',list(result.components))
        with phase(times,'decryption_codec'):recovered=decrypt(ring,result,keys['s5'],rows)
        batch_wall=perf_counter()-batch_start
        with phase(times,'verification'):assert recovered==oracle
        batch=dict(index=index,state='cold' if index==0 else 'warm',seconds=dict(times),
            batch_wall_seconds=batch_wall,output_symbols=4096,
            output_sha256=sha256(recovered.tobytes()).hexdigest(),
            input_bytes_raw=sum(len(x)*8 for ct in inputs.values() for x in ct.components),
            output_bytes_raw=sum(len(x)*8 for x in result.components),
            input_bytes_serialized=input_serialized,output_bytes_serialized=output_serialized,
            fresh_encryptions=len(inputs),diagnostic_states_retained=len(trace))
        batches.append(batch)
        print(json.dumps(dict(event='native_measurement_batch_complete',batch=batch)),flush=True)
        del trace,result,recovered,public,inputs,plain,lanes
    hints=sum(len(x)*8 for bank in banks.values() for row in bank.rows for x in row)
    pksize=sum(len(x)*8 for ct in pks.values() for x in ct.components)
    assert (hints,pksize)==(754<<20,17<<20)
    print(json.dumps(dict(status='MATCHED_SCREEN_NATIVE_PASS',arm='native',fixture=metadata(),
        setup_seconds=dict(setup),batches=batches,hint_bytes_raw=hints,public_key_bytes_raw=pksize,
        public_key_including_hints_bytes_serialized=key_serialized,
        peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        process_wall_seconds=perf_counter()-total_start,worker_threads=1,
        arithmetic_profile=dict(dimension=M,chain=list(CHAIN),width=48),
        serializer='fixed-schema public uint64 frames and SHA256 into counting sink; no network',
        process_isolation=False,security_bits=None,bootstrapping=False)),flush=True)
    ring.close()


if __name__=='__main__':main()
