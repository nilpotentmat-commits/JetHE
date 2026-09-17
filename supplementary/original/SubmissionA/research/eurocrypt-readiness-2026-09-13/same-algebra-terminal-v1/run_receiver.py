"""Fresh bounded same-algebra control. Diagnostic execution is not a benchmark.

Protocol evaluation accepts ciphertexts and public context only. Owner helpers
accept only their own fixture. Private validation never enters the public wire.
"""
from array import array
from collections import Counter,defaultdict
from contextlib import contextmanager
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import platform
import resource
import sys
from time import perf_counter
import traceback

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
RESEARCH=HERE.parents[1]
FAST=RESEARCH/'jethe-throughput-redesign-2026-09-13'
sys.path[:0]=[str(HERE),str(FAST),str(RESEARCH),str(HERE.parent/'paired-terminal-receiver-v1')]
from admission import bindings as admission_bindings, binding, Q, F, BRAW, N
from interpolation import Field, Interpolation
from prepare import composition_fixture, outer_prepare, inner_prepare, records, record_digest, expected_values
from slim_ring_base_v2 import SlimRingBase
from fast_crypto_v1 import encrypt
from composition_full_run import Secret, Cipher, Coins, keygen, encode_lanes, codec_setup, decode
from composition_wire import send


def public_product(ring,operands):
    """Four ciphertexts; no owner input, secret, source or diagnostic callback."""
    f_left,f_right,g_left,g_right=operands
    assert all(ct.key=='root' and ct.limbs==2 and len(ct.components)==2 for ct in operands)
    a=tuple(ring.add(x,y,2) for x,y in zip(f_left.components,g_left.components))
    b=tuple(ring.add(x,y,2) for x,y in zip(f_right.components,g_right.components))
    low,high=ring.point(a[0],b[0],2),ring.point(a[1],b[1],2)
    middle=ring.sub(ring.sub(ring.point(ring.add(*a,2),ring.add(*b,2),2),low,2),high,2)
    return Cipher('root',2,(low,middle,high))


class Sink:
    def __init__(self):self.bytes=0;self.hash=sha256()
    def write(self,data):self.bytes+=len(data);self.hash.update(data);return len(data)
    def flush(self):pass


class Run:
    def __init__(self,output,mode):
        self.output,self.mode=output,mode
        self.started=perf_counter()
        self.times=defaultdict(float)
        self.counts=Counter()
        self.payload=Counter()
        self.sinks={name:Sink() for name in ('public','input','output')}
        self.events=(output/'events.jsonl').open('x',buffering=1)

    @contextmanager
    def phase(self,name):
        start=perf_counter()
        try:yield
        finally:self.times[name]+=perf_counter()-start

    def event(self,stage,**extra):
        value=dict(stage=stage,wall_seconds=perf_counter()-self.started,counts=dict(self.counts),
                   peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,**extra)
        line=json.dumps(value,sort_keys=True)
        self.events.write(line+'\n');print(line,flush=True)

    def serialize(self,name,label,ct):
        with self.phase('serialization'):
            schema=dict(version=1,profile='same-algebra-paired-terminal-v1',kind=name,
                        frames=[dict(record=label,part=i,words=len(v)) for i,v in enumerate(ct.components)])
            result=send(self.sinks[name],b'JETSAV01',schema,ct.components)
            self.payload[name]+=sum(len(v)*8 for v in ct.components)
            self.counts[name+'_polynomials']+=len(ct.components)
            self.counts[name+'_ciphertexts']+=1

    def decrypt(self,ct):
        phase=self.ring.add(ct.components[0],self.ring.point(ct.components[1],self.secret.spectra,2),2)
        if len(ct.components)==3:
            phase=self.ring.add(phase,self.ring.point(ct.components[2],self.square,2),2)
        residues=[self.ring.transform(phase[j*N:(j+1)*N],j,True) for j in range(2)]
        p0,p1=self.ring.primes
        inverse=pow(p0,-1,p1)
        bits=bytearray(N)
        for i,(a,b) in enumerate(zip(*residues)):
            value=a+p0*((b-a)*inverse%p1)
            bits[i]=(value-Q if value>Q//2 else value)&1
        words=[sum(bits[i*256+e]<<e for e in range(256)) for i in range(256)]
        decoded=decode(words,self.rows)
        lanes=array('H',((decoded[j]>>(16*lane))&65535 for lane in range(16) for j in range(256)))
        return lanes,phase,bits

    def check(self,ct,bits,bound,phase=None):
        with self.phase('private_diagnostics'):
            if phase is None:
                phase=self.ring.add(ct.components[0],self.ring.point(ct.components[1],self.secret.spectra,2),2)
            assert self.ring.phase_check(phase,bits,bound,2)<=bound
            self.counts['phase_coefficients']+=N

    def make_input(self,lanes,label):
        with self.phase('native_input_codec'):mu=encode_lanes(lanes,self.inverse)
        with self.phase('encryption'):ct=encrypt(self.ring,self.coins,self.pk,mu,label)
        self.serialize('input',label,ct)
        self.check(ct,mu,F)
        return ct

    def execute(self):
        with self.phase('public_context_codec'):
            self.ring=SlimRingBase(256,2)
            assert self.ring.moduli[2]==Q
            _,_,_,_,self.rows,self.inverse=codec_setup()
            self.field=Field()
            self.interpolation=Interpolation(self.field)
        with self.phase('key_generation'):
            self.coins=Coins(self.ring)
            coeff=self.coins.ternary('secret/root')
            self.secret=Secret('root',2,coeff,self.ring.lift(coeff,2))
            self.pk=keygen(self.ring,self.coins,self.secret)
        with self.phase('recipient_key_preparation'):
            self.square=self.ring.point(self.secret.spectra,self.secret.spectra,2)
        self.serialize('public','root',self.pk)
        self.event('setup_complete')
        fs,gs=composition_fixture.inputs()
        length=4 if self.mode=='preflight' else 256
        fs,gs=[array('H',f[:length]) for f in fs],[array('H',g[:length]) for g in gs]
        public_records=records(16,length)
        self.field.products=0
        with self.phase('owner_outer'):
            outer=outer_prepare(fs,public_records,self.field)
        outer_products=self.field.products
        with self.phase('owner_inner'):
            inner=inner_prepare(gs,public_records,self.field)
        inner_products=self.field.products-outer_products
        with self.phase('private_diagnostics'):
            expected,oracle=expected_values(fs,gs)
        chunks=(len(public_records)+2047)//2048
        result=array('H',[0])*(16*length)
        raw_sum=array('H',[0])*(16*length)
        for chunk in range(chunks):
            with self.phase('owner_interpolation'):
                lanes=[self.interpolation.encode(v[chunk*2048:(chunk+1)*2048])
                       for v in (outer[0],outer[1],inner[0],inner[1])]
            operands=[self.make_input(v,f'pair/{chunk}/{i}') for i,v in enumerate(lanes)]
            with self.phase('evaluation'):ct=public_product(self.ring,operands)
            self.counts['ciphertext_products']+=1
            self.serialize('output',f'pair/{chunk}',ct)
            with self.phase('recipient_decryption_native_codec'):
                recovered,phase,bits=self.decrypt(ct)
            with self.phase('recipient_evaluation'):
                values=self.interpolation.decode(recovered)
                for at,value in enumerate(values):
                    pos=chunk*2048+at
                    if pos<len(public_records):
                        job,j,_,_=public_records[pos]
                        raw_sum[job*length+j]^=value
            with self.phase('private_diagnostics'):
                left=array('H',(a^b for a,b in zip(lanes[0],lanes[2])))
                right=array('H',(a^b for a,b in zip(lanes[1],lanes[3])))
                want=self.ring.series(left,right,256)
                want_bits=encode_lanes(want,self.inverse)
                assert recovered==want and bits==want_bits
            self.check(ct,want_bits,BRAW,phase)
            del operands,ct,lanes,recovered,phase,bits,left,right,want,want_bits
            if chunk%8==0 or chunk+1==chunks:self.event('products',completed=chunk+1,total=chunks)
        bypass=[]
        for owner,values in (('outer',outer[2]),('inner',inner[2])):
            lanes=array('H',[0])*4096
            lanes[:16*length]=values[:16*length]
            ct=self.make_input(lanes,'bypass/'+owner)
            self.serialize('output','bypass/'+owner,ct)
            with self.phase('recipient_decryption_native_codec'):
                recovered,phase,bits=self.decrypt(ct)
            with self.phase('private_diagnostics'):assert recovered==lanes
            self.check(ct,bits,F,phase)
            bypass.append(recovered[:16*length])
        with self.phase('recipient_evaluation'):
            result=array('H',(a^b^c for a,b,c in zip(raw_sum,*bypass)))
        with self.phase('private_diagnostics'):
            assert list(result)==expected
            missing_outer=sum(a^b!=c for a,b,c in zip(raw_sum,bypass[1],expected))
            missing_inner=sum(a^b!=c for a,b,c in zip(raw_sum,bypass[0],expected))
            assert missing_outer>0 and missing_inner>0
        raw=result.tobytes()
        (self.output/'recovered.bin').write_bytes(raw)
        inputs=4*chunks+2
        assert self.coins.errors==1+2*inputs
        assert len(self.coins.domains)==3*inputs+3 # secret, pk mask/error, three per input
        assert self.counts['input_ciphertexts']==inputs
        assert self.counts['output_ciphertexts']==chunks+2
        assert self.counts['phase_coefficients']==N*(inputs+chunks+2)
        workflow=sum(v for k,v in self.times.items() if k!='private_diagnostics')
        receipt=dict(status='SAME_ALGEBRA_TERMINAL_FULL_FUNCTIONAL_PASS' if self.mode=='full' else 'SAME_ALGEBRA_TERMINAL_PREFLIGHT_PASS',
            mode=self.mode,encrypted_execution=True,security_bits=None,matched_benchmark=False,
            jobs=16,length=length,field_polynomial='0x1100b',native_dimension=N,q=str(Q),
            scalar_pairs=len(public_records),records_sha256=record_digest(public_records),
            counts=dict(self.counts),source_vectors=3*inputs+2,error_vectors=self.coins.errors,
            output_symbols=len(result),recovered_sha256=sha256(raw).hexdigest(),oracle=oracle,
            missing_outer_correction_failures=missing_outer,missing_inner_correction_failures=missing_inner,
            owner_field_products=dict(outer=outer_products,inner=inner_products),
            phases=dict(self.times),complete_workflow_phase_seconds=workflow,
            instrumented_wall_seconds=perf_counter()-self.started,
            raw_payload_bytes=dict(self.payload),serialized_payload_bytes={k:v.bytes for k,v in self.sinks.items()},
            public_wire_sink='counting and hashing serialized frames; no network or ciphertext retention',
            peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            environment=dict(platform=platform.platform(),python=platform.python_version(),affinity=sorted(os.sched_getaffinity(0)),
                threads=len(list(Path('/proc/self/task').iterdir())),address_space_limit=resource.getrlimit(resource.RLIMIT_AS)[0],
                concurrent_other_HE_run=True),
            excluded_work='private phase/oracle diagnostics; initial compiler build; no network transport',
            protocol_scope='terminal recipient; evaluator-only privacy; no encrypted reentry')
        self.ring.close()
        return receipt


def input_bindings():
    paths={ROOT/p for p in admission_bindings()}
    paths.update(HERE/x for x in ('run_receiver.py','admission.json'))
    paths.update((HERE.parent/'compiled-receiver-v1/expected.bin',))
    for module in list(sys.modules.values()):
        filename=getattr(module,'__file__',None)
        if filename:
            path=Path(filename).resolve()
            if path.is_relative_to(ROOT) and path.suffix=='.py': paths.add(path)
    return {p.relative_to(ROOT).as_posix():binding(p) for p in sorted(paths)}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mode',choices=('preflight','full'),required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
    resource.setrlimit(resource.RLIMIT_CPU,(900,900))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.sched_setaffinity(0,{0})
    admission=json.loads((HERE/'admission.json').read_text())
    assert admission['status']=='SAME_ALGEBRA_TERMINAL_ADMISSION_CHECKS_PASS'
    assert admission['bindings_before']==admission['bindings_after']==admission_bindings()
    before=input_bindings()
    output=args.output.resolve()
    assert output.parent==HERE
    output.mkdir(exist_ok=False)
    run=Run(output,args.mode)
    try:
        result=run.execute()
        result.update(bindings_before=before,bindings_after=input_bindings())
        assert result['bindings_before']==result['bindings_after']
        (output/'run.json').write_text(json.dumps(result,indent=2)+'\n')
        run.event('complete',status=result['status'])
    except BaseException as exc:
        # Do not print sampled values, private phases or exception locals.
        value=dict(status='SAME_ALGEBRA_TERMINAL_EXECUTION_FAILURE',error_type=type(exc).__name__,
            frames=[dict(file=Path(f.filename).name,line=f.lineno,function=f.name) for f in traceback.extract_tb(exc.__traceback__)])
        (output/'failure.json').write_text(json.dumps(value,indent=2)+'\n')
        print(json.dumps(value),flush=True)
        raise SystemExit(1)
    finally:run.events.close()


if __name__=='__main__':main()
