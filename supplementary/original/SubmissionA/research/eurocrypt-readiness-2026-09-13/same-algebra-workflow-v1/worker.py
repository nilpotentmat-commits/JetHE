"""Separate correctness gates and bounded whole-workflow measurement workers."""
from array import array
from collections import Counter,defaultdict
from contextlib import contextmanager
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import resource
from time import perf_counter
import traceback

from common import *


@contextmanager
def timed(times,name):
    start=perf_counter()
    try:yield
    finally:times[name]+=perf_counter()-start


def emit(event,**data):print(json.dumps(dict(event=event,**data)),flush=True)


class Worker:
    def __init__(self,mode,arm,index):
        self.mode,self.arm,self.index=mode,arm,index
        self.gate=mode=='gate'
        self.setup_times=defaultdict(float)
        self.material={}
        self.checked_states=0
        self.checked_coefficients=0
        self.ring=None

    def setup(self):
        start=perf_counter()
        with timed(self.setup_times,'public_context_codec'):
            self.ring=SlimRing() if self.arm=='native' else SlimRingBase(256,2)
            _,_,_,_,self.rows,self.inverse=codec_setup()
            self.field=SharedField()
            assert self.ring.moduli[2]==Q
            if self.arm=='control':
                self.interpolation=Interpolation(self.field)
                self.records=records(16,256)
                assert len(self.records)==175776
        with timed(self.setup_times,'keys_and_hints'):
            coins=Coins(self.ring)
            if self.arm=='native':
                self.keys,self.pks,self.banks=native.setup(self.ring,coins)
            else:
                coeff=coins.ternary('secret/root')
                secret=Secret('root',2,coeff,self.ring.lift(coeff,2))
                self.keys={'root':secret}
                self.pks={'root':keygen(self.ring,coins,secret)}
                self.banks={}
            self.secret=self.keys['h1' if self.arm=='native' else 'root']
        with timed(self.setup_times,'recipient_key_preparation'):
            self.square=self.ring.point(self.secret.spectra,self.secret.spectra,2)
        with timed(self.setup_times,'public_material_serialization'):
            rec=[(name+'/'+str(j),row) for name,bank in self.banks.items() for j,row in enumerate(bank.rows)]
            rec.extend((name,pk.components) for name,pk in self.pks.items())
            self.public_wire=serialize('public',rec)
        self.material=dict(independent_secrets=len(self.keys),public_keys=len(self.pks),
            evaluation_rows=sum(len(b.rows) for b in self.banks.values()),
            setup_error_vectors=coins.errors,setup_small_vectors=len(self.keys)+coins.errors,
            public_material_raw_bytes=self.public_wire['raw_bytes'],
            public_material_serialized_bytes=self.public_wire['wire_bytes'],
            constructed_linear_buffers_bytes=16384+(len(self.ring.public_t)*8 if self.arm=='native' else
                sum(len(a)*a.itemsize for a in (self.interpolation.inverse_flat,self.interpolation.evaluation_flat,self.interpolation.logs,self.interpolation.exps))))
        assert self.material['public_material_raw_bytes']==(391 if self.arm=='native' else 2)<<20
        assert coins.errors==(139 if self.arm=='native' else 1)
        self.setup_wall=perf_counter()-start
        del coins,rec
        emit('setup_complete',arm=self.arm,index=self.index,setup_wall_seconds=self.setup_wall,material=self.material)

    def wire(self,totals,times,kind,records):
        with timed(times,'serialization'):
            result=serialize(kind,records)
            for key,value in result.items():totals[kind+'_'+key]+=value

    def check(self,ct,key,bits,bound):
        self.checked_coefficients+=check_phase(self.ring,ct,key,bits,bound)
        self.checked_states+=1

    def native_batch(self,fs,gs):
        times=defaultdict(float);totals=Counter()
        begin=perf_counter()
        lanes=owner_inputs(self.ring,self.field,fs,gs,times)
        with timed(times,'native_input_codec'):
            plaintext={name:encode_lanes(value,self.inverse) for name,value in lanes.items()}
        with timed(times,'encryption'):
            coins=Coins(self.ring)
            inputs={name:encrypt(self.ring,coins,self.pks['h'+name[1:] if name.startswith('u') else 's0'],bits,name)
                    for name,bits in plaintext.items()}
        self.wire(totals,times,'input',[(name,ct.components) for name,ct in inputs.items()])
        public=Bundle(inputs,self.banks,tuple(self.pks.values()))
        with timed(times,'evaluation'):
            evaluated=native.evaluate(self.ring,public,self.gate)
            result=evaluated[-1] if self.gate else evaluated
        self.wire(totals,times,'output',[('tail1',result.components)])
        with timed(times,'recipient_decryption_native_codec'):
            recovered=decrypt(self.ring,result,self.secret,self.square,self.rows)
        wall=perf_counter()-begin
        assert coins.errors==70
        if self.gate:
            expected,answer=expected_states(self.ring,lanes,self.inverse)
            assert recovered==answer
            for name,ct in inputs.items():self.check(ct,self.keys[ct.key],plaintext[name],NATIVE_FRESH)
            for ct,(name,key,a,arity,bound) in zip(evaluated,native.spec(self.ring)):
                assert (ct.key,ct.limbs,len(ct.components))==(key,a,arity)
                self.check(ct,self.keys[key],expected[name],bound)
        return recovered,dict(times),dict(totals),wall,dict(fresh_encryptions=35,small_vectors=105,error_vectors=70,ciphertext_products=19)

    def control_batch(self,fs,gs):
        times=defaultdict(float);totals=Counter()
        begin=perf_counter()
        with timed(times,'owner_f'):outer=outer_prepare(fs,self.records,self.field)
        with timed(times,'owner_g'):inner=inner_prepare(gs,self.records,self.field)
        coins=Coins(self.ring)
        sums=array('H',[0])*4096
        for chunk in range(86):
            with timed(times,'owner_interpolation'):
                lanes=[self.interpolation.encode(v[chunk*2048:(chunk+1)*2048]) for v in (outer[0],outer[1],inner[0],inner[1])]
            with timed(times,'native_input_codec'):plaintext=[encode_lanes(v,self.inverse) for v in lanes]
            with timed(times,'encryption'):
                operands=[encrypt(self.ring,coins,self.pks['root'],bits,f'pair/{chunk}/{i}') for i,bits in enumerate(plaintext)]
            self.wire(totals,times,'input',[(f'pair/{chunk}/{i}',ct.components) for i,ct in enumerate(operands)])
            with timed(times,'evaluation'):ct=public_product(self.ring,operands)
            self.wire(totals,times,'output',[(f'pair/{chunk}',ct.components)])
            with timed(times,'recipient_decryption_native_codec'):
                value=decrypt(self.ring,ct,self.secret,self.square,self.rows,self.gate)
                recovered=value[0] if self.gate else value
            with timed(times,'recipient_evaluation'):
                products=self.interpolation.decode(recovered)
                for at,x in enumerate(products):
                    pos=chunk*2048+at
                    if pos<len(self.records):
                        job,j,_,_=self.records[pos]
                        sums[job*256+j]^=x
            if self.gate:
                for op,bits in zip(operands,plaintext):self.check(op,self.secret,bits,F)
                left=array('H',(a^b for a,b in zip(lanes[0],lanes[2])))
                right=array('H',(a^b for a,b in zip(lanes[1],lanes[3])))
                want=self.ring.series(left,right,256)
                bits=encode_lanes(want,self.inverse)
                assert recovered==want and value[2]==bits
                assert self.ring.phase_check(value[1],bits,BRAW,2)<=BRAW
                self.checked_coefficients+=N;self.checked_states+=1
            del operands,plaintext,lanes,ct,recovered,value,products
        for owner,values in (('outer',outer[2]),('inner',inner[2])):
            with timed(times,'native_input_codec'):bits=encode_lanes(values,self.inverse)
            with timed(times,'encryption'):ct=encrypt(self.ring,coins,self.pks['root'],bits,'bypass/'+owner)
            self.wire(totals,times,'input',[('bypass/'+owner,ct.components)])
            self.wire(totals,times,'output',[('bypass/'+owner,ct.components)])
            with timed(times,'recipient_decryption_native_codec'):
                value=decrypt(self.ring,ct,self.secret,self.square,self.rows,self.gate)
                recovered=value[0] if self.gate else value
            with timed(times,'recipient_evaluation'):
                sums=array('H',(a^b for a,b in zip(sums,recovered)))
            if self.gate:
                assert recovered==values and value[2]==bits
                self.check(ct,self.secret,bits,F)
                assert self.ring.phase_check(value[1],bits,F,2)<=F
                self.checked_coefficients+=N;self.checked_states+=1
        wall=perf_counter()-begin
        assert coins.errors==692 and len(coins.domains)==1038
        return sums,dict(times),dict(totals),wall,dict(fresh_encryptions=346,small_vectors=1038,error_vectors=692,ciphertext_products=86)

    def run(self):
        self.setup()
        fs,gs=fixture_inputs()
        # Public oracle calculation/fixture construction are outside both timers.
        expected=array('H');expected.frombytes((READY/'compiled-receiver-v1/expected.bin').read_bytes())
        assert sha256(expected.tobytes()).hexdigest()==EXPECTED_SHA
        batches=[]
        for i in range(1 if self.gate else 2):
            recovered,times,wire,wall,counts=(self.native_batch if self.arm=='native' else self.control_batch)(fs,gs)
            assert recovered==expected
            record=dict(index=i,state='gate' if self.gate else 'cold' if i==0 else 'warm',
                batch_wall_seconds=wall,seconds=times,wire=wire,counts=counts,
                output_symbols=len(recovered),output_sha256=sha256(recovered.tobytes()).hexdigest())
            batches.append(record)
            emit('batch_complete',arm=self.arm,index=self.index,batch=record)
            del recovered
        if self.gate:
            assert self.checked_states==(57 if self.arm=='native' else 434)
            assert self.checked_coefficients==N*self.checked_states
        else:assert self.checked_states==self.checked_coefficients==0
        return dict(status='SAME_ALGEBRA_WORKFLOW_GATE_PASS' if self.gate else 'SAME_ALGEBRA_WORKFLOW_WORKER_PASS',
            arm=self.arm,mode=self.mode,index=self.index,setup_wall_seconds=self.setup_wall,
            setup_seconds=dict(self.setup_times),material=self.material,batches=batches,
            phase_checked_states=self.checked_states,phase_checked_coefficients=self.checked_coefficients,
            peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            worker_threads=len(list(Path('/proc/self/task').iterdir())),affinity=sorted(os.sched_getaffinity(0)),
            encrypted_execution=True,security_bits=None,shared_field_backend='check_fused_composition_frontier.FastField',
            timing_claim='Instrumented gate only' if self.gate else 'Common complete local workflow; startup and physical transport excluded')


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--supervised',required=True,action='store_true')
    p.add_argument('--mode',required=True,choices=('gate','measure'))
    p.add_argument('--arm',required=True,choices=('native','control'))
    p.add_argument('--index',required=True,type=int)
    args=p.parse_args()
    assert os.sched_getaffinity(0)=={0}
    assert all(os.environ.get(k)=='1' for k in THREAD_VARIABLES)
    for key,value in ((resource.RLIMIT_AS,LIMITS['address_space_bytes']),(resource.RLIMIT_CPU,LIMITS['cpu_seconds']),(resource.RLIMIT_CORE,0)):
        assert resource.getrlimit(key)==(value,value)
    before=source_manifest();runtime_before=runtime_manifest()
    verify_admission()
    worker=Worker(args.mode,args.arm,args.index)
    try:
        result=worker.run()
        assert source_manifest()==before and runtime_manifest()==runtime_before
        result.update(source_bindings_before=before,source_bindings_after=source_manifest(),runtime_bindings=runtime_before)
        emit('result',result=result)
    except BaseException as exc:
        emit('failure',status='SAME_ALGEBRA_WORKFLOW_WORKER_FAILURE',error_type=type(exc).__name__,
             frames=[dict(file=Path(f.filename).name,line=f.lineno,function=f.name) for f in traceback.extract_tb(exc.__traceback__)])
        raise SystemExit(1)
    finally:
        if worker.ring:worker.ring.close()


if __name__=='__main__':main()
