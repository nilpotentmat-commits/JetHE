"""Public one-prime conformance and exact current-source accounting; no HE timing."""
from array import array
from collections import Counter
from fractions import Fraction
import json
from math import prod
import os
from random import Random
import resource
from run import HERE,READY,ROOT,FIXED,imports,manifest,admission,binding,save

def main():
    assert not (HERE/'preflight.json').exists()
    resource.setrlimit(resource.RLIMIT_AS,(2<<30,)*2)
    resource.setrlimit(resource.RLIMIT_CPU,(180,)*2)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.sched_setaffinity(0,{0})
    driver,common,_,_=imports();frozen=manifest(driver,common);libraries=driver.runtime(common)
    admission(common)
    from slim_ring_base_v2 import SlimRingBase as Old
    from fixed_binding import SlimRingBase as Current
    from fast_crypto_v1 import encrypt
    from composition_full_run import Cipher
    from bounds import PRIMES
    # Ensure adapter changes exactly the one declared context expression.
    original=(READY/'same-algebra-one-prime-workflow-v1/worker.py').read_text()
    expected=original[original.index('    def setup(self):'):original.index('    def wire(')]
    expected=expected.replace("SlimRing() if self.arm=='native' else SlimRingBase(256,1)","CurrentRingBase(256,1)")
    actual=(HERE/'adapter.py').read_text();assert actual[actual.index('    def setup(self):'):]==expected
    old,new=Old(256,1),Current(256,1)
    counts=Counter();rng=Random(2026091503);n=65536;p=PRIMES[0]
    def equal(a,b,family):
        assert a==b,family
        counts[family]+=len(a) if hasattr(a,'__len__') else 1
    try:
        assert old.moduli==new.moduli==[1,p]
        assert new.dimension==old.dimension==n
        assert str(new.dll._name)==str(FIXED/'build/fixed_core.so')
        limit=((1<<64)//p)*p
        words=array('Q',[0,1,2,(1<<64)-1,(1<<64)-2,(1<<40)-1,1<<40,limit-1,limit,limit+1])
        words.extend(rng.getrandbits(64) for _ in range(10000))
        for kind,prime in ((0,0),(1,0),(2,p)):
            equal(old.sample_words(words,len(words),kind,prime),new.sample_words(words,len(words),kind,prime),'sampler_results')
        for length in (1,2,4,8,16,32,64,128,256):
            v=array('Q',(rng.randrange(p) for _ in range(length*256)))
            for inverse in (False,True):equal(old.transform(v,0,inverse,length),new.transform(v,0,inverse,length),'transform_words')
            equal(new.transform(new.transform(v,0,False,length),0,True,length),v,'roundtrip_words')
        coeff=array('q',((i*7919)%(1<<24)-(1<<23) for i in range(n)))
        x=old.lift(coeff,1);y=new.lift(coeff,1);equal(x,y,'lift_words')
        z=array('Q',(rng.randrange(p) for _ in range(n)))
        equal(old.point(x,z,1),new.point(y,z,1),'point_words')
        equal(new.point(y,z,1),array('Q',(a*b%p for a,b in zip(y,z))),'point_integer_oracle_words')
        for name in ('add','sub'):equal(getattr(old,name)(x,z,1),getattr(new,name)(y,z,1),name+'_words')
        bits=bytearray(i%2 for i in range(n));errors=[i%73-36 for i in range(n)]
        phase=new.lift(array('q',(m+2*e for m,e in zip(bits,errors))),1)
        equal(old.phase_check(phase,bits,36,1),new.phase_check(phase,bits,36,1),'phase_checks')
        u=array('q',(i%3-1 for i in range(n)))
        e0=array('q',(i%41-20 for i in range(n)));e1=array('q',((i*17)%41-20 for i in range(n)))
        class PublicCoins:
            def ternary(self,label):return u
            def error(self,label):return e0 if label.endswith('e0') else e1
        pk=Cipher('public_fixture',1,tuple(array('Q',(rng.randrange(p) for _ in range(n))) for _ in range(2)))
        a=encrypt(old,PublicCoins(),pk,bits,'fixture');b=encrypt(new,PublicCoins(),pk,bits,'fixture')
        for x,y in zip(a.components,b.components):equal(x,y,'explicit_coin_encryption_words')
        operands=[Cipher('root',1,a.components),Cipher('root',1,b.components)]*2
        for x,y in zip(common.public_product(old,operands).components,common.public_product(new,operands).components):equal(x,y,'control_raw_product_words')
        f=array('H',(rng.randrange(65536) for _ in range(4096)))
        g=array('H',(rng.randrange(65536) for _ in range(4096)))
        equal(old.series(f,g,256),new.series(f,g,256),'control_gate_series_symbols')
    finally:old.close();new.close()
    stage=driver.read(READY/'native-stage-gadgets-v1/admission.json')
    control=driver.read(READY/'same-algebra-one-prime-v1/admission.json')
    assert prod(PRIMES)%p==0 and 2<=37
    assert sum(stage['incoming_rows'])==107 and max(stage['incoming_rows'])==37
    factors=dict(native=2*(9+35*2),control=2*(1+346*2));assert factors==dict(native=158,control=1386)
    budgets=dict(native=n*(8*(297+79)+247),control=n*(17+3460*2))
    assert budgets==dict(native=213319680,control=454623232)
    assert p>2+4*control['raw_cap']
    rho=Fraction((1<<64)%p,1<<64)
    stop=n*(rho**8+Fraction(1+346*2,1<<512))
    assert stop<Fraction(1,1<<222)
    # Equal projection fibers and exact unit-normalization on a small modulus.
    fibers=Counter(x%5 for x in range(35));assert set(fibers.values())=={7}
    for s in (-1,0,1):
        for e in range(-20,21):
            for a in range(35):
                assert ((a*s+e)%35)%5==((a%5)*(s%5)+e)%5
                assert ((2*(a*s+e))%35)%5==(2*((a%5)*(s%5)+e))%5
                counts['toy_projection_normalization_cases']+=1
    v=driver.read(FIXED/'verification.json')
    assert len(v['source_bindings'])==155
    for name,want in v['source_bindings'].items():assert binding(ROOT/name)==want,name
    assert manifest(driver,common)==frozen and driver.runtime(common)==libraries
    result=dict(status='CURRENT_CONTROL_PREFLIGHT_PASS',counts=dict(counts),source_manifest=frozen,runtime_manifest=libraries,unchanged_native_source_files=155,source='q3/37 -> p0/2',two_batch_source_gap_factors=factors,two_batch_honest_word_budgets=budgets,control_stopped_source_strict_exponent=222,common_source_gap_example='1/5544 for scheme gap 1/4 with zero delta at max simulator time',new_he_execution=False,new_timing=False,security_bits=None)
    save(HERE/'preflight.json',result)
    print(json.dumps({k:v for k,v in result.items() if k not in ('source_manifest','runtime_manifest')}),flush=True)

if __name__=='__main__':main()
