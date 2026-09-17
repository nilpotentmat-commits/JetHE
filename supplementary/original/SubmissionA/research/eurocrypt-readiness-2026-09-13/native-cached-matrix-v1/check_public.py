"""Frozen sixteen-batch public screen. No secret or encryption coins sampled."""
from array import array
from collections import Counter
import ctypes as C
from hashlib import sha256
from pathlib import Path
from random import Random
from statistics import median
from time import perf_counter
import json,os,resource,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;READY=HERE.parent;ROOT=HERE.parents[3]
FIXED=READY/'native-fixed-multipliers-v1';STAGE=READY/'native-stage-gadgets-v1'
sys.path.insert(0,str(READY/'same-algebra-one-prime-workflow-v1'))
import common
sys.path[:0]=[str(HERE),str(FIXED),str(STAGE)]
from fixed_crypto import SlimRing
from composition_full_run import Cipher,Bank,Bundle,assert_public
from composition_native import P,pointer
from matrix_binding import CachedMatrix,LIBRARY
from group_public import evaluate_group
import stage_public
ORDER=('baseline','residue','quotient','quotient','residue','baseline','baseline','residue','quotient')


def binding(p):
    d=p.read_bytes();return dict(bytes=len(d),sha256=sha256(d).hexdigest())


def digest(arrays):
    h=sha256()
    for a in arrays:h.update(a)
    return h.hexdigest()


def emit(kind,**values):
    row=dict(event=kind,**values)
    with (HERE/'progress.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
    print(json.dumps(row),flush=True)


def full_digest(bundles):
    values=[v for bundle in bundles for ct in bundle.inputs.values() for v in ct.components]
    values += [v for bank in bundles[0].banks.values() for row in bank.rows for v in row]
    values += [v for pk in bundles[0].public_keys for v in pk.components]
    return digest(values)


def main():
    assert not (HERE/'public-check.json').exists() and not (HERE/'progress.jsonl').exists(),'Preserve earlier run'
    resource.setrlimit(resource.RLIMIT_AS,(8<<30,8<<30));resource.setrlimit(resource.RLIMIT_CPU,(1200,1200))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.sched_setaffinity(0,{0})
    build=json.loads((HERE/'build.json').read_text())
    for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
    for name,want in build['artifacts'].items():assert binding(HERE/name)==want,name
    protected=json.loads((FIXED/'verification.json').read_text())['source_bindings']
    for name,want in protected.items():assert binding(ROOT/name)==want,name
    host=dict(meminfo=Path('/proc/meminfo').read_text(),cpu_affinity=sorted(os.sched_getaffinity(0)),address_space_cap=8<<30,cpu_seconds_cap=1200)
    (HERE/'host-before.json').write_text(json.dumps(host,indent=2)+'\n')
    ring=SlimRing();caches={};counts=Counter();preparation={}
    assert str(ring.dll._name)==str(FIXED/'build/fixed_core.so')
    helper=C.CDLL(str(LIBRARY));helper.jet_matrix_fixture.argtypes=[P,C.c_size_t,C.c_uint,C.c_uint64];helper.jet_matrix_fixture.restype=C.c_int
    helper.jet_matrix_mul_check.argtypes=[P,P,P,C.c_size_t,C.c_uint,C.c_uint];helper.jet_matrix_mul_check.restype=C.c_int
    libraries={str(Path(x).relative_to(ROOT)):binding(Path(x)) for x in (ring.dll._name,ring.terminal_dll._name,LIBRARY)}
    try:
        n=ring.dimension; rng=Random(2026091415)
        for channel,p in enumerate(ring.primes):
            edges=(0,1,2,p-1,p-2,p//2,1<<59)
            pairs=[(x,y) for x in edges for y in edges]+[(rng.randrange(p),rng.randrange(p)) for _ in range(25000)]
            a=array('Q',(x for x,_ in pairs));b=array('Q',(y for _,y in pairs));expected=array('Q',(x*y%p for x,y in pairs))
            for arm in (0,1):
                out=array('Q',[0])*len(a)
                assert helper.jet_matrix_mul_check(pointer(a,'Q'),pointer(b,'Q'),pointer(out,'Q'),len(a),channel,arm)==0
                assert out==expected;counts['scalar_integer_oracle_words']+=len(a)
        salt=0
        def spectrum(a):
            nonlocal salt
            salt+=1;out=ring.zeros(a)
            assert helper.jet_matrix_fixture(pointer(out,'Q'),len(out),a,salt)==0
            return out
        # Check the deterministic fixture generator against a Python integer oracle.
        sample=ring.zeros(1);assert helper.jet_matrix_fixture(pointer(sample,'Q'),len(sample),1,7)==0
        state=7;mask=(1<<64)-1
        for i in range(128):
            state=(state+0x9e3779b97f4a7c15)&mask;z=state
            z=((z^(z>>30))*0xbf58476d1ce4e5b9)&mask;z=((z^(z>>27))*0x94d049bb133111eb)&mask;z^=z>>31
            assert sample[i]==z%ring.primes[0];counts['fixture_generator_words']+=1
        del sample
        bank_inputs=[]
        for b in range(16):
            inputs={}
            for name in stage_public.INPUT_NAMES:
                key='h'+name[1:] if name.startswith('u') else 's0';a=stage_public.LIMBS[key]
                inputs[name]=Cipher(key,a,(spectrum(a),spectrum(a)))
            bank_inputs.append(inputs)
        banks={}
        for name,src,dst,a,kind in stage_public.catalog():
            g=ring.gadget(a,stage_public.WIDTH_BY_VERTEX[dst])
            banks[name]=Bank(src,dst,a,kind,tuple((spectrum(a),spectrum(a)) for _ in range(g)))
        pks=tuple(Cipher(key,stage_public.LIMBS[key],(spectrum(stage_public.LIMBS[key]),spectrum(stage_public.LIMBS[key]))) for key in stage_public.PK_NAMES)
        bundles=[Bundle(inputs,banks,pks) for inputs in bank_inputs]
        for bundle in bundles:assert_public(bundle)
        origin=full_digest(bundles);emit('fixtures_ready',batches=16,fixture_sha256=origin,rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        for arm in ('residue','quotient'):
            start=perf_counter();cache=CachedMatrix(ring,banks,arm);seconds=perf_counter()-start
            caches[arm]=cache;preparation[arm]=dict(seconds=seconds,bytes=cache.words*8,sha256=cache.digest())
            emit('cache_prepared',arm=arm,**preparation[arm])
        serial=[stage_public.evaluate(ring,bundle,True) for bundle in bundles]
        expected_hashes=[[digest(ct.components) for ct in trace] for trace in serial]
        assert all(len(trace)==22 for trace in serial)
        def compare(traces,name):
            assert len(traces)==16
            for old,new in zip(serial,traces):
                assert len(old)==len(new)==22
                for a,b in zip(old,new):
                    assert (a.key,a.limbs,len(a.components))==(b.key,b.limbs,len(b.components))
                    for x,y in zip(a.components,b.components):assert x==y;counts[name]+=len(x)
        # Exactly one full correctness/warm-up group per timed arm.
        observed={};base=evaluate_group(ring,bundles,None,True,observed);compare(base,'grouped_baseline_trace_words');del base
        emit('baseline_group_correspondence_pass',states=16*22)
        for arm in ('residue','quotient'):
            traces=evaluate_group(ring,bundles,caches[arm],True);compare(traces,arm+'_trace_words');del traces
            emit('candidate_group_correspondence_pass',arm=arm,states=16*22)
        del serial
        expected_bank=[]
        for source,hasse in zip(observed['source'],observed['hasse']):
            h0=ring.hasse_spectrum(source.components[0],3,8)
            expected_bank.append((ring.sub(hasse[0],h0,3),hasse[1]))
        for arm,cache in caches.items():
            for B in (1,3,16):
                result=cache.apply(observed['compact'][:B])
                for got,want in zip(result,expected_bank[:B]):
                    for x,y in zip(got,want):assert x==y;counts['whole_helper_partial_block_words']+=len(x)
                del result
            compact=observed['compact'][0]
            inputs=(P*4)(*(C.cast(ring.spectrum(v,3),P).value for v in compact))
            destinations=[ring.zeros(3),ring.zeros(3)]
            outputs=(P*2)(*(C.cast(ring.spectrum(v,3),P).value for v in destinations))
            before=digest(destinations)
            def reject(code):
                assert code in (1,2,3);assert digest(destinations)==before;counts['atomic_rejections']+=1
            reject(cache.dll.jet_matrix_apply(cache.handle,inputs,4,3*n,outputs,2,0))
            reject(cache.dll.jet_matrix_apply(cache.handle,inputs,3,3*n,outputs,2,1))
            reject(cache.dll.jet_matrix_apply(cache.handle,inputs,4,3*n-1,outputs,2,1))
            reject(cache.dll.jet_matrix_apply(cache.handle,inputs,4,3*n,(P*2)(outputs[0],outputs[0]),2,1))
            compact_hash=digest(compact)
            reject(cache.dll.jet_matrix_apply(cache.handle,inputs,4,3*n,(P*2)(inputs[0],outputs[1]),2,1))
            assert digest(compact)==compact_hash
            reject(cache.dll.jet_matrix_apply(cache.handle,inputs,4,3*n,(P*2)(cache.dll.jet_matrix_data(cache.handle),outputs[1]),2,1))
            value=compact[0][0];compact[0][0]=ring.primes[0]
            reject(cache.dll.jet_matrix_apply(cache.handle,inputs,4,3*n,outputs,2,1));compact[0][0]=value
            assert not cache.dll.jet_matrix_create(cache._pointers,71,3*n,int(arm=='quotient'));counts['cache_shape_rejections']+=1
            assert not cache.dll.jet_matrix_create(cache._pointers,72,3*n,2);counts['cache_shape_rejections']+=1
            row=cache._rows[0];value=row[0];row[0]=ring.primes[0]
            assert not cache.dll.jet_matrix_create(cache._pointers,72,3*n,int(arm=='quotient'));row[0]=value;counts['cache_range_rejections']+=1
            assert cache.digest()==preparation[arm]['sha256']
        del observed,expected_bank,compact,inputs,destinations,outputs
        assert full_digest(bundles)==origin
        emit('all_public_checks_pass',counts=dict(counts),rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        samples=[]
        for block,arm in enumerate(ORDER):
            start=perf_counter();results=evaluate_group(ring,bundles,caches.get(arm),False);seconds=perf_counter()-start
            assert [digest(x.components) for x in results]==[row[-1] for row in expected_hashes]
            record=dict(block=block,arm=arm,batches=16,seconds=seconds)
            samples.append(record);emit('timed_group_complete',**record);del results
        medians={arm:median(x['seconds'] for x in samples if x['arm']==arm) for arm in ('baseline','residue','quotient')}
        decisions={}
        for arm in ('residue','quotient'):
            ratio=medians['baseline']/medians[arm]
            charged=medians['baseline']/(medians[arm]+preparation[arm]['seconds'])
            decisions[arm]=dict(evaluator_ratio=ratio,preprocessing_inclusive_ratio=charged,
                                advance=ratio>=1.05 and charged>=1.02)
        eligible=[a for a in decisions if decisions[a]['advance']]
        selected=min(eligible,key=lambda a:medians[a]+preparation[a]['seconds']) if eligible else None
        assert full_digest(bundles)==origin
        for arm,cache in caches.items():assert cache.digest()==preparation[arm]['sha256']
        result=dict(status='CACHED_MATRIX_PUBLIC_CORRESPONDENCE_AND_SCREEN_COMPLETE',counts=dict(counts),
                    public_fixture_sha256=origin,batches_per_group=16,trace_states_per_batch=22,
                    preparation=preparation,samples=samples,medians=medians,decisions=decisions,selected_arm=selected,
                    advance_to_fresh_gate=selected is not None,combined_public_worker_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    new_he_execution=False,complete_he_performance_claim=False,security_bits=None,
                    source_bindings=build['source_bindings'],artifacts=build['artifacts'],protected_measured_sources=protected,
                    runtime_bindings=libraries,host_after_meminfo=Path('/proc/meminfo').read_text(),
                    source_gap_factor_for_future_16_batch_HE=1138,
                    scope='Public synthetic sixteen-batch grouped evaluator and cache preparation; not HE workflow timing')
        imported={Path(m.__file__).resolve() for m in tuple(sys.modules.values()) if getattr(m,'__file__',None) and Path(m.__file__).resolve().is_relative_to(ROOT)}
        result['imported_sources']={p.relative_to(ROOT).as_posix():binding(p) for p in sorted(imported)}
        for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
        for name,want in protected.items():assert binding(ROOT/name)==want,name
        for name,want in libraries.items():assert binding(ROOT/name)==want,name
        (HERE/'public-check.json').write_text(json.dumps(result,indent=2)+'\n')
        emit('screen_complete',medians=medians,decisions=decisions,selected_arm=selected,new_he_execution=False)
    finally:
        for cache in caches.values():cache.close()
        ring.close()


if __name__=='__main__':main()
