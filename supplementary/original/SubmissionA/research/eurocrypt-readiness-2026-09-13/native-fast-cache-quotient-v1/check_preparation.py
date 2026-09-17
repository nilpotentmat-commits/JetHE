"""Frozen complete public cache-preparation screen, not an HE benchmark."""
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
OLD=READY/'native-cached-matrix-v1';FIXED=READY/'native-fixed-multipliers-v1';STAGE=READY/'native-stage-gadgets-v1'
sys.path.insert(0,str(READY/'same-algebra-one-prime-workflow-v1'))
import common
sys.path[:0]=[str(HERE),str(OLD),str(FIXED),str(STAGE)]
from fixed_crypto import SlimRing
from composition_full_run import Bank
from composition_native import P,pointer
from matrix_binding import CachedMatrix
from fast_binding import FastCachedMatrix
ORDER=('original','new','new','original','original','new')


def binding(p):
    d=p.read_bytes();return dict(bytes=len(d),sha256=sha256(d).hexdigest())


def digest(arrays):
    h=sha256()
    for a in arrays:h.update(a)
    return h.hexdigest()


def emit(kind,**data):
    row=dict(event=kind,**data)
    with (HERE/'preparation-progress.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
    print(json.dumps(row),flush=True)


def main():
    assert not (HERE/'preparation-check.json').exists() and not (HERE/'preparation-progress.jsonl').exists(),'Preserve earlier check'
    resource.setrlimit(resource.RLIMIT_AS,(4<<30,4<<30));resource.setrlimit(resource.RLIMIT_CPU,(240,240));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.sched_setaffinity(0,{0})
    build=json.loads((HERE/'build.json').read_text())
    for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
    for name,want in build['artifacts'].items():assert binding(HERE/name)==want,name
    ring=SlimRing();counts=Counter();caches=[]
    fast=C.CDLL(str(HERE/'build/matrix_fast.so'))
    fast.jet_fast_quotient_check.argtypes=[P,P,C.c_size_t,C.c_uint64];fast.jet_fast_quotient_check.restype=C.c_int
    original=C.CDLL(str(OLD/'build/matrix.so'))
    original.jet_matrix_fixture.argtypes=[P,C.c_size_t,C.c_uint,C.c_uint64];original.jet_matrix_fixture.restype=C.c_int
    libraries={str(Path(p).relative_to(ROOT)):binding(Path(p)) for p in (fast._name,original._name,ring.dll._name,ring.terminal_dll._name)}
    try:
        rng=Random(2026091457);base=1<<60
        for c in (0,1,2,603974655,1040175615,1342160895,(1<<31)-1):
            p=base-c
            values={0,1,2,p-1,p-2,p//2}
            values.update(x for k in range(60) for x in ((1<<k)-1,1<<k,(1<<k)+1) if x<p)
            values.update(rng.randrange(p) for _ in range(40000))
            data=array('Q',sorted(values));out=array('Q',[0])*len(data)
            assert fast.jet_fast_quotient_check(pointer(data,'Q'),pointer(out,'Q'),len(data),p)==0
            assert out==array('Q',((w<<64)//p for w in data));counts['compiled_quotient_oracle_words']+=len(data)
        data=array('Q',[0,1,base-1]);out=array('Q',[123]*3)
        for p in (0,base+1,base-(1<<31)):
            assert fast.jet_fast_quotient_check(pointer(data,'Q'),pointer(out,'Q'),3,p)==1
            assert out==array('Q',[123]*3);counts['atomic_shape_rejections']+=1
        assert fast.jet_fast_quotient_check(pointer(data,'Q'),pointer(data,'Q'),3,base)==2
        assert data==array('Q',[0,1,base-1]);counts['atomic_alias_rejections']+=1
        data[2]=base;assert fast.jet_fast_quotient_check(pointer(data,'Q'),pointer(out,'Q'),3,base)==3
        assert out==array('Q',[123]*3);counts['atomic_range_rejections']+=1
        salt=0
        def spectrum():
            nonlocal salt
            salt+=1;values=ring.zeros(3)
            assert original.jet_matrix_fixture(pointer(values,'Q'),len(values),3,710000+salt)==0
            return values
        banks={}
        for i in range(9):
            name=f'h8_{i}' if i<8 else 'h8_identity'
            banks[name]=Bank('s1','h8',3,'hasse' if i<8 else 'linear',tuple((spectrum(),spectrum()) for _ in range(4)))
        arrays=[v for bank in banks.values() for row in bank.rows for v in row]
        bank_hash=digest(arrays)
        emit('public_banks_ready',sha256=bank_hash,source_rows=36,source_components=72)
        old=CachedMatrix(ring,banks,'quotient');new=FastCachedMatrix(ring,banks,'quotient');caches=[old,new]
        assert old.words==new.words==88080384
        libc=C.CDLL(None);libc.memcmp.argtypes=[P,P,C.c_size_t];libc.memcmp.restype=C.c_int
        assert libc.memcmp(old.dll.jet_matrix_data(old.handle),new.dll.jet_matrix_data(new.handle),old.words*8)==0
        same_hash=old.digest();assert new.digest()==same_hash;counts['identical_cache_words']+=old.words
        # Both complete helpers consume the byte-identical cache and return equal spectra.
        compacts=[]
        for b in range(3):
            row=[]
            for j in range(4):
                coeff=array('q',(((i*7919+b*8191+j*65537)%(1<<44))-(1<<43) for i in range(ring.dimension)))
                compact,_=ring.hoist(coeff,3,8);row.append(compact)
            compacts.append(row)
        first=old.apply(compacts);second=new.apply(compacts)
        for x,y in zip(first,second):
            for a,b in zip(x,y):assert a==b;counts['unchanged_matrix_output_words']+=len(a)
        assert old.digest()==new.digest()==same_hash
        old.close();new.close();caches=[];del first,second,compacts
        emit('compiled_formula_and_cache_correspondence_pass',counts=dict(counts),cache_sha256=same_hash)
        samples=[]
        classes={'original':CachedMatrix,'new':FastCachedMatrix}
        for block,arm in enumerate(ORDER):
            start=perf_counter();cache=classes[arm](ring,banks,'quotient');seconds=perf_counter()-start
            assert cache.words==88080384 and cache.digest()==same_hash
            sample=dict(block=block,arm=arm,seconds=seconds,cache_bytes=cache.words*8)
            samples.append(sample);emit('preparation_sample',**sample);cache.close()
        medians={arm:median(x['seconds'] for x in samples if x['arm']==arm) for arm in classes}
        ratio=medians['original']/medians['new'];advance=ratio>=1.25
        assert digest(arrays)==bank_hash
        for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
        for name,want in build['artifacts'].items():assert binding(HERE/name)==want,name
        for name,want in libraries.items():assert binding(ROOT/name)==want,name
        imported={Path(m.__file__).resolve() for m in tuple(sys.modules.values()) if getattr(m,'__file__',None) and Path(m.__file__).resolve().is_relative_to(ROOT)}
        result=dict(status='FAST_QUOTIENT_PREPARATION_SCREEN_COMPLETE',counts=dict(counts),samples=samples,medians=medians,
                    original_over_new=ratio,advance_to_full_public_gate=advance,threshold=1.25,cache_bytes=704643072,
                    cache_sha256=same_hash,bank_sha256=bank_hash,build_receipt=binding(HERE/'build.json'),
                    source_bindings=build['source_bindings'],artifacts=build['artifacts'],runtime_bindings=libraries,
                    imported_sources={p.relative_to(ROOT).as_posix():binding(p) for p in sorted(imported)},
                    peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,host_meminfo=Path('/proc/meminfo').read_text(),
                    new_he_execution=False,complete_he_performance_claim=False,security_bits=None,
                    scope='Complete public cache construction including allocation, validation, powers, matrix formation and quotient writes')
        (HERE/'preparation-check.json').write_text(json.dumps(result,indent=2)+'\n')
        emit('preparation_screen_complete',medians=medians,original_over_new=ratio,advance=advance,new_he_execution=False)
    finally:
        for cache in caches:cache.close()
        ring.close()


if __name__=='__main__':main()
