"""Direct public range/product checks for the lazy 64-bit multiplication."""
from array import array
import ctypes as C
from hashlib import sha256
import json
from pathlib import Path
from random import Random

HERE=Path(__file__).resolve().parent

def main():
    assert not (HERE/'ranges.json').exists(),'Preserve previous range check'
    dll=C.CDLL(str(HERE/'build/lazy_core.so'))
    ptr=C.POINTER(C.c_uint64)
    dll.jc_lazy_check.argtypes=[ptr,ptr,ptr,C.c_uint,C.c_uint];dll.jc_lazy_check.restype=C.c_int
    rng=Random(2026091402);counts=[]
    for index,p in enumerate((1152921504002872321,1152921503566671361,1152921503264686081,1152921503096916481)):
        assert p<1<<60
        xs=(0,1,p-1,p,p+1,2*p-1,2*p,2*p+1,3*p,4*p-2,4*p-1)
        ws=(0,1,2,p//2,p-2,p-1)
        pairs=[(x,w) for x in xs for w in ws]+[(rng.randrange(4*p),rng.randrange(p)) for _ in range(25000)]
        x=(C.c_uint64*len(pairs))(*(a for a,b in pairs));w=(C.c_uint64*len(pairs))(*(b for a,b in pairs));out=(C.c_uint64*len(pairs))()
        assert dll.jc_lazy_check(x,w,out,len(pairs),index)==0
        for (a,b),v in zip(pairs,out):
            exact=a*b-((a*((b<<64)//p))>>64)*p
            assert v==exact and 0<=v<2*p and v%p==a*b%p
        counts.append(dict(prime=p,exact_pairs=len(pairs)))
    result=dict(status='LAZY_NTT_WORD_RANGE_CHECKS_PASS',cases=counts,total_pairs=sum(r['exact_pairs'] for r in counts),
        files={n:sha256((HERE/n).read_bytes()).hexdigest() for n in ('check_ranges.py','ntt-run.cpp.inc','PROOF.md','build/lazy_core.so')},
        new_he_execution=False,security_bits=None)
    (HERE/'ranges.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__':main()
