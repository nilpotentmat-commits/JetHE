"""Deterministic stage-gadget reconstruction and public payload correspondence."""
from array import array
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
from random import Random
import resource
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
LAZY=HERE.parent/'native-lazy-ntt-v1'
sys.path[:0]=[str(HERE.parent/'same-algebra-one-prime-workflow-v1'),str(LAZY),str(HERE)]
import common
from candidate_crypto import SlimRing as BaselineRing
from stage_crypto import SlimRing as CandidateRing,make_bank
import bounds
from composition_full_run import Secret
from composition_native import pointer
assert Path(bounds.__file__).resolve()==HERE/'bounds.py'
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
def main():
    assert not (HERE/'public-check.json').exists(),'Preserve earlier check'
    resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30));resource.setrlimit(resource.RLIMIT_CPU,(180,180))
    os.sched_setaffinity(0,{0})
    build=json.loads((HERE/'build.json').read_text())
    for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
    for name,want in build['candidate_files'].items():assert binding(HERE/name)==want,name
    for p in (HERE/'backend').glob('*.cpp'):
        value=p.read_text().replace('need(width==40||width==44||width==45||width==48||width==60,"supported gadget widths40/44/45/48/60");',
            'need(width==44||width==48||width==60,"supported gadget widths48/60");')
        assert value==(LAZY/'backend'/p.name).read_text()
    baseline,candidate=BaselineRing(),CandidateRing();n=candidate.dimension
    rng=Random(2026091405);counts=Counter()
    try:
        for a,w in ((3,45),(3,60),(2,40),(2,60)):
            q=candidate.moduli[a];g=candidate.gadget(a,w);D=1<<(w-1)
            chosen={0,1,-1,q//2,q//2-1,-q//2+1,-q//2+2}
            for j in range(g):
                for sign in (-1,1):
                    for offset in (-1,0,1):
                        value=sign*((D<<(w*j))+offset)
                        if abs(value)<=q//2:chosen.add(value)
            chosen=sorted(chosen)
            full=[chosen[i%len(chosen)] if i<2*len(chosen) else rng.randrange(-q//2+1,q//2+1) for i in range(n)]
            spectrum=array('Q')
            for j,p in enumerate(candidate.primes[:a]):
                part=array('Q',(v%p for v in full))
                x=baseline.transform(part,j);y=candidate.transform(part,j)
                assert x==y;counts['unchanged_transform_words']+=len(x);spectrum.extend(y)
            digits=candidate.digits(spectrum,a,w)
            assert len(digits)==g and all(-D<=v<=D for row in digits for v in row)
            assert all(-D<=v<D for row in digits[:-1] for v in row)
            assert all(sum(int(row[i])<<(w*j) for j,row in enumerate(digits))==v for i,v in enumerate(full))
            counts['exact_integer_reconstructions']+=n
            reconstructed=candidate.zeros(a)
            for j,row in enumerate(digits):
                lifted=candidate.lift(array('q',row),a)
                reconstructed=candidate.add(reconstructed,candidate.scale(lifted,a,w*j),a)
            assert reconstructed==spectrum;counts['spectral_gadget_reconstructions']+=len(spectrum)
            # Confirm that allowing new widths leaves the old width-44 route unchanged.
            out=array('q',[0])*(baseline.gadget(a)*n)
            candidate.call('jc_digits',candidate.handle,candidate.spectrum(spectrum,a),pointer(out,'q'),a,44)
            old=baseline.digits(spectrum,a)
            assert out.tolist()==[v for row in old for v in row]
            counts['old_width_correspondence_words']+=len(out)
        # Public, deterministic zero-noise rows check the constructor's exact payload scale.
        source_coeff=array('q',(i%3-1 for i in range(n)))
        source=Secret('public_source',3,source_coeff,candidate.lift(source_coeff,3))
        for dst,w in bounds.WIDTH_BY_VERTEX.items():
            a=2 if dst in ('h2','s4','h1') else 3
            coeff=array('q',((i*7)%3-1 for i in range(n)))
            destination=Secret(dst,a,coeff,candidate.lift(coeff,a))
            class PublicCoins:
                def uniform(self,label,limbs):return candidate.zeros(limbs)
                def error(self,label):return array('q',[0])*n
            bank=make_bank(candidate,PublicCoins(),source,destination,source.spectra,'public/'+dst,'linear')
            assert len(bank.rows)==candidate.gadget(a,w)
            for j,(body,mask) in enumerate(bank.rows):
                phase=candidate.add(body,candidate.point(mask,destination.spectra,a),a)
                assert phase==candidate.scale(source.spectra,a,w*j)
                counts['public_bank_payload_rows']+=1
    finally:baseline.close();candidate.close()
    for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
    for name,want in build['candidate_files'].items():assert binding(HERE/name)==want,name
    result=dict(status='NATIVE_STAGE_GADGET_PUBLIC_BOUNDARIES_PASS',counts=dict(counts),
        build_receipt=binding(HERE/'build.json'),checker=binding(Path(__file__)),
        source_bindings=build['source_bindings'],candidate_bindings=build['candidate_files'],
        new_he_execution=False,production_secret_vectors_sampled=0,security_bits=None,
        scope='Public fixed fixtures for integer/spectral digit reconstruction, old arithmetic correspondence and payload scaling. No fresh encryption, timing claim or numerical security.')
    (HERE/'public-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('source_bindings','candidate_bindings')}))
if __name__=='__main__':main()
