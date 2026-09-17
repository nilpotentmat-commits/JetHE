"""Public decoder/phase endpoints and current admission; no cryptographic coins."""
from array import array
import json
from common import (HERE,N,Q,F,BRAW,SlimRingBase,Secret,Cipher,codec_setup,
                    encode_lanes,decrypt,source_manifest,runtime_manifest,verify_admission)


def main():
    verify_admission()
    before=source_manifest();runtime=runtime_manifest()
    _,_,_,_,rows,inverse=codec_setup()
    values=array('H',((i*31337+12345)&65535 for i in range(4096)))
    bits=encode_lanes(values,inverse)
    cases=[]
    # Public zero-secret phase fixtures distinguish parity after centering from
    # parity of an arbitrary odd-modulus residue, including near the boundary.
    for limbs,bounds in ((1,(F,BRAW,(Q-3)//4)),(2,(F,BRAW))):
        ring=SlimRingBase(256,limbs)
        try:
            zeros=ring.zeros(limbs)
            secret=Secret('public',limbs,array('q',[0])*N,zeros)
            for bound in bounds:
                signed=array('q',(bit+2*(bound if i&1 else -bound) for i,bit in enumerate(bits)))
                phase=ring.lift(signed,limbs)
                ct=Cipher('public',limbs,(phase,zeros,zeros))
                recovered,actual,decoded_bits=decrypt(ring,ct,secret,zeros,rows,True)
                assert recovered==values and decoded_bits==bits and actual==phase
                assert ring.phase_check(actual,bits,bound,limbs)==bound
                q=ring.moduli[limbs]
                wrong_uncentered=sum((x%q)&1!=bit for x,bit in zip(signed,bits))
                assert wrong_uncentered>0
                cases.append(dict(limbs=limbs,bound=bound,phase_coefficients=N,
                                  decoded_symbols=len(recovered),uncentered_parity_mismatches=wrong_uncentered))
        finally:ring.close()
    assert source_manifest()==before and runtime_manifest()==runtime
    result=dict(status='ONE_PRIME_WORKFLOW_PUBLIC_PREFLIGHT_PASS',cases=cases,
                source_manifest=before,runtime_manifest=runtime,source_files=len(before),
                secret_vectors_sampled=0,new_he_execution=False,security_bits=None,
                scope='Public zero-secret decoder/phase endpoint fixtures and admission bindings; not encryption, a rare-event test, a fresh gate or a benchmark.')
    with (HERE/'preflight.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('source_manifest','runtime_manifest')},indent=2))


if __name__=='__main__':main()
