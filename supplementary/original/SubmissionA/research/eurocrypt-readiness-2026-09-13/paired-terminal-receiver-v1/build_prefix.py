"""Construct and exactly validate every prefix bin of the preserved finite CDFs."""
from array import array
from bisect import bisect_right
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

from prefix_sampler import HERE,SOURCE,PREFIX_BITS,PRECISION,SENTINEL,BIN,sample_vectors


def main():
    tables=sample_vectors.load_tables()
    entries=array('h')
    checked,ambiguous_total=0,0
    records=[]
    for table_index,(first,length,bounds) in enumerate(tables):
        prefix=array('h',[0])*65536
        start=0
        for index,bound in enumerate(bounds):
            change=(bound+BIN-1)//BIN
            if change>start:
                prefix[start:change]=array('h',[first+index])*(change-start)
            start=change
        if start<65536:
            prefix[start:]=array('h',[first+len(bounds)])*(65536-start)
        ambiguous={bound//BIN for bound in bounds if bound % BIN}
        for index in ambiguous:
            prefix[index]=SENTINEL
        masses=[0]*length
        # Independent endpoint semantics and complete exact probability mass.
        for p,value in enumerate(prefix):
            low,high=p*BIN,(p+1)*BIN
            left,right=bisect_right(bounds,low),bisect_right(bounds,high-1)
            assert (value==SENTINEL)==(left!=right)
            if left==right:
                assert value==first+left
                masses[left]+=BIN
            else:
                previous=low
                for outcome in range(left,right):
                    endpoint=bounds[outcome]
                    masses[outcome]+=endpoint-previous
                    previous=endpoint
                masses[right]+=high-previous
            checked+=1
        expected=[b-a for a,b in zip([0]+bounds,bounds+[1 << 256])]
        assert masses==expected and sum(masses)==1 << 256
        assert first+length-1<SENTINEL and first>=-32768
        records.append(dict(table=table_index,first=first,length=length,
                            ambiguous_prefixes=len(ambiguous),
                            expected_scalar_bytes=str(Fraction(2)+Fraction(30*len(ambiguous),65536)),
                            reconstructed_mass_sha256=sha256(json.dumps(masses).encode()).hexdigest()))
        ambiguous_total+=len(ambiguous)
        entries.extend(prefix)
    if sys.byteorder!='little':
        entries.byteswap()
    raw=struct.pack('<8sIII',b'JTPFX016',257,16,256)+entries.tobytes()
    assert len(raw)==33685524 and checked==16842752
    before={str(p.relative_to(HERE.parents[3])).replace('\\','/'):
            dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
            for p in [HERE/'build_prefix.py',HERE/'prefix_sampler.py',HERE/'PROOF.md',
                      SOURCE/'sample_vectors.py',SOURCE/'tables.bin',SOURCE/'table-receipt.json']}
    (HERE/'prefix16.bin').write_bytes(raw)
    result=dict(status='EXACT_FINITE_CDF_PREFIX_LOOKUP_CHECKS_PASS',prefix_bits=16,source_precision_bits=256,
                tables=257,checked_prefix_bins=checked,ambiguous_prefixes=ambiguous_total,
                prefix_bytes=len(raw),prefix_sha256=sha256(raw).hexdigest(),tables_detail=records,
                additional_statistical_distance='0',cryptographic_coins_used=False,
                maximum_vector_source_bytes=32*(32768+1)+1,minimum_vector_source_bytes=2*(32768+1)+1,
                bindings=before,scope='Every prefix bin and every original integer CDF mass checked. Same scalar and vector laws; no fresh source vector or HE execution.')
    (HERE/'prefix-receipt.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('tables_detail','bindings')},indent=2))


if __name__=='__main__':
    main()
