"""Independent public plaintext check of a completed HElib receipt, no HE run.

Uses the previously checked log-table Horner core, rather than the baseline's
bitwise field arithmetic, on the independently generated shared V1 fixture.
"""
from array import array
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
from composition_fixture import inputs,metadata
from composition_native import NativeRing,DLL_PATH


def main():
    assert len(sys.argv)==2
    receipt_path=Path(sys.argv[1]).resolve()
    receipt=json.loads(receipt_path.read_text(encoding='utf-8'))
    assert receipt['status']=='PASS' and receipt['mode']=='encrypted'
    result=receipt['result'];assert result['fixture_jobs']==[0,1,2,3]
    assert receipt['fixture']==metadata()
    fs,gs=inputs();ring=NativeRing(256,1)
    try:
        expected=ring.series(array('H',(x for f in fs[:4] for x in f)),
                             array('H',(x for g in gs[:4] for x in g)),256,4,horner=True)
    finally:ring.close()
    assert list(expected)==result['recovered_public_fixture_symbols']
    assert list(expected[:256])==[fs[0][0]]+[0]*255
    assert list(expected[256:512])==fs[1]
    sources=[Path(__file__).resolve(),Path(__file__).with_name('composition_fixture.py'),
             Path(__file__).with_name('composition_native.py'),
             Path(__file__).with_name('composition_native_core.cpp'),DLL_PATH]
    out=dict(status='PASS',receipt_sha256=sha256(receipt_path.read_bytes()).hexdigest(),
             symbols_checked=1024,fixture_sha256=metadata()['sha256'],
             output_sha256=sha256(struct.pack('<1024H',*expected)).hexdigest(),
             source_manifest={str(p):sha256(p.read_bytes()).hexdigest() for p in sources},
             scope='Independent frozen-input generator and log-table Horner; public output check only, no keys or HE replay; inherited core validation covers transitive arithmetic dependencies')
    print(json.dumps(out))


if __name__=='__main__':main()
