"""Frozen public inputs for future matched composition checks, NOT crypto coins.

V1 fixes sixteen length-256 jobs over GF(2)[X]/(X^16+X^12+X^3+X+1).
Byte serialization is job-major: f_j then g_j, each uint16 little endian.
The already completed native correctness run predates and did NOT use V1.
"""
from hashlib import sha256
import json
import struct

SEED=0x4A657448454C3235
MASK=(1<<64)-1


def inputs():
    state=SEED

    def draw():
        nonlocal state
        state=(state+0x9e3779b97f4a7c15)&MASK
        z=((state^(state>>30))*0xbf58476d1ce4e5b9)&MASK
        z=((z^(z>>27))*0x94d049bb133111eb)&MASK
        return (z^(z>>31))&65535

    fs,gs=[],[]
    for job in range(16):
        f=[draw() for _ in range(256)];g=[draw() for _ in range(256)]
        f[0]|=1
        valuation=2 if job==2 else 4 if job==3 else 1
        g[:valuation]=[0]*valuation;g[valuation]=g[valuation] or 1
        if job==0:g=[0]*256
        if job==1:g=[0,1]+[0]*254
        fs.append(f);gs.append(g)
    return fs,gs


def metadata():
    fs,gs=inputs()
    raw=b''.join(struct.pack('<256H',*v) for pair in zip(fs,gs) for v in pair)
    check=14695981039346656037
    for byte in raw:check=((check^byte)*1099511628211)&MASK
    return dict(id='composition-l256-v1',seed_hex=hex(SEED),jobs=16,length=256,
                field_polynomial='0x1100b',serialization='job-major f then g; uint16 little endian',
                sha256=sha256(raw).hexdigest(),fnv64_cross_language_check=str(check),
                scope='Public synthetic correctness fixture; not an application distribution or encryption randomness')


if __name__=='__main__':
    print(json.dumps(metadata()))
