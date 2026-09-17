"""Bounded exact prefix sampling of the preserved finite CDF vector law."""
from array import array
from bisect import bisect_right
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parent/'control-sampler-v1'
sys.path.insert(0,str(SOURCE))
import sample_vectors

PREFIX_BITS,PRECISION,SENTINEL=16,256,32767
BIN=1 << (PRECISION-PREFIX_BITS)


class PrefixSource:
    def __init__(self):
        self.tables=sample_vectors.load_tables()
        raw=(HERE/'prefix16.bin').read_bytes()
        receipt=json.loads((HERE/'prefix-receipt.json').read_text())
        assert sha256(raw).hexdigest()==receipt['prefix_sha256']
        assert struct.unpack_from('<8sIII',raw)==(b'JTPFX016',257,16,256)
        entries=array('h');entries.frombytes(raw[20:])
        if sys.byteorder!='little':
            entries.byteswap()
        assert len(entries)==257*65536
        self.prefix=entries
        self.vectors=self.source_bytes=self.ambiguous_draws=self.caps=0
        self.uniform_vectors=self.uniform_bytes=0

    def draw(self,table_index,prefix):
        value=self.prefix[(table_index << 16)+prefix]
        if value!=SENTINEL:
            return value
        suffix=os.urandom(30)
        self.source_bytes+=30
        self.ambiguous_draws+=1
        u=(prefix << 240)+int.from_bytes(suffix,'little')
        first,_,bounds=self.tables[table_index]
        return first+bisect_right(bounds,u)

    def sample(self):
        first=os.urandom(2)
        self.source_bytes+=2
        k=self.draw(0,int.from_bytes(first,'little'))
        integer,fraction=divmod(k,256)
        raw=os.urandom(2*sample_vectors.N+1)
        self.source_bytes+=len(raw)
        prefixes=array('H');prefixes.frombytes(raw[:-1])
        if sys.byteorder!='little':
            prefixes.byteswap()
        table_index=1+fraction
        values=[integer+self.draw(table_index,prefix) for prefix in prefixes]
        capped=any(abs(x)>96 for x in values)
        if capped:
            values=[0]*sample_vectors.N
        if raw[-1] & 1:
            values=[-x for x in values]
        self.vectors+=1;self.caps+=int(capped)
        assert len(values)==sample_vectors.N and all(-96<=x<=96 for x in values)
        return values

    def uniform(self,modulus):
        bits=modulus.bit_length()
        width=(bits+7)//8
        mask=(1 << bits)-1
        raw=os.urandom(sample_vectors.N*width)
        self.uniform_bytes+=len(raw)
        result=[]
        for i in range(sample_vectors.N):
            value=int.from_bytes(raw[i*width:(i+1)*width],'little') & mask
            for attempt in range(256):
                if value<modulus:
                    break
                if attempt==255:
                    raise RuntimeError('Bounded uniform-mask rejection exhausted.')
                extra=os.urandom(width)
                self.uniform_bytes+=width
                value=int.from_bytes(extra,'little') & mask
            result.append(value)
        self.uniform_vectors+=1
        return result
