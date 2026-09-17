"""Original counting-sink serialization, unchanged."""
from array import array
from hashlib import sha256
import json,struct,sys
HEADER=struct.Struct("<8sQ32s32s")
FRAME=struct.Struct("<II")

def write_all(stream,data):
    view=memoryview(data).cast('B');done=0
    while done<len(view):
        count=stream.write(view[done:])
        if not count:raise ValueError('Closed packet sink')
        done+=count


def schema_digest(schema):
    return sha256(json.dumps(schema,sort_keys=True,separators=(',',':')).encode()).digest()


def send(stream,magic,schema,arrays,binding=bytes(32),cap=1<<30):
    assert sys.byteorder=='little' and len(magic)==8 and len(binding)==32
    frames=schema['frames'];assert len(frames)==len(arrays)
    payload=sum(f['words']*8 for f in frames)
    total=HEADER.size+len(frames)*FRAME.size+payload+32
    assert total<=cap
    head=HEADER.pack(magic,payload,schema_digest(schema),binding);digest=sha256(head)
    write_all(stream,head)
    for i,(spec,values) in enumerate(zip(frames,arrays)):
        assert isinstance(values,array) and values.typecode=='Q' and values.itemsize==8 and len(values)==spec['words']
        tag=FRAME.pack(i,len(values)*8);digest.update(tag);write_all(stream,tag)
        raw=memoryview(values).cast('B');digest.update(raw);write_all(stream,raw)
    result=digest.digest();write_all(stream,result);stream.flush()
    return dict(sha256=result.hex(),payload_bytes=payload,wire_bytes=total,frames=len(frames))

