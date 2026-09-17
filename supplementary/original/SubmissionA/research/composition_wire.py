"""Fixed-schema little-endian public array packets; no pickle or object loader."""
from array import array
from hashlib import sha256
import json
import struct
import sys

HEADER=struct.Struct('<8sQ32s32s')
FRAME=struct.Struct('<II')


def exact(stream,n):
    out=bytearray(n);view=memoryview(out);done=0
    while done<n:
        count=stream.readinto(view[done:])
        if not count:raise ValueError('Truncated packet')
        done+=count
    return out


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


def receive(stream,magic,schema,binding=bytes(32),cap=1<<30):
    assert sys.byteorder=='little'
    frames=schema['frames'];payload=sum(f['words']*8 for f in frames)
    total=HEADER.size+len(frames)*FRAME.size+payload+32
    if total>cap:raise ValueError('Protocol cap')
    head=exact(stream,HEADER.size)
    if HEADER.unpack(head)!=(magic,payload,schema_digest(schema),binding):raise ValueError('Packet profile/header mismatch')
    digest=sha256(head);arrays=[]
    for i,spec in enumerate(frames):
        tag=exact(stream,FRAME.size)
        if FRAME.unpack(tag)!=(i,spec['words']*8):raise ValueError('Frame id/size mismatch')
        digest.update(tag)
        values=array('Q',[0])*spec['words'];view=memoryview(values).cast('B');done=0
        while done<len(view):
            count=stream.readinto(view[done:])
            if not count:raise ValueError('Truncated frame')
            done+=count
        digest.update(view);arrays.append(values)
    expected=digest.digest()
    if bytes(exact(stream,32))!=expected:raise ValueError('Packet digest mismatch')
    if stream.read(1)!=b'':raise ValueError('Trailing packet bytes')
    return arrays,dict(sha256=expected.hex(),payload_bytes=payload,wire_bytes=total,frames=len(frames))
