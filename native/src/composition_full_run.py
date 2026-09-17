from array import array
from dataclasses import dataclass,fields,is_dataclass
from os import urandom
from check_tensor_codec import setup as codec_setup,encode,decode
from field import FastField
from check_native_composition import mixed_hasse,frobenius
L,M,KAPPA,WIDTH,BETA=256,65536,130816,48,20
FRESH=(2*KAPPA+1)*BETA
TAIL=(8,4,2,1)
CHAIN=(4,4,4,3,2)

@dataclass
class Cipher:
    key:str
    limbs:int
    components:tuple


@dataclass
class Bank:
    source:str
    destination:str
    limbs:int
    payload:str
    rows:tuple


@dataclass
class Bundle:
    inputs:dict
    banks:dict
    public_keys:tuple


@dataclass
class Secret:
    key:str
    limbs:int
    coefficients:array
    spectra:array


class Coins:
    def __init__(self,ring):
        self.ring,self.domains=ring,set()
        self.errors=self.nonzero_errors=0

    def claim(self,label):
        assert label not in self.domains
        self.domains.add(label)

    def small(self,kind):
        result=array('q')
        while len(result)<M:
            wanted=M-len(result)
            words=array('Q');words.frombytes(urandom(8*wanted))
            result.extend(self.ring.sample_words(words,wanted,kind))
        return result

    def ternary(self,label):
        self.claim(label)
        return self.small(0)

    def error(self,label):
        self.claim(label)
        result=self.small(1)
        self.errors+=1;self.nonzero_errors+=bool(any(result))
        return result

    def uniform(self,label,a):
        self.claim(label);result=array('Q')
        for p in self.ring.primes[:a]:
            channel=array('q')
            while len(channel)<M:
                wanted=M-len(channel)
                words=array('Q');words.frombytes(urandom(8*wanted))
                channel.extend(self.ring.sample_words(words,wanted,2,p))
            result.frombytes(channel.tobytes())
        return result


def keygen(ring,coins,secret):
    a=coins.uniform('pk/'+secret.key+'/a',secret.limbs)
    e=coins.error('pk/'+secret.key+'/e')
    noise=ring.lift(array('q',(2*x for x in e)),secret.limbs)
    b=ring.sub(noise,ring.point(a,secret.spectra,secret.limbs),secret.limbs)
    return Cipher(secret.key,secret.limbs,(b,a))


def encrypt(ring,coins,pk,mu,label):
    assert len(mu)==M and set(mu)<={0,1}
    u=coins.ternary('enc/'+label+'/u')
    e0,e1=coins.error('enc/'+label+'/e0'),coins.error('enc/'+label+'/e1')
    us=ring.lift(u,pk.limbs)
    one=ring.lift(array('q',(2*x+y for x,y in zip(e0,mu))),pk.limbs)
    two=ring.lift(array('q',(2*x for x in e1)),pk.limbs)
    return Cipher(pk.key,pk.limbs,(
        ring.add(ring.point(pk.components[0],us,pk.limbs),one,pk.limbs),
        ring.add(ring.point(pk.components[1],us,pk.limbs),two,pk.limbs)))


def make_bank(ring,coins,source,destination,payload,name,kind):
    a=destination.limbs
    assert source.key!=destination.key and a<=source.limbs
    rows=[]
    for j in range(ring.gadget(a)):
        mask=coins.uniform('hint/'+name+f'/{j}/a',a)
        e=coins.error('hint/'+name+f'/{j}/e')
        noise=ring.lift(array('q',(2*x for x in e)),a)
        b=ring.add(ring.sub(noise,ring.point(mask,destination.spectra,a),a),ring.scale(payload,a,WIDTH*j),a)
        rows.append((b,mask))
    return Bank(source.key,destination.key,a,kind,tuple(rows))


def external(ring,bank,digits,source,relative=None):
    assert bank.source==source and len(digits)==len(bank.rows)
    out=[ring.zeros(bank.limbs),ring.zeros(bank.limbs)]
    for digit,row in zip(digits,bank.rows):
        spectrum=ring.relative_spectrum(digit,*relative,bank.limbs) if relative else ring.lift(digit,bank.limbs)
        for c in range(2):out[c]=ring.add(out[c],ring.point(spectrum,row[c],bank.limbs),bank.limbs)
    return tuple(out)


def relin(ring,raw,linear,quadratic):
    assert len(raw.components)==3 and (linear.payload,quadratic.payload)==('linear','quadratic')
    assert (linear.source,linear.destination,linear.limbs)==(quadratic.source,quadratic.destination,quadratic.limbs)
    assert (raw.key,raw.limbs)==(linear.source,linear.limbs)
    a=raw.limbs
    one=external(ring,linear,ring.digits(raw.components[1],a),raw.key)
    two=external(ring,quadratic,ring.digits(raw.components[2],a),raw.key)
    return Cipher(linear.destination,a,(ring.add(raw.components[0],ring.add(one[0],two[0],a),a),ring.add(one[1],two[1],a)))


def raw_sum(ring,pairs,addend=None):
    assert pairs
    src=pairs[0][0];a=src.limbs
    sums=[ring.zeros(a) for _ in range(3)]
    for left,right in pairs:
        assert left.key==right.key==src.key and left.limbs==right.limbs==a
        assert len(left.components)==len(right.components)==2
        l0,l1=left.components;r0,r1=right.components
        terms=(ring.point(l0,r0,a),ring.point(l1,r1,a),ring.point(ring.add(l0,l1,a),ring.add(r0,r1,a),a))
        sums=[ring.add(x,y,a) for x,y in zip(sums,terms)]
    components=[sums[0],ring.sub(ring.sub(sums[2],sums[0],a),sums[1],a),sums[1]]
    if addend:
        assert addend.key==src.key and addend.limbs==a and len(addend.components)==2
        for j in range(2):components[j]=ring.add(components[j],addend.components[j],a)
    return Cipher(src.key,a,tuple(components))


def assert_public(value):
    if is_dataclass(value):
        assert type(value) in (Cipher,Bank,Bundle)
        for member in fields(value):assert_public(getattr(value,member.name))
    elif isinstance(value,dict):
        for k,v in value.items():assert isinstance(k,str);assert_public(v)
    elif isinstance(value,tuple):
        for x in value:assert_public(x)
    elif isinstance(value,array):
        assert value.typecode=='Q'
    else:
        assert isinstance(value,(str,int))


def encode_lanes(lanes,inverse):
    assert len(lanes)==L*16
    packed=[sum(int(lanes[lane*L+i])<<(16*lane) for lane in range(16)) for i in range(L)]
    words=encode(packed,inverse)
    return bytearray((word>>e)&1 for word in words for e in range(256))

