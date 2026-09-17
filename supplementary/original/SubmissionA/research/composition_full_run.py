"""One untimed full-size encrypted correspondence run for J256/k4.

The public evaluator receives no secret keys, owner coefficients, randomness
or diagnostic callback. Same-process testing is NOT process-isolation evidence.
"""
import sys
import json
if __name__=='__main__':
    if sys.argv[1:]!=['--supervised']:
        raise SystemExit('Use supervise_composition_full.py')
    print(json.dumps({'event':'ready_for_limits'}),flush=True)
    if sys.stdin.readline().strip()!='LIMITS_INSTALLED':
        raise SystemExit('Missing limits handshake')

from array import array
from dataclasses import dataclass, fields, is_dataclass
from hashlib import sha256
from os import urandom
from secrets import randbelow
from composition_native import NativeRing
from check_tensor_codec import setup as codec_setup, encode, decode
from check_fused_composition_frontier import FastField
from check_native_composition import mixed_hasse, frobenius
from check_composition_modulus_chain import drop_noise
from check_composition_rns_arithmetic import recover_garner

L,M,KAPPA,WIDTH,BETA=256,65536,130816,48,20
FRESH=(2*KAPPA+1)*BETA
TAIL=(8,4,2,1)
CHAIN=(4,4,4,3,2)


def event(name,**data):
    print(json.dumps(dict(event=name,**data)),flush=True)


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


@dataclass
class Trace:
    name:str
    cipher:Cipher
    bound:int


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


def validate_public(ring,bundle):
    assert_public(bundle)
    assert set(bundle.inputs)=={f'f{i}' for i in range(16)}|{f'w{i}' for i in range(1,16)}|{f'u{r}' for r in TAIL}
    assert len(bundle.banks)==44 and len(bundle.public_keys)==5
    for ct in list(bundle.inputs.values())+list(bundle.public_keys):
        assert len(ct.components)==2
        for x in ct.components:ring.validate(x,ct.limbs)
    for bank in bundle.banks.values():
        assert bank.source!=bank.destination and len(bank.rows)==ring.gadget(bank.limbs)
        for row in bank.rows:
            assert len(row)==2
            for x in row:ring.validate(x,bank.limbs)


def evaluate(ring,bundle):
    """No private setup, random source, key or owner data in this interface."""
    validate_public(ring,bundle)
    inputs,banks=bundle.inputs,bundle.banks
    trace=[Trace(name,ct,FRESH) for name,ct in inputs.items()]
    lam=lambda a:511*ring.gadget(a)*(1<<(WIDTH-1))*BETA
    raw_bound=FRESH+15*KAPPA*((1+2*FRESH)*FRESH+FRESH)+(15*KAPPA+1)//2
    raw=raw_sum(ring,[(inputs[f'f{i}'],inputs[f'w{i}']) for i in range(1,16)],inputs['f0'])
    trace.append(Trace('prefix_raw',raw,raw_bound))
    current=relin(ring,raw,banks['prefix_linear'],banks['prefix_quadratic'])
    bound=raw_bound+2*L*lam(4);trace.append(Trace('prefix',current,bound))
    event('full_size_encrypted_prefix_complete')
    for stage,r in enumerate(TAIL):
        a=CHAIN[stage+1]
        if current.limbs!=a:
            assert current.limbs==a+1
            current=Cipher(current.key,a,tuple(ring.drop(x,a+1) for x in current.components))
            bound=drop_noise(bound,KAPPA,ring.primes[a]);trace.append(Trace(f'drop{r}',current,bound))
            event('full_size_encrypted_prime_drop',remaining_limbs=a)
        digits=ring.digits(current.components[1],a)
        parts=[ring.hasse_spectrum(current.components[0],a,r),ring.zeros(a)]
        for i in range(2*r):
            bank=banks[f'h{r}_{i}']
            assert (bank.source,bank.destination,bank.limbs,bank.payload)==(current.key,inputs[f'u{r}'].key,a,f'H{r}(t^{i}s)')
            term=external(ring,bank,digits,current.key,(i,r))
            parts=[ring.add(x,y,a) for x,y in zip(parts,term)]
        h=Cipher(inputs[f'u{r}'].key,a,tuple(parts));hbound=bound+L*lam(a)
        trace.append(Trace(f'hasse{r}',h,hbound))
        alignment=banks[f'align{r}']
        assert (alignment.source,alignment.limbs,alignment.payload)==(current.key,a,'linear')
        aligned=external(ring,alignment,digits,current.key)
        bypass=Cipher(alignment.destination,a,(ring.add(current.components[0],aligned[0],a),aligned[1]))
        trace.append(Trace(f'bypass{r}',bypass,hbound))
        product_bound=KAPPA*((1+2*FRESH)*hbound+FRESH)+(KAPPA+1)//2
        raw=raw_sum(ring,[(h,inputs[f'u{r}'])]);trace.append(Trace(f'product{r}_raw',raw,product_bound))
        product_ct=relin(ring,raw,banks[f'product{r}_linear'],banks[f'product{r}_quadratic'])
        product_bound+=2*L*lam(a);trace.append(Trace(f'product{r}',product_ct,product_bound))
        assert bypass.key==product_ct.key and bypass.limbs==product_ct.limbs==a
        current=Cipher(bypass.key,a,tuple(ring.add(x,y,a) for x,y in zip(bypass.components,product_ct.components)))
        bound=hbound+product_bound+1;assert ring.moduli[a]>2+4*bound
        trace.append(Trace(f'tail{r}',current,bound));event('full_size_encrypted_tail_complete',r=r)
    return current,trace


def encode_lanes(lanes,inverse):
    assert len(lanes)==L*16
    packed=[sum(int(lanes[lane*L+i])<<(16*lane) for lane in range(16)) for i in range(L)]
    words=encode(packed,inverse)
    return bytearray((word>>e)&1 for word in words for e in range(256))


def prepare_private(ring,coins):
    _,_,_,_,rows,inverse=codec_setup();field=FastField()
    f=array('H');f.frombytes(urandom(2*L*16))
    g=array('H');g.frombytes(urandom(2*L*16))
    valuations=[None,1,2,4]+[1]*12
    for lane,v in enumerate(valuations):
        if v is None:g[lane*L:(lane+1)*L]=array('H',[0])*L
        else:
            for i in range(v):g[lane*L+i]=0
            g[lane*L+v]=randbelow(65535)+1
    g[L:2*L]=array('H',[0,1]+[0]*(L-2))
    assert all(any(x>1 for x in f[lane*L:(lane+1)*L]) for lane in range(16))
    source_lanes={}
    for mask in range(16):
        source_lanes[f'f{mask}']=array('H',(x for lane in range(16) for x in mixed_hasse(f[lane*L:(lane+1)*L],mask*16)))
    u={}
    for j in range(8):
        value=array('H',(x for lane in range(16) for x in frobenius(g[lane*L:(lane+1)*L],j,field)))
        for lane in range(16):value[lane*L+(1<<j)]^=1
        u[1<<j]=value
    for mask in range(1,16):
        bit=mask&-mask;r=16*bit
        source_lanes[f'w{mask}']=u[r] if mask==bit else ring.series(source_lanes[f'w{mask^bit}'],u[r],L)
    for r in TAIL:source_lanes[f'u{r}']=u[r]
    plain={name:encode_lanes(value,inverse) for name,value in source_lanes.items()}
    for name,value in source_lanes.items():
        bits=plain[name];words=[sum(bits[i*256+e]<<e for e in range(256)) for i in range(L)]
        decoded=decode(words,rows)
        assert all(((decoded[i]>>(16*lane))&65535)==value[lane*L+i] for lane in range(16) for i in range(L))
    current=array('H',source_lanes['f0'])
    for i in range(1,16):
        product=ring.series(source_lanes[f'f{i}'],source_lanes[f'w{i}'],L)
        current=array('H',(x^y for x,y in zip(current,product)))
    plain['prefix_raw']=plain['prefix']=encode_lanes(current,inverse)
    for r in TAIL:
        if r in (2,1):plain[f'drop{r}']=encode_lanes(current,inverse)
        h=array('H',(x for lane in range(16) for x in mixed_hasse(current[lane*L:(lane+1)*L],r)))
        product=ring.series(h,u[r],L)
        plain[f'hasse{r}']=encode_lanes(h,inverse)
        plain[f'bypass{r}']=encode_lanes(current,inverse)
        plain[f'product{r}_raw']=plain[f'product{r}']=encode_lanes(product,inverse)
        current=array('H',(x^y for x,y in zip(current,product)))
        plain[f'tail{r}']=encode_lanes(current,inverse)
    horner=ring.series(f,g,L,horner=True)
    assert current==horner and len(plain)==59
    event('full_size_private_oracles_and_codec_verified')
    profiles=[('s0',4),('s1',4)]
    for stage,r in enumerate(TAIL):profiles.extend([(f'h{r}',CHAIN[stage+1]),(f's{stage+2}',CHAIN[stage+1])])
    keys={}
    for name,a in profiles:
        coeff=coins.ternary('secret/'+name);keys[name]=Secret(name,a,coeff,ring.lift(coeff,a))
    pks={name:keygen(ring,coins,keys[name]) for name in ('s0','h8','h4','h2','h1')}
    inputs={name:encrypt(ring,coins,pks['h'+name[1:] if name.startswith('u') else 's0'],plain[name],name) for name in source_lanes}
    event('full_size_owner_encryption_complete',inputs=len(inputs))
    banks={}
    pairs=[('prefix','s0','s1')]+[(f'product{r}',f'h{r}',f's{stage+2}') for stage,r in enumerate(TAIL)]
    for prefix,src,dst in pairs:
        a=keys[dst].limbs
        for kind in ('linear','quadratic'):
            payload=keys[src].spectra if kind=='linear' else ring.point(keys[src].spectra,keys[src].spectra,a)
            name=prefix+'_'+kind;banks[name]=make_bank(ring,coins,keys[src],keys[dst],payload,name,kind)
    for stage,r in enumerate(TAIL):
        src,dst,result=f's{stage+1}',f'h{r}',f's{stage+2}'
        for i in range(2*r):
            payload=array('q',[0])*M
            for t in range(L):
                target=(t+i)%L;sign=-1 if t+i>=L else 1
                if target&r:payload[(target-r)*256:(target-r+1)*256]=array('q',(sign*x for x in keys[src].coefficients[t*256:(t+1)*256]))
            name=f'h{r}_{i}';banks[name]=make_bank(ring,coins,keys[src],keys[dst],ring.lift(payload,keys[dst].limbs),name,f'H{r}(t^{i}s)')
        name=f'align{r}';banks[name]=make_bank(ring,coins,keys[src],keys[result],keys[src].spectra,name,'linear')
        event('full_size_hint_stage_complete',r=r)
    assert len(banks)==44 and sum(len(b.rows) for b in banks.values())==203
    return Bundle(inputs,banks,tuple(pks.values())),keys,plain,horner,rows


def verify_private(ring,trace,keys,plain,horner,rows):
    receipt=[]
    for record in trace:
        ct=record.cipher;secret=keys[ct.key]
        assert ct.limbs<=secret.limbs
        phase=ct.components[0];secret_power=secret.spectra
        for component in ct.components[1:]:
            phase=ring.add(phase,ring.point(component,secret_power,ct.limbs),ct.limbs)
            secret_power=ring.point(secret_power,secret.spectra,ct.limbs)
        ring.phase_check(phase,plain[record.name],record.bound,ct.limbs)
        receipt.append(dict(name=record.name,key=ct.key,limbs=ct.limbs,arity=len(ct.components),bound_decimal=str(record.bound),parity_and_bound_check='PASS'))
    assert len(receipt)==59
    # Actual recipient recovery, independently reconstructing signed CRT values
    # in Python rather than using the core's expected-plaintext phase checker.
    a=trace[-1].cipher.limbs
    values=[ring.transform(phase[j*M:(j+1)*M],j,True) for j in range(a)]
    inv={(j,i):pow(ring.primes[j],-1,ring.primes[i]) for i in range(a) for j in range(i)}
    recovered=[recover_garner([values[j][i] for j in range(a)],ring.primes[:a],inv)[0]%2 for i in range(M)]
    words=[sum(recovered[i*256+e]<<e for e in range(256)) for i in range(L)]
    decoded=decode(words,rows)
    output=array('H',((decoded[i]>>(16*lane))&65535 for lane in range(16) for i in range(L)))
    assert output==horner
    return receipt,sha256(output.tobytes()).hexdigest()


def main():
    assert sys.byteorder=='little'
    ring=NativeRing(L,4);coins=Coins(ring)
    public,keys,plain,horner,rows=prepare_private(ring,coins)
    result,trace=evaluate(ring,public)
    assert result.key=='s5' and result.limbs==2
    receipt,digest=verify_private(ring,trace,keys,plain,horner,rows)
    size=lambda x:len(x)*x.itemsize
    hints=sum(size(x) for b in public.banks.values() for row in b.rows for x in row)
    uploads=sum(size(x) for c in public.inputs.values() for x in c.components)
    pkbytes=sum(size(x) for c in public.public_keys for x in c.components)
    assert (hints,uploads,pkbytes)==tuple(x*(1<<20) for x in (754,137,17))
    event('result',status='FULL_SIZE_ENCRYPTED_CORRESPONDENCE_ONLY',
          length=L,lanes=16,coefficient_field='GF(2^16), polynomial0x1100b',
          binary_coordinates=M,output_field_symbols=4096,output_digest=digest,
          input_ciphertexts=35,independent_keys=10,public_keys=5,hint_banks=44,
          hint_rows=203,private_products=19,hasse_maps=4,parity_drops=2,
          raw_hint_bytes=hints,raw_input_bytes=uploads,raw_pk_bytes=pkbytes,
          stage_chain=list(CHAIN),digit_width=WIDTH,trace=receipt,
          random_domains=len(coins.domains),error_vectors=coins.errors,
          nonzero_error_vectors=coins.nonzero_errors,
          randomness='OS urandom words with exact ternary/uniform rejection and CBD20 popcount; not a certified ideal-law implementation',
          fixture='sixteen full-field f lanes; g=0, g=z, valuations2/4, twelve dense valuation1 lanes',
          diagnostics='private post-evaluation checks; no phase norms/vectors or secret-key files published',
          evaluator='same-process public objects only; no process-isolation claim',
          optimized_hoisting=False,benchmark=False,security_bits=None,bootstrapping=False)
    ring.close()


if __name__=='__main__':
    main()
