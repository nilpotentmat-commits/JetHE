"""Fixed public program/schema. No fixture, plaintext, key setup or oracle call."""
from composition_full_run import (Cipher,Bank,Bundle,Trace,L,M,KAPPA,WIDTH,BETA,
    FRESH,TAIL,CHAIN,relin,raw_sum,validate_public)
from check_composition_modulus_chain import drop_noise

INPUT_NAMES=[f'f{i}' for i in range(16)]+[f'w{i}' for i in range(1,16)]+[f'u{r}' for r in TAIL]
PK_NAMES=['s0','h8','h4','h2','h1']
LIMBS={'s0':4,'s1':4,'h8':4,'s2':4,'h4':4,'s3':4,'h2':3,'s4':3,'h1':2,'s5':2}


def bank_catalog():
    out=[]
    for prefix,src,dst in [('prefix','s0','s1')]+[(f'product{r}',f'h{r}',f's{i+2}') for i,r in enumerate(TAIL)]:
        for kind in ('linear','quadratic'):out.append((prefix+'_'+kind,src,dst,LIMBS[dst],kind))
    for stage,r in enumerate(TAIL):
        src,dst,result=f's{stage+1}',f'h{r}',f's{stage+2}'
        for i in range(2*r):out.append((f'h{r}_{i}',src,dst,LIMBS[dst],f'H{r}(t^{i}s)'))
        out.append((f'align{r}',src,result,LIMBS[result],'linear'))
    assert len(out)==44
    return out


def trace_spec(ring):
    out=[]
    lam=lambda a:511*ring.gadget(a)*(1<<(WIDTH-1))*BETA
    bound=FRESH+15*KAPPA*((1+2*FRESH)*FRESH+FRESH)+(15*KAPPA+1)//2
    out.append(('prefix_raw','s0',4,3,bound));bound+=2*L*lam(4)
    out.append(('prefix','s1',4,2,bound));last=4
    for stage,r in enumerate(TAIL):
        a=CHAIN[stage+1];src=f's{stage+1}'
        if a!=last:
            assert last==a+1;bound=drop_noise(bound,KAPPA,ring.primes[a])
            out.append((f'drop{r}',src,a,2,bound))
        hb=bound+L*lam(a)
        out.extend([(f'hasse{r}',f'h{r}',a,2,hb),(f'bypass{r}',f's{stage+2}',a,2,hb)])
        pb=KAPPA*((1+2*FRESH)*hb+FRESH)+(KAPPA+1)//2
        out.append((f'product{r}_raw',f'h{r}',a,3,pb));pb+=2*L*lam(a)
        out.append((f'product{r}',f's{stage+2}',a,2,pb));bound=hb+pb+1
        assert ring.moduli[a]>2+4*bound
        out.append((f'tail{r}',f's{stage+2}',a,2,bound));last=a
    assert len(out)==24
    return out


def packet_schema(ring,response=False):
    records=[]
    if response:
        for name,key,a,arity,_ in trace_spec(ring):records.append([name,key,a,arity])
    else:
        for name in INPUT_NAMES:
            key='h'+name[1:] if name.startswith('u') else 's0'
            records.append(['input/'+name,key,LIMBS[key],2])
        for name,src,dst,a,payload in bank_catalog():
            for j in range(ring.gadget(a)):records.append(['bank/'+name+f'/{j}',src,dst,a,2,payload])
        for name in PK_NAMES:records.append(['pk/'+name,name,LIMBS[name],2])
    frames=[]
    for rec in records:
        a,arity=(rec[3],rec[4]) if rec[0].startswith('bank/') else (rec[2],rec[3])
        for part in range(arity):frames.append(dict(record=rec,part=part,words=a*M))
    schema=dict(version=1,response=response,length=L,dimension=M,primes=ring.primes,
        chain=list(CHAIN),width=WIDTH,field_polynomial='0x1100b',frames=frames)
    assert len(frames)==(53 if response else 486)
    assert sum(f['words']*8 for f in frames)==(181403648//2 if response else 952107008)
    return schema


def bundle_arrays(ring,bundle):
    validate_public(ring,bundle)
    assert list(bundle.inputs)==INPUT_NAMES
    assert list(bundle.banks)==[x[0] for x in bank_catalog()]
    arrays=[]
    for name in INPUT_NAMES:
        ct=bundle.inputs[name];key='h'+name[1:] if name.startswith('u') else 's0'
        assert (ct.key,ct.limbs)==(key,LIMBS[key]);arrays.extend(ct.components)
    for name,src,dst,a,payload in bank_catalog():
        bank=bundle.banks[name]
        assert (bank.source,bank.destination,bank.limbs,bank.payload)==(src,dst,a,payload)
        for row in bank.rows:arrays.extend(row)
    assert [x.key for x in bundle.public_keys]==PK_NAMES
    for ct in bundle.public_keys:
        assert ct.limbs==LIMBS[ct.key];arrays.extend(ct.components)
    return arrays


def decode_bundle(ring,arrays):
    it=iter(arrays)
    def components():return (next(it),next(it))
    inputs={}
    for name in INPUT_NAMES:
        key='h'+name[1:] if name.startswith('u') else 's0'
        inputs[name]=Cipher(key,LIMBS[key],components())
    banks={name:Bank(src,dst,a,payload,tuple(components() for _ in range(ring.gadget(a)))) for name,src,dst,a,payload in bank_catalog()}
    pks=tuple(Cipher(key,LIMBS[key],components()) for key in PK_NAMES)
    assert next(it,None) is None
    result=Bundle(inputs,banks,pks);bundle_arrays(ring,result)
    return result


def decode_trace(ring,arrays):
    it=iter(arrays);out=[]
    for name,key,a,arity,bound in trace_spec(ring):
        components=tuple(next(it) for _ in range(arity))
        for x in components:ring.validate(x,a)
        out.append(Trace(name,Cipher(key,a,components),bound))
    assert next(it,None) is None
    return out


def evaluate_optimized(ring,bundle):
    bundle_arrays(ring,bundle);inputs,banks=bundle.inputs,bundle.banks
    hoist_start=len(ring.hoisted)
    outputs=[]
    raw=raw_sum(ring,[(inputs[f'f{i}'],inputs[f'w{i}']) for i in range(1,16)],inputs['f0'])
    outputs.append(raw);current=relin(ring,raw,banks['prefix_linear'],banks['prefix_quadratic']);outputs.append(current)
    for stage,r in enumerate(TAIL):
        a=CHAIN[stage+1]
        if current.limbs!=a:
            current=Cipher(current.key,a,tuple(ring.drop(x,a+1) for x in current.components));outputs.append(current)
        digits=ring.digits(current.components[1],a)
        # One compact transform family and completion per digit, reused twice.
        hparts=[ring.hasse_spectrum(current.components[0],a,r),ring.zeros(a)]
        apart=[current.components[0],ring.zeros(a)];alignment=banks[f'align{r}']
        for j,digit in enumerate(digits):
            compact,full=ring.hoist(digit,a,r)
            for i in range(2*r):
                for part in range(2):
                    term=ring.relative_point(compact,banks[f'h{r}_{i}'].rows[j][part],a,r,i)
                    hparts[part]=ring.add(hparts[part],term,a)
            for part in range(2):apart[part]=ring.add(apart[part],ring.point(full,alignment.rows[j][part],a),a)
        h=Cipher(f'h{r}',a,tuple(hparts));bypass=Cipher(alignment.destination,a,tuple(apart))
        outputs.extend([h,bypass]);raw=raw_sum(ring,[(h,inputs[f'u{r}'])]);outputs.append(raw)
        product=relin(ring,raw,banks[f'product{r}_linear'],banks[f'product{r}_quadratic']);outputs.append(product)
        current=Cipher(bypass.key,a,tuple(ring.add(x,y,a) for x,y in zip(bypass.components,product.components)));outputs.append(current)
    spec=trace_spec(ring);assert len(outputs)==len(spec)
    for ct,(_,key,a,arity,_) in zip(outputs,spec):assert (ct.key,ct.limbs,len(ct.components))==(key,a,arity)
    assert ring.hoisted[hoist_start:]==[(a,r) for r,a in zip(TAIL,CHAIN[1:]) for _ in range(ring.gadget(a))]
    return outputs
