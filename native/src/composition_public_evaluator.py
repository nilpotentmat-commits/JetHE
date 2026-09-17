from composition_full_run import *
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

