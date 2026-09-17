"""Public virtual-row correspondence evaluator. Not a timing implementation."""
from array import array
import stage_public as reference
from composition_full_run import Cipher


def prepare(ring,bundle):
    reference.validate(ring,bundle)
    powers={}
    def monomial(a,i):
        if (a,i) not in powers:
            coeff=array('q',[0])*ring.dimension
            coeff[i*256:(i+1)*256]=array('q',[-1])*256
            powers[a,i]=ring.lift(coeff,a)
        return powers[a,i]
    result={}
    for r in reference.TAIL:
        a=reference.LIMBS[f'h{r}']
        identity=bundle.banks[f'h{r}_identity']
        virtual=[bundle.banks[f'h{r}_{i}'].rows for i in range(r)]
        for i in range(r):
            rows=[]
            for row,keyrow in zip(virtual[i],identity.rows):
                pair=[]
                for component in range(2):
                    left=keyrow[component] if i==0 else ring.point(monomial(a,i),keyrow[component],a)
                    right=ring.point(monomial(a,r),row[component],a)
                    pair.append(ring.sub(left,right,a))
                rows.append(tuple(pair))
            virtual.append(tuple(rows))
        result[r]=tuple(virtual)
    return result


def evaluate(ring,bundle,virtual,retain_trace=False,observations=None):
    reference.validate(ring,bundle)
    inputs,banks=bundle.inputs,bundle.banks
    expected=iter(reference.spec(ring)); outputs=[] if retain_trace else None
    def state(ct):
        _,key,a,arity,_=next(expected)
        assert (ct.key,ct.limbs,len(ct.components))==(key,a,arity)
        if outputs is not None:outputs.append(ct)
        return ct
    current=state(reference.raw_sum(ring,[(inputs[f'f{i}'],inputs[f'w{i}']) for i in range(1,16)],inputs['f0']))
    current=state(reference.relin(ring,current,banks['prefix_linear'],banks['prefix_quadratic']))
    for stage,r in enumerate(reference.TAIL):
        a=reference.CHAIN[stage+1]
        if current.limbs!=a:
            current=state(Cipher(current.key,a,tuple(ring.drop(x,a+1) for x in current.components)))
        digits=ring.digits(current.components[1],a,reference.WIDTH_BY_VERTEX[f'h{r}'])
        hparts=[ring.hasse_spectrum(current.components[0],a,r),ring.zeros(a)]
        apart=[current.components[0],ring.zeros(a)]
        alignment=banks['h1_identity' if r==1 else f'align{r}']
        compact_records=[]
        for j,digit in enumerate(digits):
            compact,full=ring.hoist(digit,a,r)
            if observations is not None:compact_records.append(compact)
            for i in range(2*r):
                for v in range(2):
                    term=ring.relative_point(compact,virtual[r][i][j][v],a,r,i)
                    hparts[v]=ring.add(hparts[v],term,a)
            for v in range(2):
                apart[v]=ring.add(apart[v],ring.point(full,alignment.rows[j][v],a),a)
        if observations is not None:
            observations[r]=dict(compact=compact_records,bank_result=tuple(hparts),current=current)
        h=state(Cipher(f'h{r}',a,tuple(hparts)))
        bypass=state(Cipher(alignment.destination,a,tuple(apart)))
        raw=state(reference.raw_sum(ring,[(h,inputs[f'u{r}'])]))
        if r==1:
            current=state(Cipher('h1',a,(ring.add(raw.components[0],bypass.components[0],a),
                                       ring.add(raw.components[1],bypass.components[1],a),raw.components[2])))
        else:
            product=state(reference.relin(ring,raw,banks[f'product{r}_linear'],banks[f'product{r}_quadratic']))
            current=state(Cipher(bypass.key,a,tuple(ring.add(x,y,a) for x,y in zip(bypass.components,product.components))))
    assert next(expected,None) is None
    return outputs if retain_trace else current
