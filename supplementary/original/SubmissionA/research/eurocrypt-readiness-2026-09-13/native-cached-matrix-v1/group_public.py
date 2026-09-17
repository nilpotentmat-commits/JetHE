"""Common grouped schedule; replace only the Hasse-8 bank application."""
import stage_public as reference
from composition_full_run import Cipher


def evaluate_group(ring,bundles,cache=None,retain_trace=False,observations=None):
    B=len(bundles);assert 1<=B<=16
    banks=bundles[0].banks
    assert all(bundle.banks is banks for bundle in bundles)
    for bundle in bundles:reference.validate(ring,bundle)
    expected=[iter(reference.spec(ring)) for _ in bundles]
    outputs=[[] for _ in bundles] if retain_trace else None
    def state(b,ct):
        _,key,a,arity,_=next(expected[b])
        assert (ct.key,ct.limbs,len(ct.components))==(key,a,arity)
        if outputs is not None:outputs[b].append(ct)
        return ct
    current=[]
    for b,bundle in enumerate(bundles):
        inputs=bundle.inputs
        raw=state(b,reference.raw_sum(ring,[(inputs[f'f{i}'],inputs[f'w{i}']) for i in range(1,16)],inputs['f0']))
        current.append(state(b,reference.relin(ring,raw,banks['prefix_linear'],banks['prefix_quadratic'])))
    for stage,r in enumerate(reference.TAIL):
        a=reference.CHAIN[stage+1]
        alignment=banks['h1_identity' if r==1 else f'align{r}']
        prepared=[];all_compact=[]
        for b,ct in enumerate(current):
            if ct.limbs!=a:ct=state(b,Cipher(ct.key,a,tuple(ring.drop(x,a+1) for x in ct.components)))
            digits=ring.digits(ct.components[1],a,reference.WIDTH_BY_VERTEX[f'h{r}'])
            hparts=[ring.hasse_spectrum(ct.components[0],a,r),ring.zeros(a)]
            apart=[ct.components[0],ring.zeros(a)];compacts=[]
            for j,digit in enumerate(digits):
                compact,full=ring.hoist(digit,a,r)
                if r==8 and (cache is not None or observations is not None):compacts.append(compact)
                if cache is None or r!=8:
                    multipliers=ring.terminal_multipliers(compact,a) if r==1 else None
                    for index in range(r+1):
                        name=f'h{r}_{index}' if index<r else f'h{r}_identity'
                        mult=multipliers[index] if r==1 else ring.paid_multiplier(compact,a,r,index)
                        for v in range(2):hparts[v]=ring.add(hparts[v],ring.point(mult,banks[name].rows[j][v],a),a)
                for v in range(2):apart[v]=ring.add(apart[v],ring.point(full,alignment.rows[j][v],a),a)
            prepared.append((ct,hparts,apart));all_compact.append(compacts)
        if r==8 and cache is not None:
            applied=cache.apply(all_compact)
            for b,(_,hparts,_) in enumerate(prepared):
                hparts[0]=ring.add(hparts[0],applied[b][0],a)
                hparts[1]=applied[b][1]
        if r==8 and observations is not None:
            observations['compact']=all_compact
            observations['source']=[x[0] for x in prepared]
            observations['hasse']=[tuple(x[1]) for x in prepared]
        following=[]
        for b,(ct,hparts,apart) in enumerate(prepared):
            h=state(b,Cipher(f'h{r}',a,tuple(hparts)))
            bypass=state(b,Cipher(alignment.destination,a,tuple(apart)))
            raw=state(b,reference.raw_sum(ring,[(h,bundles[b].inputs[f'u{r}'])]))
            if r==1:
                after=state(b,Cipher('h1',a,(ring.add(raw.components[0],bypass.components[0],a),
                                            ring.add(raw.components[1],bypass.components[1],a),raw.components[2])))
            else:
                product=state(b,reference.relin(ring,raw,banks[f'product{r}_linear'],banks[f'product{r}_quadratic']))
                after=state(b,Cipher(bypass.key,a,tuple(ring.add(x,y,a) for x,y in zip(bypass.components,product.components))))
            following.append(after)
        current=following
    assert all(next(it,None) is None for it in expected)
    return outputs if retain_trace else current
