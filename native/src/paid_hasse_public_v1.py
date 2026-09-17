from composition_full_run import *
from composition_public_evaluator import INPUT_NAMES,PK_NAMES,LIMBS
from check_composition_modulus_chain import drop_noise
CHANGED=frozenset((8,4,2))

def bank_catalog_paid():
    out = []
    for prefix, src, dst in [('prefix', 's0', 's1')] + [
            (f'product{r}', f'h{r}', f's{i+2}') for i, r in enumerate(TAIL)]:
        for kind in ('linear', 'quadratic'):
            out.append((prefix+'_'+kind, src, dst, LIMBS[dst], kind))
    for stage, r in enumerate(TAIL):
        src, dst, result = f's{stage+1}', f'h{r}', f's{stage+2}'
        for i in range(r if r in CHANGED else 2*r):
            out.append((f'h{r}_{i}', src, dst, LIMBS[dst], f'H{r}(t^{i}s)'))
        if r in CHANGED:
            out.append((f'h{r}_identity', src, dst, LIMBS[dst], 'linear'))
        out.append((f'align{r}', src, result, LIMBS[result], 'linear'))
    assert len(out) == 33
    return out


def trace_spec_paid(ring):
    out = []
    delta = lambda a: KAPPA*ring.gadget(a)*(1 << (WIDTH-1))*BETA
    bound = FRESH+15*KAPPA*((1+2*FRESH)*FRESH+FRESH)+(15*KAPPA+1)//2
    out.append(('prefix_raw', 's0', 4, 3, bound))
    bound += 2*delta(4)
    out.append(('prefix', 's1', 4, 2, bound))
    last = 4
    for stage, r in enumerate(TAIL):
        a, src = CHAIN[stage+1], f's{stage+1}'
        if a != last:
            assert last == a+1
            bound = drop_noise(bound, KAPPA, ring.primes[a])
            out.append((f'drop{r}', src, a, 2, bound))
        d = delta(a)
        hb = bound+(3*d//2 if r in CHANGED else d)
        bypass = bound+d
        out.extend(((f'hasse{r}', f'h{r}', a, 2, hb),
                    (f'bypass{r}', f's{stage+2}', a, 2, bypass)))
        pb = KAPPA*((1+2*FRESH)*hb+FRESH)+(KAPPA+1)//2
        out.append((f'product{r}_raw', f'h{r}', a, 3, pb))
        pb += 2*d
        out.append((f'product{r}', f's{stage+2}', a, 2, pb))
        bound = bypass+pb+1
        out.append((f'tail{r}', f's{stage+2}', a, 2, bound))
        last = a
    assert len(out) == 24
    assert all(ring.moduli[a] > 2+4*bound for _, _, a, _, bound in out)
    return out


def bundle_arrays_paid(ring, bundle):
    assert ring.length == L and ring.dimension == M
    assert_public(bundle)
    assert list(bundle.inputs) == INPUT_NAMES
    assert list(bundle.banks) == [x[0] for x in bank_catalog_paid()]
    assert [x.key for x in bundle.public_keys] == PK_NAMES
    arrays = []
    for name in INPUT_NAMES:
        ct = bundle.inputs[name]
        key = 'h'+name[1:] if name.startswith('u') else 's0'
        assert (ct.key, ct.limbs, len(ct.components)) == (key, LIMBS[key], 2)
        for value in ct.components:
            ring.validate(value, ct.limbs)
            arrays.append(value)
    rows = 0
    for name, src, dst, a, payload in bank_catalog_paid():
        bank = bundle.banks[name]
        assert (bank.source, bank.destination, bank.limbs, bank.payload) == (src, dst, a, payload)
        assert src != dst and len(bank.rows) == ring.gadget(a)
        rows += len(bank.rows)
        for row in bank.rows:
            assert len(row) == 2
            for value in row:
                ring.validate(value, a)
                arrays.append(value)
    assert rows == 149
    for ct in bundle.public_keys:
        assert ct.limbs == LIMBS[ct.key] and len(ct.components) == 2
        for value in ct.components:
            ring.validate(value, ct.limbs)
            arrays.append(value)
    return arrays


def packet_schema_paid(ring, response=False):
    records = []
    if response:
        records = [[name, key, a, arity] for name, key, a, arity, _ in trace_spec_paid(ring)]
    else:
        for name in INPUT_NAMES:
            key = 'h'+name[1:] if name.startswith('u') else 's0'
            records.append(['input/'+name, key, LIMBS[key], 2])
        for name, src, dst, a, payload in bank_catalog_paid():
            for j in range(ring.gadget(a)):
                records.append(['bank/'+name+f'/{j}', src, dst, a, 2, payload])
        records.extend(['pk/'+name, name, LIMBS[name], 2] for name in PK_NAMES)
    frames = []
    for rec in records:
        a, arity = (rec[3], rec[4]) if rec[0].startswith('bank/') else (rec[2], rec[3])
        for part in range(arity):
            frames.append(dict(record=rec, part=part, words=a*M))
    assert len(frames) == (53 if response else 378)
    assert sum(x['words']*8 for x in frames) == (90701824 if response else 729808896)
    return dict(version=2, profile='J256-k4-paid-Hasse-v1', response=response,
                length=L, dimension=M, primes=ring.primes, chain=list(CHAIN),
                width=WIDTH, changed_orders=sorted(CHANGED, reverse=True),
                field_polynomial='0x1100b', frames=frames)


def _evaluate_paid(ring, bundle, retain_trace):
    bundle_arrays_paid(ring, bundle)
    inputs, banks = bundle.inputs, bundle.banks
    expected = iter(trace_spec_paid(ring))
    hoist_start = len(ring.hoisted)
    outputs = [] if retain_trace else None

    def state(cipher):
        _, key, limbs, arity, _ = next(expected)
        assert (cipher.key, cipher.limbs, len(cipher.components)) == (key, limbs, arity)
        if outputs is not None:
            outputs.append(cipher)
        return cipher

    raw = state(raw_sum(ring, [(inputs[f'f{i}'], inputs[f'w{i}']) for i in range(1, 16)], inputs['f0']))
    current = state(relin(ring, raw, banks['prefix_linear'], banks['prefix_quadratic']))
    del raw
    for stage, r in enumerate(TAIL):
        a = CHAIN[stage+1]
        if current.limbs != a:
            current = state(Cipher(current.key, a, tuple(ring.drop(x, a+1) for x in current.components)))
        digits = ring.digits(current.components[1], a)
        hparts = [ring.hasse_spectrum(current.components[0], a, r), ring.zeros(a)]
        apart = [current.components[0], ring.zeros(a)]
        alignment = banks[f'align{r}']
        for j, digit in enumerate(digits):
            compact, full = ring.hoist(digit, a, r)
            if r in CHANGED:
                for index in range(r+1):
                    name = f'h{r}_{index}' if index < r else f'h{r}_identity'
                    multiplier = ring.paid_multiplier(compact, a, r, index)
                    for part in range(2):
                        term = ring.point(multiplier, banks[name].rows[j][part], a)
                        hparts[part] = ring.add(hparts[part], term, a)
                    del multiplier
            else:
                for index in range(2*r):
                    for part in range(2):
                        term = ring.relative_point(compact, banks[f'h{r}_{index}'].rows[j][part], a, r, index)
                        hparts[part] = ring.add(hparts[part], term, a)
            for part in range(2):
                apart[part] = ring.add(apart[part], ring.point(full, alignment.rows[j][part], a), a)
        h = state(Cipher(f'h{r}', a, tuple(hparts)))
        bypass = state(Cipher(alignment.destination, a, tuple(apart)))
        del digits, digit, compact, full, term, hparts, apart
        raw = state(raw_sum(ring, [(h, inputs[f'u{r}'])]))
        del h
        product = state(relin(ring, raw, banks[f'product{r}_linear'], banks[f'product{r}_quadratic']))
        del raw
        current = state(Cipher(bypass.key, a, tuple(ring.add(x, y, a) for x, y in zip(bypass.components, product.components))))
        del bypass, product
    assert next(expected, None) is None
    assert ring.hoisted[hoist_start:] == [(a, r) for r, a in zip(TAIL, CHAIN[1:]) for _ in range(ring.gadget(a))]
    return outputs if retain_trace else current


def evaluate_paid_final_output(ring, bundle):
    return _evaluate_paid(ring, bundle, False)


def evaluate_paid_with_trace(ring, bundle):
    return _evaluate_paid(ring, bundle, True)

