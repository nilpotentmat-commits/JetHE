"""Terminal JetHE compilation. Public evaluator and explicit private setup.

All untouched stages use the existing paid-Hasse implementation and primitives.
The final stage shares an independent-target identity bank with the bypass and
returns a three-component ciphertext under h1 without final relinearization.
"""
from array import array
import ctypes as C
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
OLD = HERE.parents[1]/'existing-results-revision-2026-09-13'
sys.path[:0] = [str(OLD), str(HERE.parent)]
from composition_full_run import (Cipher, Secret, Bundle, FRESH, KAPPA, BETA,
    WIDTH, L, M, TAIL, CHAIN, keygen, make_bank, relin, raw_sum, assert_public)
from paid_hasse_public_v1 import bank_catalog_paid, trace_spec_paid, PK_NAMES, INPUT_NAMES, LIMBS
from paid_hasse_ring_v1 import PaidHasseRing
from composition_native import pointer, P
from check_composition_modulus_chain import drop_noise


from stage_crypto import SlimRing as TerminalRing
from stage_crypto import make_bank,relin
from bounds import FRESH, CHAIN, trace_spec, WIDTH_BY_VERTEX
LIMBS={"s0":3,"s1":3,"h8":3,"s2":3,"h4":3,"s3":3,"h2":2,"s4":2,"h1":2}


def catalog():
    out = []
    for record in bank_catalog_paid():
        name = record[0]
        if name in ('product1_linear', 'product1_quadratic', 'align1'):
            continue
        if name == 'h1_1':
            record = ('h1_identity', 's4', 'h1', 2, 'linear')
        out.append((record[0],record[1],record[2],LIMBS[record[2]],record[4]))
    assert len(out) == 30
    return out


def spec(ring):
    return trace_spec()


def setup(ring, coins):
    profiles = [('s0',3), ('s1',3)]
    for stage, r in enumerate(TAIL):
        profiles.append((f'h{r}', CHAIN[stage+1]))
        if r != 1:
            profiles.append((f's{stage+2}', CHAIN[stage+1]))
    keys = {}
    for name, a in profiles:
        coeff = coins.ternary('secret/'+name)
        keys[name] = Secret(name, a, coeff, ring.lift(coeff,a))
    pks = {name: keygen(ring, coins, keys[name]) for name in PK_NAMES}
    banks = {}
    for name, src, dst, a, kind in catalog():
        if kind == 'linear':
            payload = keys[src].spectra
        elif kind == 'quadratic':
            payload = ring.point(keys[src].spectra, keys[src].spectra, a)
        else:
            r, index = map(int, name[1:].split('_'))
            physical = array('q',[0])*M
            for t in range(L):
                target = (t+index)%L
                if target&r:
                    sign = -1 if t+index >= L else 1
                    physical[(target-r)*256:(target-r+1)*256] = array('q', (sign*x for x in keys[src].coefficients[t*256:(t+1)*256]))
            payload = ring.lift(physical, a)
        banks[name] = make_bank(ring, coins, keys[src], keys[dst], payload, name, kind)
    assert len(keys) == 9 and len(pks) == 5
    assert sum(len(b.rows) for b in banks.values()) == 102 and coins.errors == 107
    return keys, pks, banks


def validate(ring, bundle):
    assert_public(bundle)
    assert list(bundle.inputs) == INPUT_NAMES
    assert list(bundle.banks) == [x[0] for x in catalog()]
    assert [x.key for x in bundle.public_keys] == PK_NAMES
    for name, ct in bundle.inputs.items():
        key = 'h'+name[1:] if name.startswith('u') else 's0'
        assert (ct.key,ct.limbs,len(ct.components)) == (key,LIMBS[key],2)
        for x in ct.components:
            ring.validate(x, ct.limbs)
    for name,src,dst,a,kind in catalog():
        bank = bundle.banks[name]
        assert (bank.source,bank.destination,bank.limbs,bank.payload) == (src,dst,a,kind)
        assert src != dst and len(bank.rows) == ring.gadget(a,WIDTH_BY_VERTEX[dst])
        for row in bank.rows:
            assert len(row) == 2
            for x in row:
                ring.validate(x,a)
    for pk in bundle.public_keys:
        assert pk.limbs == LIMBS[pk.key] and len(pk.components) == 2
        for x in pk.components:
            ring.validate(x,pk.limbs)


def evaluate(ring, bundle, retain_trace=False):
    validate(ring,bundle)
    inputs,banks = bundle.inputs,bundle.banks
    expected = iter(spec(ring))
    outputs = [] if retain_trace else None
    def state(ct):
        _,key,a,arity,_ = next(expected)
        assert (ct.key,ct.limbs,len(ct.components)) == (key,a,arity)
        if outputs is not None:
            outputs.append(ct)
        return ct
    raw = state(raw_sum(ring,[(inputs[f'f{i}'],inputs[f'w{i}']) for i in range(1,16)],inputs['f0']))
    current = state(relin(ring,raw,banks['prefix_linear'],banks['prefix_quadratic']))
    del raw
    for stage,r in enumerate(TAIL):
        a = CHAIN[stage+1]
        if current.limbs != a:
            current = state(Cipher(current.key,a,tuple(ring.drop(x,a+1) for x in current.components)))
        digits = ring.digits(current.components[1],a,WIDTH_BY_VERTEX[f'h{r}'])
        hparts = [ring.hasse_spectrum(current.components[0],a,r),ring.zeros(a)]
        apart = [current.components[0],ring.zeros(a)]
        alignment = banks['h1_identity' if r == 1 else f'align{r}']
        for j,digit in enumerate(digits):
            compact,full = ring.hoist(digit,a,r)
            if r == 1:
                multipliers = ring.terminal_multipliers(compact,a)
            for index in range(r+1):
                name = f'h{r}_{index}' if index < r else f'h{r}_identity'
                multiplier = multipliers[index] if r == 1 else ring.paid_multiplier(compact,a,r,index)
                for part in range(2):
                    term = ring.point(multiplier,banks[name].rows[j][part],a)
                    hparts[part] = ring.add(hparts[part],term,a)
                del multiplier
            if r == 1:
                del multipliers
            for part in range(2):
                apart[part] = ring.add(apart[part],ring.point(full,alignment.rows[j][part],a),a)
        h = state(Cipher(f'h{r}',a,tuple(hparts)))
        bypass = state(Cipher(alignment.destination,a,tuple(apart)))
        del digits,digit,compact,full,term,hparts,apart
        raw = state(raw_sum(ring,[(h,inputs[f'u{r}'])]))
        del h
        if r == 1:
            current = state(Cipher('h1',a,(ring.add(raw.components[0],bypass.components[0],a),
                ring.add(raw.components[1],bypass.components[1],a),raw.components[2])))
        else:
            product = state(relin(ring,raw,banks[f'product{r}_linear'],banks[f'product{r}_quadratic']))
            current = state(Cipher(bypass.key,a,tuple(ring.add(x,y,a) for x,y in zip(bypass.components,product.components))))
            del product
        del raw,bypass
    assert next(expected,None) is None
    return outputs if retain_trace else current

