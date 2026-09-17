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
OLD = HERE.parent/'existing-results-revision-2026-09-13'
sys.path[:0] = [str(OLD), str(HERE.parent)]
from composition_full_run import (Cipher, Secret, Bundle, FRESH, KAPPA, BETA,
    WIDTH, L, M, TAIL, CHAIN, keygen, make_bank, relin, raw_sum, assert_public)
from paid_hasse_public_v1 import bank_catalog_paid, trace_spec_paid, PK_NAMES, INPUT_NAMES, LIMBS
from paid_hasse_ring_v1 import PaidHasseRing
from composition_native import pointer, P
from check_composition_modulus_chain import drop_noise


class TerminalRing(PaidHasseRing):
    def __init__(self, length=256, limbs=4):
        super().__init__(length, limbs)
        self.terminal_dll = C.CDLL(str(HERE/'build'/'terminal_kernel_v1.so'))
        self.terminal_dll.jet_terminal_multipliers.argtypes = [P,P,P,P,C.c_uint,C.c_uint]
        self.terminal_dll.jet_terminal_multipliers.restype = C.c_int
        coeff = array('q', [0])*self.dimension
        # In the b^1,...,b^256 basis, 1 = -sum b^i.
        coeff[256:512] = array('q', [-1])*256
        self.public_t = self.lift(coeff, min(2, limbs))

    def terminal_multipliers(self, compact, a):
        assert a <= 2
        even, odd = self.zeros(a), self.zeros(a)
        code = self.terminal_dll.jet_terminal_multipliers(
            self.spectrum(compact, a), self.spectrum(self.public_t, a, True),
            pointer(even, 'Q'), pointer(odd, 'Q'), self.length, a)
        assert code == 0
        return even, odd


def catalog():
    out = []
    for record in bank_catalog_paid():
        name = record[0]
        if name in ('product1_linear', 'product1_quadratic', 'align1'):
            continue
        if name == 'h1_1':
            record = ('h1_identity', 's4', 'h1', 2, 'linear')
        out.append(record)
    assert len(out) == 30
    return out


def spec(ring):
    out = trace_spec_paid(ring)[:-5]  # retain final drop, replace only r=1 operations
    assert out[-1][0] == 'drop1'
    bound = out[-1][-1]
    d = KAPPA*ring.gadget(2)*(1 << (WIDTH-1))*BETA
    h, bypass = bound+3*d//2, bound+d
    product = KAPPA*((1+2*FRESH)*h+FRESH)+(KAPPA+1)//2
    out.extend((('hasse1', 'h1', 2, 2, h), ('bypass1', 'h1', 2, 2, bypass),
                ('product1_raw', 'h1', 2, 3, product),
                ('tail1', 'h1', 2, 3, bypass+product+1)))
    assert len(out) == 23 and all(ring.moduli[a] > 2+4*b for _,_,a,_,b in out)
    return out


def setup(ring, coins):
    profiles = [('s0',4), ('s1',4)]
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
    assert sum(len(b.rows) for b in banks.values()) == 140 and coins.errors == 145
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
        assert src != dst and len(bank.rows) == ring.gadget(a)
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
        digits = ring.digits(current.components[1],a)
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


def decrypt(ring,ct,secret,rows):
    from measure_composition_native import decrypt as old_decrypt
    assert (ct.key,ct.limbs,len(ct.components)) == ('h1',2,3)
    square = ring.point(secret.spectra,secret.spectra,2)
    folded = Cipher(ct.key,2,(ring.add(ct.components[0],ring.point(ct.components[2],square,2),2),ct.components[1]))
    return old_decrypt(ring,folded,secret,rows)
