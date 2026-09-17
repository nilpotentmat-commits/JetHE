from array import array
from composition_full_run import L,M,TAIL,CHAIN,Secret,keygen,make_bank
from paid_hasse_public_v1 import bank_catalog_paid,PK_NAMES

def setup_keys_paid(ring, coins):
    assert ring.length == L and ring.dimension == M and ring.limbs == 4
    profiles = [('s0', 4), ('s1', 4)]
    for stage, r in enumerate(TAIL):
        profiles.extend(((f'h{r}', CHAIN[stage+1]), (f's{stage+2}', CHAIN[stage+1])))
    keys = {}
    for name, limbs in profiles:
        coefficients = coins.ternary('secret/'+name)
        keys[name] = Secret(name, limbs, coefficients, ring.lift(coefficients, limbs))
    pks = {name: keygen(ring, coins, keys[name]) for name in PK_NAMES}
    banks = {}
    error_start = coins.errors
    for name, src, dst, limbs, kind in bank_catalog_paid():
        if kind == 'linear':
            payload = keys[src].spectra
        elif kind == 'quadratic':
            payload = ring.point(keys[src].spectra, keys[src].spectra, limbs)
        else:
            r_text, index_text = name[1:].split('_')
            r, index = int(r_text), int(index_text)
            assert kind == f'H{r}(t^{index}s)'
            physical = array('q', [0])*M
            for t in range(L):
                target = (t+index) % L
                sign = -1 if t+index >= L else 1
                if target&r:
                    physical[(target-r)*256:(target-r+1)*256] = array('q', (
                        sign*x for x in keys[src].coefficients[t*256:(t+1)*256]))
            payload = ring.lift(physical, limbs)
        banks[name] = make_bank(ring, coins, keys[src], keys[dst], payload, name, kind)
    assert len(keys) == 10 and len(pks) == 5 and len(banks) == 33
    assert sum(len(bank.rows) for bank in banks.values()) == 149
    assert coins.errors-error_start == 149
    return keys, pks, banks

