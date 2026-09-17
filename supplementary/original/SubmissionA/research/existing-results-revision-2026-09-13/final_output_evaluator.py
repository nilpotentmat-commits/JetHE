"""Final-output variant of the existing J256/k4 public evaluator.

The frozen evaluator remains the reference. This variant changes object
lifetimes and the return interface only; it uses the same arithmetic helpers,
keys, inputs, transforms, digits and prime-drop schedule. It does not load an
arithmetic backend, sample keys, or execute HE merely by being imported.
"""
from pathlib import Path
import sys

RESEARCH = Path(__file__).resolve().parents[1]
if str(RESEARCH) not in sys.path:
    sys.path.insert(0, str(RESEARCH))
import composition_public_evaluator as reference

if Path(reference.__file__).resolve() != RESEARCH / 'composition_public_evaluator.py':
    raise ImportError('The evaluator must use the original local reference module')


def evaluate_final_output(ring, bundle):
    """Return only the final Cipher, validating each transient state's metadata."""
    reference.bundle_arrays(ring, bundle)
    inputs, banks = bundle.inputs, bundle.banks
    expected = iter(reference.trace_spec(ring))
    hoist_start = len(ring.hoisted)

    def state(cipher):
        _, key, limbs, arity, _ = next(expected)
        assert (cipher.key, cipher.limbs, len(cipher.components)) == (key, limbs, arity)
        return cipher

    raw = state(reference.raw_sum(ring, [(inputs[f'f{i}'], inputs[f'w{i}'])
                                        for i in range(1, 16)], inputs['f0']))
    current = state(reference.relin(ring, raw, banks['prefix_linear'], banks['prefix_quadratic']))
    del raw
    for stage, r in enumerate(reference.TAIL):
        a = reference.CHAIN[stage + 1]
        if current.limbs != a:
            current = state(reference.Cipher(current.key, a,
                            tuple(ring.drop(x, a + 1) for x in current.components)))
        digits = ring.digits(current.components[1], a)
        hparts = [ring.hasse_spectrum(current.components[0], a, r), ring.zeros(a)]
        apart = [current.components[0], ring.zeros(a)]
        alignment = banks[f'align{r}']
        for j, digit in enumerate(digits):
            compact, full = ring.hoist(digit, a, r)
            for i in range(2 * r):
                for part in range(2):
                    term = ring.relative_point(compact, banks[f'h{r}_{i}'].rows[j][part], a, r, i)
                    hparts[part] = ring.add(hparts[part], term, a)
            for part in range(2):
                apart[part] = ring.add(apart[part], ring.point(full, alignment.rows[j][part], a), a)
        h = state(reference.Cipher(f'h{r}', a, tuple(hparts)))
        bypass = state(reference.Cipher(alignment.destination, a, tuple(apart)))
        del digits, digit, compact, full, term, hparts, apart
        raw = state(reference.raw_sum(ring, [(h, inputs[f'u{r}'])]))
        del h
        product = state(reference.relin(ring, raw, banks[f'product{r}_linear'], banks[f'product{r}_quadratic']))
        del raw
        current = state(reference.Cipher(bypass.key, a,
                        tuple(ring.add(x, y, a) for x, y in zip(bypass.components, product.components))))
        del bypass, product
    assert next(expected, None) is None
    assert ring.hoisted[hoist_start:] == [(a, r) for r, a in zip(reference.TAIL, reference.CHAIN[1:])
                                        for _ in range(ring.gadget(a))]
    return current
