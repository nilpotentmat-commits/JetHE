from hashlib import sha256

def expected_states(ring, lanes, inverse):
    """Private checker only: direct plaintext operations, independent of ciphertext code."""
    from array import array
    import measure_composition_native as old
    expected = {}
    current = array('H', lanes['f0'])
    for i in range(1, 16):
        term = ring.series(lanes[f'f{i}'], lanes[f'w{i}'], old.L)
        current = array('H', (x ^ y for x, y in zip(current, term)))
    expected['prefix_raw'] = expected['prefix'] = old.encode_lanes(current, inverse)
    last = 4
    for stage, r in enumerate(old.TAIL):
        a = old.CHAIN[stage+1]
        if a != last:
            expected[f'drop{r}'] = old.encode_lanes(current, inverse)
        h = array('H', (value for lane in range(16)
                       for value in old.mixed_hasse(current[lane*old.L:(lane+1)*old.L], r)))
        expected[f'hasse{r}'] = old.encode_lanes(h, inverse)
        expected[f'bypass{r}'] = old.encode_lanes(current, inverse)
        product = ring.series(h, lanes[f'u{r}'], old.L)
        expected[f'product{r}_raw'] = expected[f'product{r}'] = old.encode_lanes(product, inverse)
        current = array('H', (x ^ y for x, y in zip(current, product)))
        expected[f'tail{r}'] = old.encode_lanes(current, inverse)
        last = a
    assert len(expected) == 24
    return expected, current


def check_phase(ring, cipher, secret, bits, bound):
    a = cipher.limbs
    phase = ring.add(cipher.components[0], ring.point(cipher.components[1], secret.spectra, a), a)
    if len(cipher.components) == 3:
        square = ring.point(secret.spectra, secret.spectra, a)
        phase = ring.add(phase, ring.point(cipher.components[2], square, a), a)
    else:
        assert len(cipher.components) == 2
    observed = ring.phase_check(phase, bits, bound, a)
    assert observed <= bound
    # Do not emit observed error values or ciphertext-derived digests.
    return len(bits)

