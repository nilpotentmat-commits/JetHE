"""Public RNS arithmetic admission/accounting; no HE keys or benchmark timings.

Ciphertext q is a product of certified transform primes, not an auxiliary
integer-convolution modulus. The fresh phase bound is derived from encryption.
The earlier Mersenne phase-class frontier remains a distinct diagnostic.
"""

from math import gcd, isqrt, prod
from random import Random
import json

from check_fused_composition_frontier import FastField, fused_maps, methods, level_options
from check_prepared_arithmetic import (Arithmetic, Counts, NTT, NormalCyclotomic,
                                       Dyadic, OddPower, tensor_run, expected_axis_counts)


CONDUCTOR = 512 * 65535
KAPPA_J, KAPPA_C, BETA = 511 * 256, 332661, 20
CERTIFICATES = [
    (1152921504002872321, 38, [(2, 10), (3, 2), (5, 1), (17, 1), (47, 1), (257, 1), (2617, 1), (46559, 1)]),
    (1152921503566671361, 14, [(2, 9), (3, 1), (5, 1), (17, 1), (191, 1), (257, 1), (179896663, 1)]),
    (1152921503264686081, 7, [(2, 14), (3, 1), (5, 1), (17, 1), (257, 1), (1073758207, 1)]),
    (1152921503096916481, 13, [(2, 9), (3, 2), (5, 1), (17, 1), (257, 1), (11453420873, 1)]),
    (1152921503063362561, 31, [(2, 10), (3, 1), (5, 1), (11, 1), (17, 1), (29, 1), (257, 1), (601, 1), (89611, 1)]),
    (1152921502794931201, 11, [(2, 10), (3, 2), (5, 2), (17, 1), (257, 1), (1145342087, 1)]),
    (1152921502560053761, 13, [(2, 9), (3, 1), (5, 1), (17, 1), (23, 1), (109, 1), (257, 1), (1319, 1), (10391, 1)]),
    (1152921501922529281, 11, [(2, 12), (3, 1), (5, 1), (17, 1), (257, 1), (3911, 1), (1098193, 1)]),
]


def verify_certificate(certificate):
    prime, generator, factors = certificate
    assert len({r for r, _ in factors}) == len(factors)
    assert prod(r**e for r, e in factors) == prime - 1
    for r, _ in factors:
        assert r >= 2 and all(r % d for d in range(2, isqrt(r) + 1))
        assert gcd(pow(generator, (prime - 1) // r, prime) - 1, prime) == 1
    assert pow(generator, prime - 1, prime) == 1
    assert prime.bit_length() == 60 and (prime - 1) % CONDUCTOR == 0
    root = pow(generator, (prime - 1) // CONDUCTOR, prime)
    assert pow(root, CONDUCTOR, prime) == 1
    assert all(pow(root, CONDUCTOR // r, prime) != 1 for r in (2, 3, 5, 17, 257))


def provision_certificates():
    # Five additional primes were found by a bounded downward scan once.
    # Reproduction verifies the recorded exact certificates; no search reruns.
    certificates = list(CERTIFICATES)
    assert len(certificates) == len({c[0] for c in certificates}) == 8
    for certificate in certificates:
        verify_certificate(certificate)
    return certificates


def recover_garner(residues, primes, inverses):
    """Exact mixed-radix CRT; constants are precomputed outside each call."""
    digits, modular_products = [], 0
    for i, (residue, prime) in enumerate(zip(residues, primes)):
        digit = residue
        for j in range(i):
            digit = (digit - digits[j]) * inverses[j, i] % prime
            modular_products += 1
        digits.append(digit)
    value, growing_products = digits[-1], 0
    for i in range(len(primes) - 2, -1, -1):
        value = value * primes[i] + digits[i]
        growing_products += 1
    modulus = prod(primes)
    return (value if value <= modulus // 2 else value - modulus,
            modular_products, growing_products)


def chunk_digits(value, width, gadget):
    """Chunk/carry version of the existing iterative balanced digit map.

    The final digit may equal +2**(width-1), so its container needs w+1
    signed bits. The loop never divides a growing integer by the gadget base.
    """
    base, bound = 1 << width, 1 << (width - 1)
    unsigned, carry, result = value % (base**gadget), 0, []
    octets = unsigned.to_bytes((width * gadget + 7) // 8, 'little')
    position, buffer, available = 0, 0, 0
    for i in range(gadget):
        while available < width:
            buffer |= octets[position] << available
            position += 1
            available += 8
        chunk = buffer & (base - 1)
        buffer >>= width
        available -= width
        if i == gadget - 1:
            result.append(chunk - base * int(value < 0) + carry)
        else:
            chunk += carry
            carry = int(chunk >= bound)
            result.append(chunk - base * carry)
    return result


def conversion_checks(certificates):
    rng, crt_cases, digit_cases, positive_top = Random(2026090821), 0, 0, 0
    for channels in range(1, 9):
        primes = [c[0] for c in certificates[:channels]]
        q = prod(primes)
        inverses = {(j, i): pow(primes[j], -1, primes[i])
                    for i in range(channels) for j in range(i)}
        values = [0, 1, -1, q // 2, -(q // 2)]
        values += [rng.randrange(-(q // 2), q // 2 + 1) for _ in range(16)]
        for x in values:
            y, modular, growing = recover_garner([x % p for p in primes], primes, inverses)
            assert (y, modular, growing) == (x, channels * (channels - 1) // 2, channels - 1)
            crt_cases += 1
        for width in (8, 16, 24, 32, 40, 48, 56, 60):
            gadget, base, bound = (q.bit_length() + width - 1) // width, 1 << width, 1 << (width - 1)
            fixtures = list(values)
            for i in range(gadget):
                for sign in (-1, 1):
                    for offset in (-1, 0, 1):
                        x = sign * ((bound << (width * i)) + offset)
                        if abs(x) <= q // 2:
                            fixtures.append(x)
            for x in fixtures:
                ds = chunk_digits(x, width, gadget)
                reference, y = [], x
                for _ in range(gadget - 1):
                    digit = (y + bound) % base - bound
                    reference.append(digit)
                    y = (y - digit) // base
                reference.append(y)
                assert ds == reference and max(map(abs, ds)) <= bound
                assert sum(d * base**i for i, d in enumerate(ds)) == x
                assert all([d if d >= 0 else p + d for d in ds] == [d % p for d in ds] for p in primes)
                positive_top += ds[-1] == bound
                digit_cases += 1
    assert positive_top
    return {'exact_garner_cases': crt_cases, 'balanced_digit_cases': digit_cases,
            'positive_maximum_final_digit_cases': positive_top}


def native_noise(gadget, width=8):
    fresh = (2 * KAPPA_J + 1) * BETA
    lam, terms = 511 * gadget * (1 << (width - 1)) * BETA, 15
    noise = (fresh + terms * KAPPA_J * ((1 + 2 * fresh) * fresh + fresh)
             + (terms * KAPPA_J + 1) // 2 + 512 * lam)
    stages = [fresh, noise]
    for _ in range(4):
        noise = (noise + 768 * lam + KAPPA_J * ((1 + 2 * fresh) * (noise + 256 * lam) + fresh)
                 + (KAPPA_J + 1) // 2 + 1)
        stages.append(noise)
    return stages


def conventional_noise(gadget, selected, width=8):
    fresh = (2 * KAPPA_C + 1) * BETA
    lam, terms = KAPPA_C * gadget * (1 << (width - 1)) * BETA, 15
    noise = (fresh + terms * KAPPA_C * ((1 + 2 * fresh) * fresh + fresh)
             + (terms * KAPPA_C + 1) // 2 + 2 * lam)
    stages = [fresh, noise]
    for weights, option in selected:
        pre, odd, even = weights
        pm = next(m for m in methods([pre], prune=False) if m['name'] == option['pre'])
        qm = next(m for m in methods([odd, even], option['raw'], prune=False) if m['name'] == option['post'])
        p, h = len(pre), len(odd) + len(even)
        before_product = p * KAPPA_C * noise + pm['switch'] * lam + (p * KAPPA_C + 1) // 2
        product_bound = KAPPA_C * ((1 + 2 * fresh) * before_product + fresh) + (KAPPA_C + 1) // 2
        if not option['raw']:
            product_bound += 2 * lam
        noise = (KAPPA_C * (h * product_bound + noise) + (qm['switch'] + 1) * lam
                 + ((h + 1) * KAPPA_C + 1) // 2)
        stages.extend((before_product, product_bound, noise))
    return stages


def admit_rns(certificates, noise_function, width=8):
    q = 1
    for count, (prime, _generator, _factors) in enumerate(certificates, 1):
        q *= prime
        bits, gadget = q.bit_length(), (q.bit_length() + width - 1) // width
        stages = noise_function(gadget)
        if q > 2 + 4 * max(stages):
            return {'channels': count, 'q': q, 'bits': bits, 'gadget': gadget,
                    'digit_width': width,
                    'fresh_noise': stages[0], 'final_noise': stages[-1],
                    'margin': q - 2 - 4 * max(stages)}
    raise AssertionError('No admitted prefix of certified primes')


class OddNormal:
    def __init__(self, conductor, prime, generator):
        self.power = OddPower(conductor, prime, generator)
        self.n, self.r, self.p, self.root = self.power.n, conductor, prime, self.power.root

    def run(self, values, arithmetic, inverse=False):
        if inverse:
            recovered = self.power.run(values, arithmetic, inverse=True)
            return [arithmetic.sub(x, recovered[0]) for x in recovered[1:]] + [arithmetic.neg(recovered[0])]
        converted = [arithmetic.neg(values[-1])] + [arithmetic.sub(x, values[-1]) for x in values[:-1]]
        return self.power.run(converted, arithmetic)


def normal_axis(conductor, prime, generator):
    index_generator = next(a for a in range(2, conductor)
                           if pow(a, (conductor - 1) // 2, conductor) != 1)
    return NormalCyclotomic(conductor, index_generator, pow(generator, (prime - 1) // conductor, prime), prime, generator)


def axis_counts(axis, inverse=False):
    if isinstance(axis, OddNormal):
        base = expected_axis_counts(axis.power, inverse)
        return base + Counts(0, axis.r - 2, 1)
    return expected_axis_counts(axis, inverse)


def full_counts(axes, inverse=False):
    dimension = prod(a.n for a in axes)
    result = Counts()
    for axis in axes:
        result += axis_counts(axis, inverse) * (dimension // axis.n)
    return result


def hasse_fibers(spectrum, r, length, extension, prime, generator, arithmetic):
    """Integral H_r in the split-root spectrum, with a truncated forward FFT."""
    h, blocks = 2 * r, length // (2 * r)
    root = pow(generator, (prime - 1) // (2 * length), prime)
    inverse = NTT(h, pow(root, -2 * blocks, prime), prime)
    forward = NTT(r, pow(root, 4 * blocks, prime), prime)
    odd_root = pow(root, 2 * blocks, prime)
    twists = [pow(odd_root, i, prime) for i in range(r)]
    result = [0] * len(spectrum)
    for j in range(blocks):
        scale = pow(h * pow(root, (2 * j + 1) * r, prime), -1, prime)
        for e in range(extension):
            values = [spectrum[(j + blocks * k) * extension + e] for k in range(h)]
            coefficients = inverse.run(values, arithmetic)[r:]
            coefficients = [arithmetic.mul(x, scale) for x in coefficients]
            even = forward.run(coefficients, arithmetic)
            twisted = [coefficients[0]] + [arithmetic.mul(x, w) for x, w in zip(coefficients[1:], twists[1:])]
            odd = forward.run(twisted, arithmetic)
            for k, value in enumerate(even):
                result[(j + blocks * (2 * k)) * extension + e] = value
            for k, value in enumerate(odd):
                result[(j + blocks * (2 * k + 1)) * extension + e] = value
    return result


def public_transform_checks():
    rng, basis_cases, roundtrips, h_cases = Random(2026090811), 0, 0, 0
    prime, generator, _ = CERTIFICATES[0]
    native_axes = [Dyadic(256, prime, generator), normal_axis(257, prime, generator)]
    conventional_axes = [OddNormal(3, prime, generator), OddNormal(5, prime, generator),
                         normal_axis(17, prime, generator), normal_axis(257, prime, generator)]
    for axes in (native_axes, conventional_axes):
        for axis in axes:
            for index in range(axis.n):
                source = [int(i == index) for i in range(axis.n)]
                arithmetic = Arithmetic(prime)
                encoded = axis.run(source, arithmetic)
                exponent = index if isinstance(axis, Dyadic) else index + 1
                points = range(1, 2 * axis.n, 2) if isinstance(axis, Dyadic) else range(1, axis.r)
                assert encoded == [pow(axis.root, exponent * point, prime) for point in points]
                assert arithmetic.count == axis_counts(axis)
                arithmetic = Arithmetic(prime)
                assert axis.run(encoded, arithmetic, inverse=True) == source
                assert arithmetic.count == axis_counts(axis, True)
                basis_cases += 1
        source = [rng.randrange(prime) for _ in range(prod(a.n for a in axes))]
        arithmetic = Arithmetic(prime)
        encoded = tensor_run(source, axes, arithmetic)
        assert arithmetic.count == full_counts(axes)
        arithmetic = Arithmetic(prime)
        assert tensor_run(encoded, axes, arithmetic, inverse=True) == source
        assert arithmetic.count == full_counts(axes, True)
        roundtrips += 1
        if axes is native_axes:
            for r in (8, 4, 2, 1):
                target = [0] * len(source)
                for t in range(256):
                    if t & r:
                        target[(t - r) * 256:(t - r + 1) * 256] = source[t * 256:(t + 1) * 256]
                arithmetic = Arithmetic(prime)
                transformed = hasse_fibers(encoded, r, 256, 256, prime, generator, arithmetic)
                assert transformed == tensor_run(target, axes, Arithmetic(prime))
                h, dimension = 2 * r, 65536
                expected_m = dimension * (2 * h * (h.bit_length() - 1) - 3 * h + 4) // (2 * h)
                assert arithmetic.count == Counts(expected_m, dimension * (2 * (h.bit_length() - 1) - 1))
                h_cases += 1
    return {'axis_basis_columns': basis_cases, 'full_tensor_roundtrips': roundtrips,
            'full_native_hasse_spectral_maps': h_cases,
            'native_forward': full_counts(native_axes).as_dict(),
            'native_inverse': full_counts(native_axes, True).as_dict(),
            'conventional_forward': full_counts(conventional_axes).as_dict(),
            'conventional_inverse': full_counts(conventional_axes, True).as_dict()}


def map_additions(method, count, channels, gadget):
    if method['name'].startswith('direct'):
        return 2 * gadget * method['ext'] + count - 2
    if method['name'].startswith('tree'):
        return 2 * gadget * method['ext'] + 2 * count - 1022 * channels - 2
    giants = method['decompositions'] - channels * (2 if method['name'].endswith('_raw') else 1)
    babies = (method['banks'] - giants) // (2 if method['name'].endswith('_raw') else 1)
    return 2 * gadget * method['ext'] + 2 * count - channels * babies - giants - 2


def priced_conventional_options(weights, gadget, width, channels):
    pre, odd, even = weights
    p, h, fresh = len(pre), len(odd) + len(even), (2 * KAPPA_C + 1) * BETA
    lam = KAPPA_C * gadget * (1 << (width - 1)) * BETA
    options = []
    for pm in methods([pre], prune=False):
        for raw in (False, True):
            for qm in methods([odd, even], raw, prune=False):
                separate = int(not raw)
                decomps = 2 * (pm['decompositions'] + qm['decompositions'] + 4 * separate)
                ext = 2 * (pm['ext'] + qm['ext'] + 1 + 4 * separate)
                public = 2 * (pm['public_products'] + qm['public_products'] + 1)
                point = 2 * gadget * ext + public + 12
                adds = 2 * (map_additions(pm, p, 1, gadget) + map_additions(qm, h, 2, gadget)
                            + (2 * gadget + 1) + 5 + separate * (8 * gadget - 2))
                # The source gain is identical for every choice at this level.
                a = KAPPA_C * (h * KAPPA_C * (1 + 2 * fresh) * p * KAPPA_C + 1)
                before = pm['switch'] * lam + (p * KAPPA_C + 1) // 2
                product_b = KAPPA_C * ((1 + 2 * fresh) * before + fresh) + (KAPPA_C + 1) // 2 + 2 * separate * lam
                z = KAPPA_C * h * product_b + (qm['switch'] + 1) * lam + ((h + 1) * KAPPA_C + 1) // 2
                options.append({'pre': pm['name'], 'post': qm['name'], 'raw': raw,
                                'decomps': decomps, 'ext': ext, 'public': public, 'point': point,
                                'point_add': adds, 'banks': pm['banks'] + qm['banks'] + 1 + 2 * separate,
                                'destinations': pm['destinations'] + qm['destinations'] + separate,
                                'fixed_M': decomps * (gadget * 389376 + 405760),
                                'a': a, 'z': z})
    assert len({o['a'] for o in options}) == 1
    for o in options:
        # Transform/pointwise totals repeat per channel; Garner modular work
        # applies once to the coefficient vector reconstructed across them.
        o['price'] = (channels * (o['fixed_M'] + o['point'] * 32768)
                      + o['decomps'] * 32768 * channels * (channels - 1) // 2)
    return options


def conventional_schedule_receipt(q, channels, width, schedule):
    gadget = (q.bit_length() + width - 1) // width
    fresh, lam = (2 * KAPPA_C + 1) * BETA, KAPPA_C * gadget * (1 << (width - 1)) * BETA
    noise = fresh + 15 * KAPPA_C * ((1 + 2 * fresh) * fresh + fresh) + (15 * KAPPA_C + 1) // 2 + 2 * lam
    for option in schedule:
        noise = option['a'] * noise + option['z']
    decomps, ext = 4 + sum(o['decomps'] for o in schedule), 4 + sum(o['ext'] for o in schedule)
    point = 90 + 8 * gadget + sum(o['point'] for o in schedule)
    point_add = 90 + 8 * gadget + sum(o['point_add'] for o in schedule) + 76
    forwards, inverses = 156 + gadget * decomps, decomps + 4
    fixed_m = channels * (forwards * 389376 + inverses * 405760)
    result = {'channels': channels, 'modulus_bits': q.bit_length(), 'digit_width': width, 'gadget': gadget,
              'final_noise': noise, 'admitted': q > 2 + 4 * noise,
              'decompositions_over_m': decomps, 'crt_coefficients': (decomps + 4) * 32768,
              'digit_coefficients': decomps * gadget * 32768,
              'forwards_per_prime': forwards, 'inverses_per_prime': inverses,
              'banks': 2 + sum(o['banks'] for o in schedule),
              'independent_keys': 2 + sum(o['destinations'] for o in schedule),
              'paired_ext_over_g': ext,
              'transform_multiplications': fixed_m,
              'pointwise_multiplications': channels * point * 32768,
              'additions': channels * ((forwards + inverses) * 991232 + point_add * 32768),
              'negations': channels * (forwards + inverses) * 24576,
              'schedule': [[o['pre'], o['post']] for o in schedule]}
    result['crt_modular_multiplications'] = result['crt_coefficients'] * channels * (channels - 1) // 2
    result['crt_growing_integer_products'] = result['crt_coefficients'] * (channels - 1)
    result['digit_channel_lifts'] = result['digit_coefficients'] * channels
    result['total_field_multiplications'] = (result['transform_multiplications'] + result['pointwise_multiplications']
                                             + result['crt_modular_multiplications'])
    result['additions'] += result['crt_modular_multiplications']
    result['prepared_hint_bytes'] = 2 * result['banks'] * gadget * 32768 * channels * 8
    result['prepared_mask_bytes_upper'] = 2836 * 32768 * channels * 8
    return result


def native_receipt(profile):
    channels, gadget = profile['channels'], profile['gadget']
    forwards, inverses = 70 + 14 * gadget, 16
    fixed_m = channels * (forwards * 721408 + inverses * 721664 + 385024)
    result = {'channels': channels, 'modulus_bits': profile['bits'], 'digit_width': profile['digit_width'],
              'gadget': gadget, 'final_noise': profile['final_noise'],
              'decompositions_over_m': 14, 'crt_coefficients': 16 * 65536,
              'digit_coefficients': 14 * gadget * 65536,
              'forwards_per_prime': forwards, 'inverses_per_prime': inverses,
              'banks': 44, 'independent_keys': 10, 'paired_ext_over_g': 44,
              'transform_multiplications': fixed_m,
              'pointwise_multiplications': channels * (88 * gadget + 57) * 65536,
              'additions': channels * ((forwards + inverses) * 1572864 + (88 * gadget + 103) * 65536),
              'negations': 0,
              'prepared_hint_bytes': 88 * gadget * 65536 * channels * 8,
              'prepared_mask_bytes_upper': 0}
    result['crt_modular_multiplications'] = result['crt_coefficients'] * channels * (channels - 1) // 2
    result['crt_growing_integer_products'] = result['crt_coefficients'] * (channels - 1)
    result['digit_channel_lifts'] = result['digit_coefficients'] * channels
    result['total_field_multiplications'] = (result['transform_multiplications'] + result['pointwise_multiplications']
                                             + result['crt_modular_multiplications'])
    result['additions'] += result['crt_modular_multiplications']
    return result


def arithmetic_scan(certificates, field):
    weights = [fused_maps(b, field) for b in range(5, 9)]
    conventional_rows, native_rows, unresolved, noise_replays = [], [], [], 0
    for width in (8, 16, 24, 32, 40, 48, 56, 60):
        native_rows.append(native_receipt(admit_rns(certificates, lambda g: native_noise(g, width), width)))
        q = 1
        for channels, certificate in enumerate(certificates, 1):
            q *= certificate[0]
            gadget = (q.bit_length() + width - 1) // width
            options = [priced_conventional_options(w, gadget, width, channels) for w in weights]
            schedule = [min(choices, key=lambda o: (o['price'], o['point_add'], o['z'])) for choices in options]
            row = conventional_schedule_receipt(q, channels, width, schedule)
            replay = conventional_noise(gadget, list(zip(weights, schedule)), width)
            assert row['final_noise'] == replay[-1] == max(replay)
            assert row['admitted'] == (q > 2 + 4 * max(replay))
            noise_replays += 1
            if row['admitted']:
                conventional_rows.append(row)
            else:
                smallest_noise = [min(choices, key=lambda o: o['z']) for choices in options]
                # If this ever passes, cost/noise Pareto DP is required; do not
                # silently discard the feasible, higher-cost alternative.
                if conventional_schedule_receipt(q, channels, width, smallest_noise)['admitted']:
                    unresolved.append([channels, width])
    assert not unresolved, f'Noise-constrained arithmetic choices require a Pareto DP: {unresolved}'
    return {'native_rows': native_rows, 'conventional_rows': conventional_rows,
            'independent_stage_noise_replays': noise_replays,
            'native_minimum_field_multiplications': min(native_rows, key=lambda r: r['total_field_multiplications']),
            'conventional_minimum_field_multiplications': min(conventional_rows, key=lambda r: r['total_field_multiplications']),
            'scope': 'Finite direct/BSGS/full-tree family, eight digit widths, eight RNS prefixes; not runtime optimality'}


def main():
    certificates, field = provision_certificates(), FastField()
    selected = []
    for b in range(5, 9):
        weights = fused_maps(b, field)
        option = min(level_options(weights, prune=False), key=lambda o:
                     (o['ext'], o['decompositions'], o['banks'], o['c']))
        selected.append((weights, option))
    native = admit_rns(certificates, native_noise)
    conventional = admit_rns(certificates, lambda g: conventional_noise(g, selected))
    print(json.dumps({'status': 'PUBLIC_RNS_MODULUS_AND_ENCRYPTION_NOISE_ADMISSION_ONLY',
                      'certificates': certificates,
                      'native': native, 'conventional': conventional,
                      'conventional_schedule': [[o['pre'], o['post']] for _, o in selected],
                      'conversion_checks': conversion_checks(certificates),
                      'public_transform_checks': public_transform_checks(),
                      'arithmetic_scan': arithmetic_scan(certificates, field)}, indent=2))


if __name__ == '__main__':
    main()
