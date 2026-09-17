"""Execute exact kernel and finite-source HE primitive checks in Linux/WSL.

Fresh secrets and OS tapes are not saved. Deterministic public arithmetic
fixtures are identified separately. A receipt binds the actual execution;
replay creates a new receipt and new source coins, never a pretend rerun.
"""
import argparse
from array import array
from hashlib import sha256, shake_256
import json
from math import gcd
import os
from pathlib import Path
import platform
from random import Random
import resource
import sys
from time import perf_counter

from arithmetic import GMP, RealRing, centered, nearest, scale_round, decompose, choose_radix
from codec import Codec, ASSETS, binary_multiply, binary_remainder

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CONTROL = HERE.parent/'factored-control-v1'
SOURCE = HERE.parent/'control-sampler-v1'
sys.path.insert(0, str(SOURCE))
import sample_vectors


def bind(path):
    return dict(bytes=path.stat().st_size, sha256=sha256(path.read_bytes()).hexdigest())


def digest_vector(values, modulus):
    width = (modulus.bit_length()+7)//8
    h = sha256()
    for value in values:
        h.update((value % modulus).to_bytes(width, 'little'))
    return h.hexdigest()


def small_checks(backend):
    rng, checked = Random(2026091465537), 0
    for p in (3, 5, 7, 11, 17, 41):
        ring, python_ring = RealRing(p, backend), RealRing(p)
        for modulus in (2, 17, 256, 65535, (1 << 1066)-1):
            for _ in range(3):
                a = [rng.randrange(-modulus, modulus) for _ in range(ring.n)]
                b = [rng.randrange(-modulus, modulus) for _ in range(ring.n)]
                exact = ring.slow_mul(a, b, modulus)
                assert exact == ring.mul(a, b, modulus) == python_ring.mul(a, b, modulus)
                checked += ring.n
    round_checks = 0
    for q in (17, 31, 128, 257):
        for x in range(-4*q*q, 4*q*q+1):
            rounded = nearest(2*x, q) % q
            assert nearest(2*(x % (q*q)), q) % q == rounded
            assert nearest(2*(x + q*q), q) % q == rounded
            round_checks += 1
        # Reducing the raw integer tensor to q is not a valid substitute.
        assert any(nearest(2*(x % q), q) % q != nearest(2*x, q) % q for x in range(q*q))
    digits_checked = 0
    for modulus in (17, 257, 65535, (1 << 1066)-1, ((1 << 1066)-1)*((1 << 533)-3)):
        for count in (2, 4):
            values = [0, 1, -1, modulus//2, -modulus//2, modulus-1]
            radix = choose_radix(modulus, count)
            digits = decompose(values, modulus, radix, count)
            assert all(sum(digits[j][i]*radix**j for j in range(count)) == centered(x, modulus)
                       for i, x in enumerate(values))
            digits_checked += len(values)
    return dict(independent_ring_coefficients=checked, integer_rounding_cases=round_checks,
                balanced_digit_endpoints=digits_checked, wrong_mod_q_tensor_reduction_detected=True)


class Source:
    def __init__(self):
        self.tables = sample_vectors.load_tables()
        self.vectors, self.source_bytes, self.uniform_bytes, self.uniform_vectors = 0, 0, 0, 0
        self.caps = 0

    def sample(self):
        length = 32*(sample_vectors.N+1)+1
        coins = os.urandom(length)
        values, capped = sample_vectors.vector(self.tables, coins)
        self.vectors += 1
        self.source_bytes += length
        self.caps += int(capped)
        return list(values)

    def uniform(self, modulus):
        bits, length = modulus.bit_length(), (modulus.bit_length()+7)//8
        mask = (1 << bits)-1
        raw = os.urandom(sample_vectors.N*length)
        self.uniform_bytes += len(raw)
        out = []
        for i in range(sample_vectors.N):
            value = int.from_bytes(raw[i*length:(i+1)*length], 'little') & mask
            for attempt in range(256):
                if value < modulus:
                    break
                if attempt == 255:
                    raise RuntimeError('Uniform rejection cap reached: this primitive trial aborts.')
                value = int.from_bytes(os.urandom(length), 'little') & mask
                self.uniform_bytes += length
            out.append(value)
        self.uniform_vectors += 1
        return out


class HE:
    def __init__(self, ring, source, q, P):
        self.ring, self.source, self.q, self.P, self.M = ring, source, q, P, q*P
        self.rows, self.encryptions, self.ring_products = 0, 0, 0

    def mul(self, a, b, modulus):
        self.ring_products += 1
        return self.ring.mul(a, b, modulus)

    def row(self, payload, secret, modulus):
        a, error = self.source.uniform(modulus), self.source.sample()
        b = self.ring.add(self.ring.add(payload, error, modulus),
                          self.ring.scale(self.mul(a, secret, modulus), -1, modulus), modulus)
        self.rows += 1
        return b, a

    def public_key(self, secret):
        return self.row([0]*self.ring.n, secret, self.q)

    def encrypt(self, message, public):
        u, e0, e1 = (self.source.sample() for _ in range(3))
        q, ring = self.q, self.ring
        c0 = ring.add(ring.add(self.mul(public[0], u, q), e0, q), ring.scale(message, q//2, q), q)
        c1 = ring.add(self.mul(public[1], u, q), e1, q)
        self.encryptions += 1
        return c0, c1

    def phase(self, ciphertext, secret):
        return self.ring.add(ciphertext[0], self.mul(ciphertext[1], secret, self.q), self.q)

    def check_plaintext(self, ciphertext, secret, expected):
        phase = self.phase(ciphertext, secret)
        decoded = [nearest(2*centered(x, self.q), self.q) % 2 for x in phase]
        error = [centered(x-(self.q//2)*bit, self.q) for x, bit in zip(phase, expected)]
        assert decoded == expected
        error_max = max(map(abs, error))
        assert 4*error_max < self.q-1
        return dict(coefficients=len(decoded), decoded_sha256=sha256(bytes(decoded)).hexdigest(),
                    maximum_error=str(error_max), strict_quarter_modulus=True)

    def hints(self, payload, target, input_modulus, factor):
        radix = choose_radix(input_modulus, 2)
        rows = [self.row(self.ring.scale(payload, factor*radix**j, self.M), target, self.M)
                for j in range(2)]
        return radix, rows

    def accumulate(self, base, component, hints, input_modulus):
        radix, rows = hints
        digits = decompose(component, input_modulus, radix, 2)
        out = [list(c) for c in base]
        for digit, row in zip(digits, rows):
            for i in range(2):
                out[i] = self.ring.add(out[i], self.mul(digit, row[i], self.M), self.M)
        return out

    def down(self, ciphertext):
        return [scale_round([centered(x, self.M) for x in c], 1, self.P, self.q) for c in ciphertext]

    def switch(self, ciphertext, source_secret, target):
        bank = self.hints(source_secret, target, self.q, self.P)
        base = [self.ring.scale(ciphertext[0], self.P, self.M), [0]*self.ring.n]
        return self.down(self.accumulate(base, ciphertext[1], bank, self.q))

    def diagonal(self, ciphertext, source_secret, target, exponent, mask):
        # Direct single diagonal: automorphism then fresh-key map switch at M.
        # The complete BSGS graph still requires separate helper/giant banks.
        lifted = [self.ring.auto(self.ring.scale(c, self.P, self.M), exponent, self.M) for c in ciphertext]
        payload = self.ring.auto(source_secret, exponent, self.M)
        bank = self.hints(payload, target, self.M, 1)
        switched = self.accumulate([lifted[0], [0]*self.ring.n], lifted[1], bank, self.M)
        return self.down([self.mul(mask, component, self.M) for component in switched])

    def product(self, a, b, sa, sb, target):
        q, ring = self.q, self.ring
        left = [[centered(x, q) for x in c] for c in a]
        right = [[centered(x, q) for x in c] for c in b]
        tensor = {(i, j): scale_round(self.mul(left[i], right[j], q*q), 2, q, q)
                  for i in range(2) for j in range(2)}
        base = [ring.scale(tensor[0, 0], self.P, self.M), [0]*ring.n]
        omitted = [list(c) for c in base]
        # Different secrets require both identities plus their product.
        for index, (coefficient, payload) in enumerate(((tensor[1, 0], sa), (tensor[0, 1], sb),
                                                       (tensor[1, 1], self.mul(sa, sb, self.M)))):
            bank = self.hints(payload, target, q, self.P)
            previous = base
            base = self.accumulate(previous, coefficient, bank, q)
            if index:
                for i in range(2):
                    delta = ring.add(base[i], ring.scale(previous[i], -1, self.M), self.M)
                    omitted[i] = ring.add(omitted[i], delta, self.M)
        return self.down(base), self.down(omitted)


def production_checks(backend):
    began = perf_counter()
    ring, codec = RealRing(65537, backend), Codec(backend)
    print(json.dumps(dict(stage='codec_built', seconds=perf_counter()-began)), flush=True)
    # Old full-dimensional public fixture gives an external coefficient chart.
    old = ASSETS.parent
    raw = [list((old/f'prime-physical-plaintext-{i}-v1.bin').read_bytes()) for i in range(2)]
    assert all(len(v)==65536 and v==v[::-1] for v in raw)
    inputs = [v[:ring.n] for v in raw]
    slots = [codec.decode(v) for v in inputs]
    original_tape = shake_256(b'full prime receiver subfield CRT v1').digest(4*2048)
    original_slots = [[int.from_bytes(original_tape[2*(i*2048+j):2*(i*2048+j+1)], 'little')
                       for j in range(2048)] for i in range(2)]
    assert slots == original_slots
    for values, encoded in zip(slots, inputs):
        assert codec.encode(values) == encoded
    public_product = ring.mul(*inputs, 2)
    field_product = [codec.unembed[codec.field_mul(codec.embedding[a], codec.embedding[b])]
                     for a, b in zip(*slots)]
    assert codec.decode(public_product) == field_product
    direct = (0, 1, 37, 2047)
    assert codec.direct_slots(public_product, direct) == [field_product[t] for t in direct]
    assert ring.mul(inputs[0], ring.scalar(1, 2), 2) == inputs[0]
    print(json.dumps(dict(stage='full_codec_and_field_product_pass', slots=2048)), flush=True)
    q, P = (1 << 1066)-1, (1 << 533)-3
    assert (q.bit_length(), P.bit_length()) == (1066, 533)
    assert gcd(q, P) == gcd(q*P, 2*65537) == 1
    profile = json.loads((CONTROL/'width16.json').read_text())['search']['selected']
    assert profile['q_bits'] == q.bit_length() and profile['P_bits'] == P.bit_length()
    assert 1 << 1065 <= q < 1 << 1066 and 1 << 532 <= P < 1 << 533
    # Dense arithmetic at q, qP and q^2, separately from encrypted trials.
    rng, arithmetic = Random(20260914), []
    for modulus in (q, q*P, q*q):
        a, b = [[rng.randrange(modulus) for _ in range(ring.n)] for _ in range(2)]
        product = ring.mul(a, b, modulus)
        assert ring.mul(a, ring.scalar(1, modulus), modulus) == a
        # Direct cyclic-convolution coefficients, not the packed-int code.
        aa, bb = ring.embed(a, modulus), ring.embed(b, modulus)
        constant = sum(aa[i]*bb[-i % ring.p] for i in range(ring.p))
        for j in (1, 2, 37, 32768):
            expected = (sum(aa[i]*bb[(j-i) % ring.p] for i in range(ring.p))-constant) % modulus
            assert product[j-1] == expected
        exponent = 3
        assert ring.auto(product, exponent, modulus) == ring.mul(ring.auto(a, exponent, modulus),
                                                               ring.auto(b, exponent, modulus), modulus)
        arithmetic.append(dict(modulus_bits=modulus.bit_length(), direct_coefficients=4,
                               dense_product_sha256=digest_vector(product, modulus)))
    print(json.dumps(dict(stage='large_modulus_arithmetic_pass')), flush=True)
    source = Source()
    he = HE(ring, source, q, P)
    secrets = [source.sample() for _ in range(5)]
    public = [he.public_key(s) for s in secrets[:2]]
    ciphertexts = [he.encrypt(m, pk) for m, pk in zip(inputs, public)]
    tests = [dict(name='fresh_owner_'+str(i), **he.check_plaintext(c, s, m))
             for i, (c, s, m) in enumerate(zip(ciphertexts, secrets, inputs))]
    switched = he.switch(ciphertexts[0], secrets[0], secrets[2])
    tests.append(dict(name='ordinary_independent_key_switch', **he.check_plaintext(switched, secrets[2], inputs[0])))
    # A full, independently chosen public mask is encoded in the actual chart.
    mask_words = array('H')
    mask_words.frombytes(shake_256(b'real receiver public diagonal mask 2026-09-14').digest(4096))
    mask = codec.encode(mask_words)
    expected = ring.mul(ring.auto(inputs[0], 3, 2), mask, 2)
    diagonal = he.diagonal(ciphertexts[0], secrets[0], secrets[3], 3, mask)
    tests.append(dict(name='single_diagonal_automorphism_and_mask', **he.check_plaintext(diagonal, secrets[3], expected)))
    product, omitted = he.product(ciphertexts[0], ciphertexts[1], secrets[0], secrets[1], secrets[4])
    tests.append(dict(name='different_key_scaled_BFV_product', **he.check_plaintext(product, secrets[4], public_product)))
    # Decrypt/codec the actual encrypted product at every field slot.
    phase = he.phase(product, secrets[4])
    decoded = [nearest(2*centered(x, q), q) % 2 for x in phase]
    assert codec.decode(decoded) == field_product
    wrong_phase = he.phase(omitted, secrets[4])
    wrong = [nearest(2*centered(x, q), q) % 2 for x in wrong_phase]
    changed = sum(a != b for a, b in zip(wrong, public_product))
    assert changed > 0, 'Omitted-identity negative fixture did not distinguish this sample.'
    print(json.dumps(dict(stage='fresh_source_primitive_pass', trials=len(tests), source_vectors=source.vectors)), flush=True)
    return dict(conductor=65537, dimension=ring.n, field_slots=2048,
                q=str(q), P=str(P), modulus_bits=[q.bit_length(), P.bit_length(), (q*P).bit_length()],
                modulus_scope='Concrete odd coprime moduli inside the selected admitted bit intervals; no primality or hardness claim.',
                codec=dict(roundtrip_field_slots=4096, inverse_coordinate_basis_checks=65536,
                           original_fixture_slot_order_checks=4096,
                           full_field_product_slots=2048, original_root_oracle_slots=list(direct),
                           encrypted_product_field_slots=2048),
                arithmetic=arithmetic, primitive_tests=tests,
                sources=dict(finite_vectors=source.vectors, finite_os_bytes=source.source_bytes,
                             capped_vectors=source.caps, uniform_vectors=source.uniform_vectors,
                             uniform_os_bytes=source.uniform_bytes,
                             source_law='Existing capped globally signed 257-table law; fresh os.urandom tapes.',
                             uniform_law='Exact bit-masked rejection; abort on the bounded rejection cap.'),
                he=dict(primitive_public_rows=he.rows, owner_encryptions=he.encryptions,
                        instrumented_ring_products=he.ring_products,
                        omitted_identity_changes_plaintext_bits=changed),
                diagnostic_seconds=perf_counter()-began)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--small-only', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.parent == HERE and not output.exists(), 'Use an exclusive receipt in this directory.'
    paths = [HERE/x for x in ('PLAN.md', 'arithmetic.py', 'codec.py', 'check_kernels.py')]
    paths += [ASSETS, CONTROL/'width16.json', SOURCE/'sample_vectors.py', SOURCE/'tables.bin', SOURCE/'table-receipt.json']
    paths += [ASSETS.parent/f'prime-physical-plaintext-{i}-v1.bin' for i in range(2)]
    before = {p.relative_to(ROOT).as_posix(): bind(p) for p in paths}
    start = perf_counter()
    backend = GMP()
    small = small_checks(backend)
    print(json.dumps(dict(stage='small_independent_arithmetic_pass', **small)), flush=True)
    production = None if args.small_only else production_checks(backend)
    after = {p.relative_to(ROOT).as_posix(): bind(p) for p in paths}
    assert before == after
    result = dict(status='REAL_PERIOD_RECEIVER_KERNEL_CHECKS_PASS' if production else 'SMALL_KERNEL_CHECKS_PASS',
                  small=small, production=production, bindings=after, backend=backend.binding(),
                  execution=dict(platform=platform.platform(), python=sys.version, executable=sys.executable,
                                 peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                                 elapsed_seconds=perf_counter()-start, affinity=sorted(os.sched_getaffinity(0)),
                                 timing_scope='Diagnostic elapsed values; no controlled timing campaign or total-workflow result.'),
                  scope='Fresh selected-dimension arithmetic, codec and HE primitive trials. No full compiled control execution, 128-bit qualification, total-time ordering, or EUROCRYPT readiness claim.')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=result['status'], receipt=output.name, elapsed_seconds=result['execution']['elapsed_seconds'])), flush=True)


if __name__ == '__main__':
    main()
