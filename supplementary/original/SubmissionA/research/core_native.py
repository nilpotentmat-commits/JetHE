"""Dimension-generic preparation for the remaining leveled W1/W2 core.

Reuses the frozen arithmetic and public raw-product/rekey primitives.
No benchmark protocol or 128-bit qualification is supplied by this module.
The measured W0 sampler is unchanged; this adapter has an explicit abort cap.
"""
from array import array
from dataclasses import dataclass
from fractions import Fraction
from math import prod
from operator import index
from os import urandom

from composition_full_run import Cipher, Secret, keygen, make_bank, raw_sum, relin
from check_tensor_codec import encode, decode
from check_composition_rns_arithmetic import CERTIFICATES
from check_composition_modulus_chain import drop_noise

if not __debug__:
    raise RuntimeError('The checked native adapter requires Python assertions enabled')


class SamplerExhausted(RuntimeError):
    """Public abort: no partial vector is returned and this coin object is closed."""


@dataclass(frozen=True)
class CoreProfile:
    length: int
    limbs: int = 4
    width: int = 48

    def __post_init__(self):
        if self.length not in (16, 256) or not 1 <= self.limbs <= 4 or self.width != 48:
            raise ValueError('Unsupported core profile; re-admission is required')

    @property
    def dimension(self):
        return 256 * self.length

    @property
    def kappa(self):
        return 511 * self.length

    @property
    def fresh_bound(self):
        return (2 * self.kappa + 1) * 20

    def modulus(self, limbs):
        if not 1 <= limbs <= self.limbs:
            raise ValueError('Invalid level')
        return prod(row[0] for row in CERTIFICATES[:limbs])

    def gadget(self, limbs):
        return (self.modulus(limbs).bit_length() + self.width - 1) // self.width

    def product_bound(self, left, right):
        return self.kappa * (left + right + 2 * left * right) + (self.kappa + 1) // 2

    def switch_bound(self, limbs):
        # Two full-ring banks: linear and quadratic source payloads.
        return 2 * self.kappa * self.gadget(limbs) * (1 << (self.width - 1)) * 20


class BoundedCoins:
    """Exact accepted laws under ideal words; at most eight rounds per vector.

    The injectable byte source is for public tests. Production defaults to OS
    urandom, whose computational randomness is an explicit separate premise.
    A failed object cannot be retried to condition away its public abort.
    """
    def __init__(self, ring, byte_source=urandom, max_rounds=8, max_words=None):
        if not isinstance(max_rounds, int) or not 1 <= max_rounds <= 8:
            raise ValueError('Rejection-round cap must be between one and eight')
        if ring.dimension <= 0 or array('Q').itemsize != 8 or array('q').itemsize != 8:
            raise ValueError('Unsupported dimension or integer ABI')
        if max_words is not None and (not isinstance(max_words, int) or max_words < 1):
            raise ValueError('Global word budget must be a positive integer')
        self.ring, self.byte_source, self.max_rounds = ring, byte_source, max_rounds
        self.max_words = max_words
        self.domains, self.failed = set(), False
        self.words_requested = self.rounds = self.errors = self.nonzero_errors = 0

    def claim(self, label):
        if self.failed:
            raise SamplerExhausted('Coin object already aborted')
        if not isinstance(label, str) or not label or label in self.domains:
            raise ValueError('Randomness domain must be fresh and nonempty')
        self.domains.add(label)

    def _sample(self, kind, prime=0):
        result = array('q')
        try:
            for _ in range(1 if kind == 1 else self.max_rounds):
                wanted = self.ring.dimension - len(result)
                if self.max_words is not None and self.words_requested + wanted > self.max_words:
                    raise SamplerExhausted('Public random-tape budget exhaustion')
                raw = self.byte_source(8 * wanted)
                if not isinstance(raw, bytes) or len(raw) != 8 * wanted:
                    raise ValueError('Random source returned a malformed block')
                words = array('Q')
                words.frombytes(raw)
                self.words_requested += wanted
                self.rounds += 1
                accepted = self.ring.sample_words(words, wanted, kind, prime)
                if not isinstance(accepted, array) or accepted.typecode != 'q' or len(accepted) > wanted:
                    raise ValueError('Sampler backend returned malformed output')
                result.extend(accepted)
                if len(result) == self.ring.dimension:
                    return result
        except Exception:
            self.failed = True
            raise
        self.failed = True
        raise SamplerExhausted('Public rejection-budget exhaustion')

    def ternary(self, label):
        self.claim(label)
        return self._sample(0)

    def error(self, label):
        self.claim(label)
        result = self._sample(1)
        self.errors += 1
        self.nonzero_errors += bool(any(result))
        return result

    def uniform(self, label, limbs):
        self.claim(label)
        if not 1 <= limbs <= self.ring.limbs:
            raise ValueError('Invalid uniform-mask level')
        result = array('Q')
        for prime in self.ring.primes[:limbs]:
            result.frombytes(self._sample(2, prime).tobytes())
        return result


def new_secret(ring, coins, key, limbs=None):
    limbs = ring.limbs if limbs is None else limbs
    if coins.ring is not ring:
        raise ValueError('Coin source belongs to a different ring instance')
    if not isinstance(key, str) or not key or not 1 <= limbs <= ring.limbs:
        raise ValueError('Invalid secret metadata')
    coefficients = coins.ternary('secret/' + key)
    return Secret(key, limbs, coefficients, ring.lift(coefficients, limbs))


def encrypt(ring, coins, public_key, message, label):
    if coins.ring is not ring:
        raise ValueError('Coin source belongs to a different ring instance')
    if len(message) != ring.dimension or any(x not in (0, 1) for x in message):
        raise ValueError('Expected a binary coefficient plaintext of the ring dimension')
    if len(public_key.components) != 2 or not 1 <= public_key.limbs <= ring.limbs:
        raise ValueError('Invalid encryption key')
    level = public_key.limbs
    u = coins.ternary('enc/' + label + '/u')
    e0 = coins.error('enc/' + label + '/e0')
    e1 = coins.error('enc/' + label + '/e1')
    us = ring.lift(u, level)
    one = ring.lift(array('q', (2*x + m for x, m in zip(e0, message))), level)
    two = ring.lift(array('q', (2*x for x in e1)), level)
    return Cipher(public_key.key, level, (
        ring.add(ring.point(public_key.components[0], us, level), one, level),
        ring.add(ring.point(public_key.components[1], us, level), two, level)))


def encode_lanes(lanes, inverse, length, jobs):
    if length not in (16, 256) or not 1 <= jobs <= 16 or len(lanes) != length * jobs:
        raise ValueError('Invalid lane shape')
    try:
        values = [index(x) for x in lanes]
    except TypeError as exc:
        raise ValueError('Field symbols must be integer-index values') from exc
    if any(not 0 <= x < 65536 for x in values):
        raise ValueError('Field symbols must be 16-bit words')
    packed = [sum(values[j*length+i] << (16*j) for j in range(jobs)) for i in range(length)]
    words = encode(packed, inverse)
    return bytearray((word >> e) & 1 for word in words for e in range(256))


def decode_lanes(bits, rows, length, jobs):
    if length not in (16, 256) or not 1 <= jobs <= 16 or len(bits) != length * 256:
        raise ValueError('Invalid coefficient shape')
    if any(x not in (0, 1) for x in bits):
        raise ValueError('Expected binary coefficients')
    words = [sum(bits[256*i+e] << e for e in range(256)) for i in range(length)]
    packed = decode(words, rows)
    return array('H', ((packed[i] >> (16*j)) & 65535 for j in range(jobs) for i in range(length)))


def composition_coin_budget(batches, rounds=8):
    """Counterfactual capped interface for the unchanged composition inventory.

    Does not claim the recorded unbounded W0 run used this cap.
    """
    if not isinstance(batches, int) or batches < 1 or not isinstance(rounds, int) or not 1 <= rounds <= 8:
        raise ValueError('Invalid horizon or cap')
    dimension = 65536
    rows = ((1,4),(10,4),(81,4),(15,4),(41,4),(15,4),(17,3),(12,3),(7,2),(9,2))
    mask_channels = sum(count * limbs for count, limbs in rows)
    ternary_vectors, error_vectors = 10 + 35*batches, 208 + 70*batches
    prime_rejection = [Fraction((1 << 64) % p, 1 << 64) for p, *_ in CERTIFICATES[:4]]
    failure = dimension * (mask_channels * max(prime_rejection)**rounds +
                           ternary_vectors * Fraction(1, 1 << 64)**rounds)
    words = dimension * (rounds * (mask_channels + ternary_vectors) + error_vectors)
    return dict(mask_channels=mask_channels, ternary_vectors=ternary_vectors,
                error_vectors=error_vectors, rounds=rounds, word_budget=words,
                byte_budget=8*words, ideal_abort_upper=failure,
                max_prime_rejection=max(prime_rejection))


def deep_core_admission(length):
    """Deterministic correctness-only ledger; no HE execution or security estimate."""
    profile = CoreProfile(length)
    bound, records = profile.fresh_bound, []
    for level, (limbs, nodes) in enumerate(((4,4),(3,2),(2,1)), 1):
        raw = profile.product_bound(bound, bound)
        if level == 1:
            raw += profile.fresh_bound + 1  # add c_i before rekeying
        switched = raw + profile.switch_bound(limbs)
        if profile.modulus(limbs) <= 2 + 4*switched:
            raise ValueError('Correctness envelope is not admitted')
        after = drop_noise(switched, profile.kappa, CERTIFICATES[limbs-1][0]) if level < 3 else switched
        records.append(dict(level=level, limbs=limbs, nodes=nodes, raw=raw,
                            switched=switched, after_drop=after, gadget=profile.gadget(limbs)))
        bound = after
    hint_rows = sum(2 * record['gadget'] for record in records)
    hint_words = sum(4 * record['limbs'] * profile.dimension * record['gadget'] for record in records)
    return dict(length=length, dimension=profile.dimension, kappa=profile.kappa,
                fresh_bound=profile.fresh_bound, levels=records, hint_rows=hint_rows,
                hint_bytes=hint_words*8, independent_stage_keys=4,
                input_public_keys=1, input_encryptions_per_batch=12,
                admitted=True, security_128_qualified=False, encrypted_execution=False)
