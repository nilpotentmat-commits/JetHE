"""Public sampler/codec/admission tests for the dimension-generic core adapter.

No keys, ciphertext evaluation, benchmark, or concrete-security qualification.
"""
import argparse
from array import array
from fractions import Fraction
from math import comb
from pathlib import Path
import json
import subprocess
import sys
import time

from core_native import BoundedCoins, SamplerExhausted, CoreProfile, encode_lanes, decode_lanes
from core_native import composition_coin_budget, deep_core_admission
from core_native import new_secret, encrypt
from composition_native import NativeRing, DLL_PATH
from check_tensor_codec import setup
from leaf_security_screen import ROOT, digest


class ScalarSampler:
    def __init__(self, dimension=3):
        self.dimension, self.limbs, self.primes = dimension, 1, [5]

    def sample_words(self, words, wanted, kind, prime=0):
        accepted = array('q')
        modulus = 3 if kind == 0 else prime
        limit = ((1 << 64) // modulus) * modulus if kind != 1 else 0
        for word in words:
            if kind == 1:
                accepted.append((word & ((1 << 20)-1)).bit_count() - ((word >> 20) & ((1 << 20)-1)).bit_count())
            elif word < limit:
                accepted.append(word % modulus - (kind == 0))
            if len(accepted) == wanted:
                break
        return accepted


def fail_as(exception, function):
    try:
        function()
    except exception:
        return
    raise AssertionError('Required rejection did not occur')


def sampler_control_checks():
    queued = [array('Q', [(1 << 64)-1, 0, 1]).tobytes(), array('Q', [2]).tobytes()]
    def source(count):
        block = queued.pop(0)
        assert len(block) == count
        return block
    coins = BoundedCoins(ScalarSampler(), source)
    assert coins.ternary('partial') == array('q', [-1,0,1])
    assert coins.rounds == 2 and coins.words_requested == 4
    fail_as(ValueError, lambda: coins.ternary('partial'))
    for kind in ('ternary', 'uniform'):
        rejected = BoundedCoins(ScalarSampler(), lambda count: b'\xff'*count)
        action = (lambda: rejected.ternary('abort')) if kind == 'ternary' else (lambda: rejected.uniform('abort',1))
        fail_as(SamplerExhausted, action)
        assert rejected.failed and rejected.rounds == 8 and rejected.words_requested == 24
        fail_as(SamplerExhausted, lambda: rejected.error('after_abort'))
        assert rejected.words_requested == 24
    malformed = BoundedCoins(ScalarSampler(), lambda count: b'bad')
    fail_as(ValueError, lambda: malformed.error('malformed'))
    assert malformed.failed
    fail_as(ValueError, lambda: BoundedCoins(ScalarSampler(), max_rounds=0))
    fail_as(ValueError, lambda: CoreProfile(32))
    fail_as(ValueError, lambda: CoreProfile(16,width=60))
    fail_as(ValueError, lambda: composition_coin_budget(2,rounds=1.5))
    other_ring = ScalarSampler()
    mismatched = BoundedCoins(ScalarSampler(), lambda count: bytes(count))
    fail_as(ValueError, lambda: new_secret(other_ring,mismatched,'wrong'))
    fail_as(ValueError, lambda: encrypt(other_ring,mismatched,None,[], 'wrong'))
    assert mismatched.words_requested == 0
    tape = BoundedCoins(ScalarSampler(), lambda count: bytes(count), max_words=3)
    assert tape.error('within_budget') == array('q',[0,0,0])
    fail_as(SamplerExhausted, lambda: tape.error('over_budget'))
    assert tape.failed and tape.words_requested == 3
    fail_as(SamplerExhausted, lambda: tape.ternary('no_retry'))
    fail_as(ValueError, lambda: BoundedCoins(ScalarSampler(),max_words=2.5))
    # Exhaustive smaller CBD law: two8-bit blocks in the unchanged40-bit map.
    counts = [0]*17
    for left in range(256):
        for right in range(256):
            counts[left.bit_count()-right.bit_count()+8] += 1
    assert counts == [comb(16,k) for k in range(17)]
    return dict(partial_acceptance=True, terminal_abort_modes=2,
                rejection_round_cap=8, no_retry_after_abort=True,
                toy_cbd_pairs=65536, malformed_source_rejected=True,
                fractional_cap_rejected=True, mismatched_ring_rejected_before_sampling=True,
                global_tape_limit_enforced=True)


def compiled_sampler_checks():
    total = 0
    for length in (16,256):
        ring = NativeRing(length,4)
        try:
            reference = ScalarSampler(ring.dimension)
            for kind in (0,1,2):
                primes = ring.primes if kind == 2 else [0]
                for prime in primes:
                    modulus = 3 if kind == 0 else prime
                    boundary = ((1 << 64)//modulus)*modulus if kind != 1 else 1 << 40
                    words = array('Q', [0,1,2,(1 << 64)-1,(1 << 20)-1,((1 << 20)-1)<<20])
                    words.extend(x for x in (boundary-1,boundary,boundary+1) if 0 <= x < 1 << 64)
                    words.extend(((i * 0x9E3779B97F4A7C15) & ((1 << 64)-1)) for i in range(257))
                    assert ring.sample_words(words,len(words),kind,prime) == reference.sample_words(words,len(words),kind,prime)
                    total += len(words)
            # Exercise real C ABI through the new vector-level interface.
            public = BoundedCoins(ring, lambda count: bytes(count))
            assert public.ternary('public/ternary') == array('q',[-1])*ring.dimension
            assert public.error('public/error') == array('q',[0])*ring.dimension
            assert public.uniform('public/uniform',4) == array('Q',[0])*(4*ring.dimension)
            assert public.words_requested == 6*ring.dimension and public.rounds == 6
        finally:
            ring.close()
    return dict(public_word_comparisons=total, dimensions=[4096,65536],
                full_vector_abi_checks=6, os_randomness_used=False)


def codec_checks():
    _,_,_,_,rows,inverse = setup()
    cells = []
    for length in (16,256):
        for jobs in (1,16):
            values = array('H', ((i*40503 + jobs*997 + length) & 65535 for i in range(length*jobs)))
            bits = encode_lanes(values,inverse,length,jobs)
            assert len(bits) == 256*length
            assert decode_lanes(bits,rows,length,jobs) == values
            all_lanes = decode_lanes(bits,rows,length,16)
            assert all_lanes[:len(values)] == values
            assert not any(all_lanes[len(values):])
            cells.append(dict(length=length,jobs=jobs,symbols=len(values)))
    fail_as(ValueError, lambda: encode_lanes(array('H',[0]),inverse,16,1))
    fail_as(ValueError, lambda: decode_lanes(bytearray(4096),rows,16,17))
    for bad in (0.5,-0.5,'1',-1,65536):
        values = [0]*16
        values[0] = bad
        fail_as(ValueError, lambda: encode_lanes(values,inverse,16,1))
    return cells


def security_bridge_checks():
    budget = composition_coin_budget(2)
    assert budget['mask_channels'] == 771
    assert budget['word_budget'] == 468975616 and budget['byte_budget'] == 3751804928
    assert budget['max_prime_rejection'] < Fraction(1,2**29)
    assert budget['ideal_abort_upper'] < Fraction(1,2**206)
    return dict(capped_composition={k:str(v) if isinstance(v,Fraction) else v for k,v in budget.items()},
                ideal_abort_lower_bits=206, old_W0_used_cap=False,
                arbitrary_distinguishing_bound=False)


def check():
    start = time.monotonic()
    optimized = subprocess.run([sys.executable,'-O','-B','-c','import core_native'],
                               cwd=Path(__file__).resolve().parent,
                               capture_output=True,text=True,timeout=10)
    assert optimized.returncode != 0 and 'requires Python assertions enabled' in optimized.stderr
    admissions = [deep_core_admission(length) for length in (16,256)]
    for result in admissions:
        assert result['hint_rows'] == 24
        assert [row['nodes'] for row in result['levels']] == [4,2,1]
        assert all(row['switched'] < 2**74 for row in result['levels'])
        assert all(row['after_drop'] < 2**17 for row in result['levels'][:2])
    paths = [Path(__file__).resolve(), ROOT/'SubmissionA/research/core_native.py',
             ROOT/'SubmissionA/research/composition_native.py',
             ROOT/'SubmissionA/research/composition_native_core.cpp',
             ROOT/'SubmissionA/research/composition_full_run.py',
             ROOT/'SubmissionA/research/check_tensor_codec.py',
             ROOT/'SubmissionA/research/check_composition_modulus_chain.py',
             ROOT/'SubmissionA/research/check_composition_rns_arithmetic.py',
             ROOT/'SubmissionA/appendices/composition-security-decision.tex']
    result = dict(schema='core-native-public-v1', sources_sha256={p.relative_to(ROOT).as_posix():digest(p) for p in paths},
                  compiled_backend_sha256=digest(DLL_PATH), byte_order=sys.byteorder,
                  assertions_enabled=__debug__, python_version=sys.version.split()[0],
                  assertion_disabled_mode_rejected=True,
                  sampler_controls=sampler_control_checks(), compiled_sampler=compiled_sampler_checks(),
                  codec=codec_checks(), deep_admission=admissions,
                  security_bridge=security_bridge_checks(), encrypted_execution=False,
                  benchmark=False, security_128_qualified=False)
    result['verification_seconds'] = time.monotonic()-start
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output')
    parser.add_argument('--verify')
    args=parser.parse_args()
    assert not(args.output and args.verify)
    result=check()
    if args.verify:
        saved=json.loads(Path(args.verify).read_text(encoding='utf-8'))
        assert {k:v for k,v in saved.items() if k!='verification_seconds'} == {k:v for k,v in result.items() if k!='verification_seconds'}
    if args.output:
        path=Path(args.output).resolve()
        assert path.parent==(ROOT/'SubmissionA/evidence').resolve()
        with path.open('x',encoding='utf-8') as stream:
            json.dump(result,stream,indent=2,sort_keys=True,allow_nan=False)
            stream.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k!='sources_sha256'},indent=2))
