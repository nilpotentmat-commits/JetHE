"""Fresh diagnostic execution of the admitted direct paired terminal receiver.

No optimized or matched-security timing claim. Private validation, randomness
diagnostics and timings are not part of the protocol-public CPA transcript.
"""
from collections import Counter, defaultdict
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import platform
from random import Random
import resource
import struct
import sys
from time import perf_counter
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
KERNELS = HERE.parent / 'receiver-kernels-v1'
COMPILED = HERE.parent / 'compiled-receiver-v1'
sys.path.insert(0, str(KERNELS))
sys.path.insert(0, str(COMPILED))
from arithmetic import GMP, RealRing, centered
from range_arithmetic import RangeRing
from codec import Codec, ASSETS
from prefix_sampler import PrefixSource
from prepare import (Field, SLOTS, composition_fixture, expected_values,
                     inner_prepare, outer_prepare, records, record_digest, slow_mul)


def binding(path):
    return dict(bytes=path.stat().st_size, sha256=sha256(path.read_bytes()).hexdigest())


def load_admission():
    admission = json.loads((HERE / 'admission.json').read_text())
    prefix = json.loads((HERE / 'prefix-receipt.json').read_text())
    assert admission['status'] == 'PAIRED_UNSCALED_TERMINAL_ADMISSION_CHECKS_PASS'
    assert prefix['status'] == 'EXACT_FINITE_CDF_PREFIX_LOOKUP_CHECKS_PASS'
    assert admission['bindings_before'] == admission['bindings_after']
    for catalogue in (admission['bindings_after'], prefix['bindings']):
        for relative, value in catalogue.items():
            assert binding(ROOT / relative) == value, relative
    assert binding(HERE / 'prefix16.bin')['sha256'] == prefix['prefix_sha256']
    return admission, prefix


def input_bindings(admission, prefix):
    paths = {ROOT / relative for catalogue in
             (admission['bindings_after'], prefix['bindings']) for relative in catalogue}
    paths.update(HERE / name for name in ('run_receiver.py', 'prepare.py', 'admission.json',
                                         'prefix-receipt.json', 'prefix16.bin'))
    paths.update((ASSETS, COMPILED / 'expected.bin'))
    for module in list(sys.modules.values()):
        filename = getattr(module, '__file__', None)
        if filename:
            path = Path(filename).resolve()
            if path.is_relative_to(ROOT) and path.suffix == '.py':
                paths.add(path)
    return {str(path.relative_to(ROOT)).replace('\\', '/'): binding(path)
            for path in sorted(paths)}


class Receiver:
    def __init__(self, output, mode):
        self.output, self.mode = output, mode
        self.started = perf_counter()
        self.times = defaultdict(float)
        self.products = Counter()
        self.ring_seconds = defaultdict(float)
        self.source_seconds = 0.0
        self.counts = Counter()
        self.hashes = {name: sha256() for name in ('public', 'input', 'output')}
        self.payloads = Counter()
        self.events = (output / 'events.jsonl').open('w', buffering=1)

    def event(self, stage, **extra):
        record = dict(stage=stage, seconds=perf_counter() - self.started,
                      ring_products=sum(self.products.values()),
                      peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, **extra)
        if hasattr(self, 'source'):
            record['finite_vectors'] = self.source.vectors
        text = json.dumps(record, sort_keys=True)
        self.events.write(text + '\n')
        print(text, flush=True)

    def timed(self, name, operation):
        started = perf_counter()
        try:
            return operation()
        finally:
            self.times[name] += perf_counter() - started

    def mul(self, a, b, phase):
        started = perf_counter()
        out = self.ring.mul(a, b, self.q)
        self.products[phase] += 1
        self.ring_seconds[phase] += perf_counter() - started
        return out

    def sample(self):
        started = perf_counter()
        out = self.source.sample()
        self.source_seconds += perf_counter() - started
        return out

    def serialize(self, name, ciphertext):
        width = (self.q.bit_length() + 7) // 8
        for polynomial in ciphertext:
            assert len(polynomial) == self.ring.n and all(0 <= x < self.q for x in polynomial)
            raw = b''.join(x.to_bytes(width, 'little') for x in polynomial)
            self.hashes[name].update(raw)
            self.payloads[name] += len(raw)
        self.counts[name + '_polynomials'] += len(ciphertext)
        self.counts[name + '_ciphertexts'] += 1

    def setup(self):
        self.backend = GMP()
        self.ring = RangeRing(65537, self.backend)
        self.codec = Codec(self.backend)
        self.field = Field()
        self.source = PrefixSource()
        self.s, error = self.sample(), self.sample()
        self.a = self.source.uniform(self.q)
        product = self.mul(self.a, self.s, 'public_key')
        self.b = [(-v + 2 * e) % self.q for v, e in zip(product, error)]
        self.squared = self.mul(self.s, self.s, 'secret_square')
        self.serialize('public', [self.b, self.a])

    def encrypt(self, mu):
        u, e0, e1 = self.sample(), self.sample(), self.sample()
        left = self.mul(self.b, u, 'encryption')
        right = self.mul(self.a, u, 'encryption')
        self.counts['fresh_inputs'] += 1
        return [[(v + 2 * e + m) % self.q for v, e, m in zip(left, e0, mu)],
                [(v + 2 * e) % self.q for v, e in zip(right, e1)]]

    def phase(self, ciphertext, name):
        phase = self.ring.add(ciphertext[0], self.mul(ciphertext[1], self.s, name), self.q)
        if len(ciphertext) == 3:
            phase = self.ring.add(phase, self.mul(ciphertext[2], self.squared, name), self.q)
        else:
            assert len(ciphertext) == 2
        return [centered(x, self.q) for x in phase]

    def check_phase(self, phase, mu, cap, name):
        assert len(phase) == len(mu) == self.ring.n
        assert all(m in (0, 1) and (v - m) % 2 == 0 and abs((v - m) // 2) <= cap
                   for v, m in zip(phase, mu)), name
        self.counts[name + '_binary_coefficients'] += self.ring.n

    def input(self, slots):
        mu = self.timed('input_encoding', lambda: self.codec.encode(slots))
        ciphertext = self.timed('encryption', lambda: self.encrypt(mu))
        self.timed('input_serialization', lambda: self.serialize('input', ciphertext))
        phase = self.timed('diagnostic_input_decryption',
                           lambda: self.phase(ciphertext, 'input_validation'))
        self.timed('diagnostic_input_phase_check',
                   lambda: self.check_phase(phase, mu, self.fresh_cap, 'input'))
        return ciphertext

    def tensor(self, left, right):
        low = self.mul(left[0], right[0], 'raw_tensors')
        high = self.mul(left[1], right[1], 'raw_tensors')
        both = self.mul(self.ring.add(*left, self.q), self.ring.add(*right, self.q), 'raw_tensors')
        middle = [(v - a - b) % self.q for v, a, b in zip(both, low, high)]
        self.counts['raw_products'] += 1
        return [low, middle, high]

    def recover(self, ciphertext, expected_slots, cap):
        self.timed('output_serialization', lambda: self.serialize('output', ciphertext))
        phase = self.timed('terminal_decryption', lambda: self.phase(ciphertext, 'terminal_decryption'))
        mu = self.timed('diagnostic_output_encoding', lambda: self.codec.encode(expected_slots))
        self.timed('diagnostic_output_phase_check',
                   lambda: self.check_phase(phase, mu, cap, 'output'))
        recovered = self.timed('terminal_decoding', lambda: self.codec.decode([v & 1 for v in phase]))
        assert recovered == expected_slots
        self.counts['decoded_field_slots'] += SLOTS
        return recovered

    def field_and_range_check(self):
        xi = self.codec.embedding[2]
        assert self.codec.unembed[self.codec.field_power(xi, 16)] == 0x100B
        field_cases = [(1 << i, 1 << j) for i in range(16) for j in range(16)]
        rng = Random(20260914089)  # Public diagnostic cases only.
        field_cases.extend((rng.randrange(65536), rng.randrange(65536)) for _ in range(256))
        for a, b in field_cases:
            assert self.field.mul(a, b) == slow_mul(a, b) == self.codec.unembed[
                self.codec.field_mul(self.codec.embedding[a], self.codec.embedding[b])]
        small = 0
        for p in (3, 5, 17, 41):
            ring, oracle = RangeRing(p, self.backend), RealRing(p, self.backend)
            for kind in range(4):
                left = [rng.randrange(self.q) for _ in range(ring.n)]
                right = ([rng.randrange(-96, 97) for _ in left] if kind == 0 else
                         [rng.randrange(2) for _ in left] if kind == 1 else
                         [-19] * len(left) if kind == 2 else
                         [rng.randrange(self.q) for _ in left])
                assert ring.mul(left, right, self.q) == oracle.slow_mul(left, right, self.q)
                small += ring.n
        assert self.ring.mul(self.a, self.s, self.q) == RealRing(65537, self.backend).mul(self.a, self.s, self.q)
        self.counts['extra_production_range_products'] += 2
        return dict(field_pairs=len(field_cases), independent_small_range_coefficients=small,
                    production_range_coefficients=self.ring.n)

    def direct_tensor_check(self, left, right, tensor):
        oracle = RealRing(65537, self.backend)
        direct = [[oracle.mul(left[i], right[j], self.q) for j in range(2)] for i in range(2)]
        assert tensor == [direct[0][0], self.ring.add(direct[0][1], direct[1][0], self.q), direct[1][1]]
        self.counts['extra_direct_tensor_products'] += 4
        self.counts['direct_tensor_coefficients'] += 3 * self.ring.n

    def run(self):
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        admission, prefix = load_admission()
        before = input_bindings(admission, prefix)
        self.q = int(admission['selected']['q'])
        self.fresh_cap = int(admission['selected']['fresh_cap'])
        self.raw_cap = int(admission['selected']['raw_cap'])
        self.timed('setup', self.setup)
        self.event('setup complete')
        checks = self.timed('diagnostic_field_and_range', self.field_and_range_check)
        fs, gs = composition_fixture.inputs()
        length = 4 if self.mode == 'preflight' else 256
        fs, gs = [f[:length] for f in fs], [g[:length] for g in gs]
        jobs = len(fs)
        public_records = self.timed('public_routing_setup', lambda: records(jobs, length))
        field_before = self.field.products
        outer = self.timed('outer_owner_preparation', lambda: outer_prepare(fs, public_records, self.field))
        outer_products = self.field.products - field_before
        field_before = self.field.products
        inner = self.timed('inner_owner_preparation', lambda: inner_prepare(gs, public_records, self.field))
        inner_products = self.field.products - field_before
        expected, oracle_scope = self.timed('diagnostic_expected_oracle', lambda: expected_values(fs, gs))
        carriers = len(outer[0]) // SLOTS
        bypasses = len(outer[2]) // SLOTS
        assert len(outer[0]) == len(outer[1]) == len(inner[0]) == len(inner[1])
        assert len(outer[2]) == len(inner[2])
        result = [0] * (jobs * length)
        self.event('owner preparation complete', jobs=jobs, length=length,
                   scalar_pairs=len(public_records), product_carriers=carriers, bypass_carriers_per_owner=bypasses)
        for carrier in range(carriers):
            start, stop = carrier * SLOTS, (carrier + 1) * SLOTS
            outer_left, outer_right = [list(values[start:stop]) for values in outer[:2]]
            inner_left, inner_right = [list(values[start:stop]) for values in inner[:2]]
            c0, c1, c2, c3 = [self.input(v) for v in (outer_left, inner_left, outer_right, inner_right)]
            def evaluate():
                left = [self.ring.add(a, b, self.q) for a, b in zip(c0, c1)]
                right = [self.ring.add(a, b, self.q) for a, b in zip(c2, c3)]
                return left, right, self.tensor(left, right)
            left, right, raw = self.timed('evaluation', evaluate)
            if self.mode == 'preflight':
                self.timed('diagnostic_direct_tensor', lambda: self.direct_tensor_check(left, right, raw))
            slots = self.timed('diagnostic_expected_slots', lambda: [
                self.field.mul(a ^ b, c ^ d)
                for a, b, c, d in zip(outer_left, inner_left, outer_right, inner_right)])
            recovered = self.recover(raw, slots, self.raw_cap)
            def route():
                for offset, value in enumerate(recovered):
                    index = start + offset
                    if index < len(public_records):
                        job, j, _, _ = public_records[index]
                        result[job * length + j] ^= value
                    else:
                        assert value == 0
            self.timed('terminal_routing', route)
            self.event('product recovered', carrier=carrier, product_carriers=carriers)
        for owner_name, data in (('outer', outer), ('inner', inner)):
            for carrier in range(bypasses):
                start, stop = carrier * SLOTS, (carrier + 1) * SLOTS
                slots = list(data[2][start:stop])
                ciphertext = self.input(slots)
                recovered = self.recover(ciphertext, slots, self.fresh_cap)
                def add_bypass():
                    for index, value in enumerate(recovered, start):
                        if index < len(result):
                            result[index] ^= value
                        else:
                            assert value == 0
                self.timed('terminal_routing', add_bypass)
                self.event('bypass recovered', owner=owner_name, carrier=carrier)
        assert result == expected, 'Final coefficient vector differs from the independent oracle.'
        omitted = {name: sum((value ^ data[2][index]) != expected[index]
                            for index, value in enumerate(result) if index % length != 0)
                   for name, data in (('outer', outer), ('inner', inner))}
        assert all(v > 0 for v in omitted.values()), omitted
        inputs = 4 * carriers + 2 * bypasses
        predicted = dict(public_key=1, encryption=2 * inputs, raw_tensors=3 * carriers,
                         input_validation=inputs, secret_square=1,
                         terminal_decryption=2 * carriers + 2 * bypasses)
        assert dict(self.products) == predicted, (self.products, predicted)
        assert self.source.vectors == 2 + 3 * inputs and self.source.uniform_vectors == 1
        assert self.counts['fresh_inputs'] == inputs
        assert self.counts['input_polynomials'] == 2 * inputs
        assert self.counts['output_polynomials'] == 3 * carriers + 4 * bypasses
        if self.mode == 'full':
            assert (carriers, bypasses, inputs, len(public_records)) == (86, 2, 348, 175776)
            assert dict(self.payloads) == {name: admission['selected'][name + '_payload_bytes']
                                          for name in ('public', 'input', 'output')}
        after = input_bindings(admission, prefix)
        assert before == after, 'Bound implementation or admission changed during execution.'
        output_bytes = struct.pack('<' + str(len(result)) + 'H', *result)
        (self.output / 'recovered.bin').write_bytes(output_bytes)
        workflow_names = ('setup', 'public_routing_setup', 'outer_owner_preparation',
                          'inner_owner_preparation', 'input_encoding', 'encryption',
                          'input_serialization', 'evaluation', 'output_serialization',
                          'terminal_decryption', 'terminal_decoding', 'terminal_routing')
        record = dict(
            status='FRESH_PAIRED_TERMINAL_' + self.mode.upper() + '_FUNCTIONAL_PASS',
            mode=self.mode, jobs=jobs, length=length, source_cap=96, n=self.ring.n,
            q=str(self.q), q_bits=self.q.bit_length(), product_carriers=carriers,
            bypass_carriers_per_owner=bypasses, input_ciphertexts=inputs,
            scalar_pairs=len(public_records), public_record_sha256=record_digest(public_records),
            counts=dict(self.counts), ring_products=dict(self.products),
            ring_product_seconds=dict(self.ring_seconds),
            total_instrumented_core_ring_products=sum(self.products.values()),
            extra_diagnostic_ring_products=self.counts['extra_production_range_products'] +
                                           self.counts['extra_direct_tensor_products'],
            owner_field_products=dict(outer=outer_products, inner=inner_products),
            phase_seconds=dict(self.times), workflow_phase_seconds=sum(self.times[n] for n in workflow_names),
            instrumented_wall_seconds=perf_counter() - self.started,
            finite_source_sampling_seconds=self.source_seconds,
            finite_source=dict(vectors=self.source.vectors, source_bytes=self.source.source_bytes,
                               ambiguous_draws=self.source.ambiguous_draws, cap_events=self.source.caps,
                               original_fixed_byte_budget=self.source.vectors * (32 * (self.ring.n + 1) + 1),
                               exact_law_preserved=True, diagnostic_only=True),
            uniform_source=dict(vectors=self.source.uniform_vectors, source_bytes=self.source.uniform_bytes,
                                bounded_exhaustion_upper='2^-22769'),
            payload_bytes=dict(self.payloads), payload_sha256={k: v.hexdigest() for k, v in self.hashes.items()},
            payload_storage='Serialized to counting SHA-256 sinks; ciphertext bytes are not retained.',
            expected_oracle=oracle_scope, recovered_words=len(result), recovered_sha256=sha256(output_bytes).hexdigest(),
            omitted_correction_nonconstant_failures=omitted, arithmetic_checks=checks,
            fixture=composition_fixture.metadata(), backend=self.backend.binding(),
            platform=dict(platform=platform.platform(), python=sys.version,
                          affinity=sorted(os.sched_getaffinity(0)),
                          address_space_limit_bytes=2 * 1024**3,
                          peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
            width_inventory=[dict(q_bits=key[0], convolution_bytes=key[1],
                                  left_bits=key[2], right_bits=key[3], count=count)
                             for key, count in sorted(self.ring.width_inventory.items())],
            preprocessing=dict(prefix_lookup_bytes=(HERE / 'prefix16.bin').stat().st_size,
                               finite_cdf_bytes=(HERE.parent / 'control-sampler-v1' / 'tables.bin').stat().st_size,
                               charged_here='Loading and retaining existing tables; fresh codec and field setup.',
                               excluded='Initial finite-CDF construction, prefix-table construction and asset generation.'),
            bindings_before=before, bindings_after=after,
            scope='Fresh diagnostic execution on public synthetic inputs. Private phase checks, source counters '
                  'and timings are outside the protocol-public CPA transcript. Concurrent research jobs; '
                  'not an optimized benchmark, security-bit certificate, recipient-privacy result or FHE refresh.'
        )
        (self.output / 'run.json').write_text(json.dumps(record, indent=2) + '\n')
        self.event(record['status'], recovered_words=len(result), result_sha256=record['recovered_sha256'])
        self.events.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('preflight', 'full'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.parent == HERE, 'Fresh output must be a direct child of this receiver directory.'
    output.mkdir(exist_ok=False)
    receiver = Receiver(output, args.mode)
    try:
        receiver.run()
    except BaseException as error:
        (output / 'failure.json').write_text(json.dumps(dict(status='FUNCTIONAL_FAILURE',
            error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc()), indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
