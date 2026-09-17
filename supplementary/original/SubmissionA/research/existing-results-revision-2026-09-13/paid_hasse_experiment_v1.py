"""Isolated worker for candidate correctness and matched final-output measurements.

Importing this module does not load the backend or generate cryptographic data.
Run only through supervise_paid_hasse_v1.py after coordination with the root.
"""
import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parent
ROOT = RESEARCH.parents[1]
LIBRARY = HERE / 'build' / 'paid_hasse_core_v1.so'
PROTOCOL = HERE / 'PAID_HASSE_EXPERIMENT_PROTOCOL_V1.md'
PREFLIGHT = HERE / 'paid-hasse-preflight-v1.json'
ORDER = ('reference', 'paid', 'paid', 'reference', 'reference', 'paid')
LIMITS = dict(address_space_bytes=2 << 30, cpu_seconds=840,
              wall_seconds=900, output_bytes=4 << 20, core_bytes=0)
THREAD_VARIABLES = ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS',
                    'MKL_NUM_THREADS', 'NUMEXPR_NUM_THREADS')
FIXTURE_DIGEST = 'd22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
POWER_CACHE_BYTES = 112 << 10


def runtime_dependency_manifest():
    # Resolve the actual dynamic dependencies without creating a ring context.
    result = subprocess.run(['/usr/bin/ldd', str(LIBRARY)], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=20, check=True)
    paths = sorted(set(Path(x).resolve() for x in re.findall(r'(/[^\s()]+)', result.stdout)))
    assert paths and all(path.is_file() for path in paths)
    return {'external:'+str(path): sha256(path.read_bytes()).hexdigest() for path in paths}


def source_manifest():
    pending = [Path(__file__).resolve(), HERE / 'supervise_paid_hasse_v1.py',
               HERE / 'paid_hasse_ring_v1.py', HERE / 'paid_hasse_public_v1.py',
               HERE / 'paid_hasse_setup_v1.py', HERE / 'final_output_evaluator.py',
               HERE / 'check_current_interface_hasse_comparison_v1.py',
               HERE / 'check_paid_hasse_backend_v1.py', HERE / 'check_paid_hasse_profile_v1.py',
               HERE / 'collect_paid_hasse_preflight_v1.py', PROTOCOL, LIBRARY,
               HERE / 'paid_hasse_core_v1.cpp',
               RESEARCH / 'measure_composition_native.py',
               RESEARCH / 'composition_optimized_core.cpp', RESEARCH / 'composition_native_core.cpp']
    found = {}
    while pending:
        path = pending.pop().resolve()
        if path in found:
            continue
        data = path.read_bytes()
        found[path] = sha256(data).hexdigest()
        if path.suffix != '.py':
            continue
        for node in ast.walk(ast.parse(data)):
            names = ([node.module or ''] if isinstance(node, ast.ImportFrom) else
                     [item.name for item in node.names] if isinstance(node, ast.Import) else [])
            for name in names:
                for directory in (HERE, RESEARCH):
                    candidate = directory / (name.split('.')[0] + '.py')
                    if candidate.is_file():
                        pending.append(candidate)
                        break
    manifest = {p.relative_to(ROOT).as_posix(): found[p] for p in sorted(found)}
    manifest.update(runtime_dependency_manifest())
    return manifest


def check_worker_limits(cpu):
    import resource
    assert os.sched_getaffinity(0) == {cpu}
    assert all(os.environ.get(name) == '1' for name in THREAD_VARIABLES)
    for kind, expected in ((resource.RLIMIT_AS, LIMITS['address_space_bytes']),
                           (resource.RLIMIT_CPU, LIMITS['cpu_seconds']),
                           (resource.RLIMIT_CORE, LIMITS['core_bytes'])):
        assert resource.getrlimit(kind) == (expected, expected)


def serialize(ring, arm, kind, arrays):
    import measure_composition_native as old
    from paid_hasse_public_v1 import packet_schema_paid
    schema = (packet_schema_paid if arm == 'paid' else old.packet_schema)(ring, response=kind == 'output')
    def selected(frame):
        name = frame['record'][0]
        return (name == 'tail1' if kind == 'output' else
                name.startswith('input/') if kind == 'inputs' else not name.startswith('input/'))
    schema = dict(schema, packet_kind=kind, frames=[f for f in schema['frames'] if selected(f)])
    sink = old.CountSink()
    receipt = old.send(sink, b'JETPV001', schema, arrays)
    assert sink.bytes == receipt['wire_bytes']
    return receipt['wire_bytes']


def inventory(ring, arm, keys, public_keys, banks):
    rows = sum(len(bank.rows) for bank in banks.values())
    hint_bytes = sum(len(v)*8 for bank in banks.values() for row in bank.rows for v in row)
    pk_bytes = sum(len(v)*8 for pk in public_keys.values() for v in pk.components)
    incoming = {name: int(name in public_keys) for name in keys}
    for bank in banks.values():
        incoming[bank.destination] += len(bank.rows)
    expected = (149, 542 << 20, 46) if arm == 'paid' else (203, 754 << 20, 81)
    assert (rows, hint_bytes, max(incoming.values())) == expected
    assert len(keys) == 10 and len(public_keys) == 5 and pk_bytes == 17 << 20
    assert ring.length == 256 and ring.limbs == 4
    return dict(independent_secrets=len(keys), public_keys=len(public_keys), hint_rows=rows,
                hint_bytes_raw=hint_bytes, public_key_bytes_raw=pk_bytes,
                maximum_receiving_rows=max(incoming.values()), incoming_rows=incoming,
                public_power_cache_bytes=POWER_CACHE_BYTES,
                arithmetic_profile=dict(dimension=65536, chain=[4, 4, 4, 3, 2], width=48))


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


def run_worker(mode, arm, sample_index, progress):
    from array import array
    from collections import defaultdict
    import resource
    from time import perf_counter
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    progress['stage'] = 'imports'
    from paid_hasse_ring_v1 import PaidHasseRing
    from paid_hasse_setup_v1 import setup_keys_paid
    from paid_hasse_public_v1 import (bank_catalog_paid, evaluate_paid_final_output,
                                      evaluate_paid_with_trace, trace_spec_paid)
    from final_output_evaluator import evaluate_final_output
    import measure_composition_native as old
    from composition_full_run import FRESH
    assert Path(old.__file__).resolve() == RESEARCH / 'measure_composition_native.py'
    total_start = perf_counter()
    setup = defaultdict(float)
    ring = None
    try:
        progress['stage'] = 'context_and_codec'
        with old.phase(setup, 'public_context_codec'):
            ring = PaidHasseRing()
            _, _, _, _, rows, inverse = old.codec_setup()
            field = old.FastField()
        progress['stage'] = 'keys_and_hints'
        with old.phase(setup, 'keys_hints'):
            if arm == 'paid':
                setup_coins = old.Coins(ring)
                keys, public_keys, banks = setup_keys_paid(ring, setup_coins)
                assert setup_coins.errors == 154
                del setup_coins
            else:
                keys, public_keys, banks = old.setup_keys(ring)
        material = inventory(ring, arm, keys, public_keys, banks)
        progress['stage'] = 'key_serialization'
        with old.phase(setup, 'public_key_serialization'):
            catalog = bank_catalog_paid() if arm == 'paid' else old.bank_catalog()
            arrays = [v for name, *_ in catalog for row in banks[name].rows for v in row]
            arrays.extend(v for name in old.PK_NAMES for v in public_keys[name].components)
            key_serialized = serialize(ring, arm, 'keys', arrays)
            del arrays
        print(json.dumps(dict(event='paid_hasse_setup_complete', mode=mode, arm=arm,
                              sample_index=sample_index, seconds=dict(setup), **material)), flush=True)
        progress['stage'] = 'public_fixture_oracle'
        fs, gs = old.fixture_inputs()
        flat_f = array('H', (v for lane in fs for v in lane))
        flat_g = array('H', (v for lane in gs for v in lane))
        oracle = ring.series(flat_f, flat_g, old.L, horner=True)
        assert sha256(oracle.tobytes()).hexdigest() == FIXTURE_DIGEST
        batches = []
        phase_words = 0
        for index in range(1 if mode == 'gate' else 2):
            progress.update(stage='batch_preparation', batch_index=index)
            batch_start = perf_counter()
            times = defaultdict(float)
            lanes = old.owner_inputs(ring, field, fs, gs, times)
            with old.phase(times, 'codec'):
                plain = {name: old.encode_lanes(value, inverse) for name, value in lanes.items()}
            with old.phase(times, 'encryption'):
                coins = old.Coins(ring)
                inputs = {name: old.encrypt(ring, coins,
                          public_keys['h'+name[1:] if name.startswith('u') else 's0'], plain[name], name)
                          for name in lanes}
                assert coins.errors == 70
            public = old.Bundle(inputs, banks, tuple(public_keys.values()))
            progress['stage'] = 'input_serialization'
            with old.phase(times, 'serialization'):
                input_serialized = serialize(ring, arm, 'inputs', [v for ct in inputs.values() for v in ct.components])
            progress['stage'] = 'evaluation'
            with old.phase(times, 'evaluation'):
                if mode == 'gate':
                    trace = evaluate_paid_with_trace(ring, public)
                    result = trace[-1]
                else:
                    trace = None
                    result = (evaluate_paid_final_output if arm == 'paid' else evaluate_final_output)(ring, public)
            progress['stage'] = 'output_serialization'
            with old.phase(times, 'serialization'):
                output_serialized = serialize(ring, arm, 'output', list(result.components))
            progress['stage'] = 'decryption_and_decode'
            with old.phase(times, 'decryption_codec'):
                recovered = old.decrypt(ring, result, keys['s5'], rows)
            batch_wall = perf_counter()-batch_start
            progress['stage'] = 'verification'
            with old.phase(times, 'verification'):
                assert recovered == oracle
                if mode == 'gate':
                    expected, plain_result = expected_states(ring, lanes, inverse)
                    assert plain_result == oracle
                    for name, ct in inputs.items():
                        phase_words += check_phase(ring, ct, keys[ct.key], plain[name], FRESH)
                    spec = trace_spec_paid(ring)
                    assert len(trace) == len(spec) == 24
                    for ct, (name, key, a, arity, bound) in zip(trace, spec):
                        progress['stage'] = 'phase_check/'+name
                        assert (ct.key, ct.limbs, len(ct.components)) == (key, a, arity)
                        phase_words += check_phase(ring, ct, keys[key], expected[name], bound)
                    assert phase_words == (35+24)*old.M
                    del expected, plain_result
            batch = dict(index=index, state='cold' if index == 0 else 'warm', seconds=dict(times),
                         batch_wall_seconds=batch_wall, output_symbols=4096,
                         output_sha256=sha256(recovered.tobytes()).hexdigest(),
                         input_bytes_raw=sum(len(v)*8 for ct in inputs.values() for v in ct.components),
                         output_bytes_raw=sum(len(v)*8 for v in result.components),
                         input_bytes_serialized=input_serialized, output_bytes_serialized=output_serialized,
                         fresh_encryptions=len(inputs), diagnostic_states_retained=24 if trace is not None else 1)
            batches.append(batch)
            print(json.dumps(dict(event='paid_hasse_batch_complete', mode=mode, arm=arm,
                                  sample_index=sample_index, batch=batch)), flush=True)
            del trace, result, recovered, public, inputs, plain, lanes
        progress['stage'] = 'result_inventory'
        result = dict(status='PAID_HASSE_GATE_WORKER_PASS' if mode == 'gate' else 'PAID_HASSE_MEASUREMENT_WORKER_PASS',
                      mode=mode, arm=arm, sample_index=sample_index, fixture=old.metadata(),
                      setup_seconds=dict(setup), batches=batches, **material,
                      public_key_including_hints_bytes_serialized=key_serialized,
                      phase_checked_states=59 if mode == 'gate' else 0,
                      phase_checked_coefficients=phase_words,
                      peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                      process_wall_seconds=perf_counter()-total_start,
                      worker_threads=1, encrypted_execution=True, security_bits=None, bootstrapping=False,
                      serializer='Fixed-schema uint64 frames and SHA256 into counting sinks; candidate catalog-specific header; no network.',
                      phase_scope='Cold/warm wall includes both owners, codec, fresh encryption, evaluator, serialization and recovery; verification excluded.',
                      memory_scope='Process high-water RSS includes setup, owners, key material and every batch; both arms pay the same 112 KiB power cache.',
                      process_scope='Same-process roles. Public evaluator accepts ring and public bundle only. Import/startup excluded from process_wall_seconds.')
        print(json.dumps(result), flush=True)
    finally:
        if ring is not None:
            ring.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--supervised', action='store_true', required=True)
    parser.add_argument('--mode', choices=('gate', 'measurement'), required=True)
    parser.add_argument('--arm', choices=('reference', 'paid'), required=True)
    parser.add_argument('--sample-index', type=int, required=True)
    parser.add_argument('--cpu', type=int, required=True)
    args = parser.parse_args()
    progress = {'stage': 'worker_limits'}
    try:
        assert os.name == 'posix'
        assert ((args.mode == 'gate' and args.arm == 'paid' and args.sample_index == -1) or
                (args.mode == 'measurement' and 0 <= args.sample_index < 6 and ORDER[args.sample_index] == args.arm))
        check_worker_limits(args.cpu)
        run_worker(args.mode, args.arm, args.sample_index, progress)
    except BaseException as exc:
        print(json.dumps(dict(status='PAID_HASSE_WORKER_FAIL', mode=args.mode,
                              arm=args.arm, sample_index=args.sample_index,
                              error_type=type(exc).__name__, **progress)), flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
