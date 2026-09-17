"""JetHE-149 measured computation with portable imports and result return."""
from pathlib import Path
from hashlib import sha256
import sys,json
from paid_hasse_experiment_v1 import expected_states,check_phase
HERE=Path(__file__).resolve().parent
FIXTURE_DIGEST="d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3"
POWER_CACHE_BYTES=112<<10

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


def run_worker(mode, arm, sample_index, progress):
    assert arm == "paid", "This release selects the measured 149-row profile only"
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
    import measure_composition_native as old
    from composition_full_run import FRESH
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
        return result
    finally:
        if ring is not None:
            ring.close()
