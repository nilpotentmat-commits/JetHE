"""Matched timing adapter for the already admitted native six-cell core.

Arithmetic/samplers/codecs are imported unchanged. The evaluator differs from
the gate only by omitting unused trace retention and phase diagnostics.
Invoke only through supervise_core_matched_v1.py after its prerequisite checks.
"""
from contextlib import contextmanager
from hashlib import sha256
import json
import resource
import sys
from time import perf_counter

from core_grid_fixture import CELLS, inputs, metadata, oracle_states
from core_native import BoundedCoins, encrypt, encode_lanes
from core_native_execution import coin_budget, setup_keys, recover
from core_profile_manifest import select
from composition_full_run import Cipher, Bank, Bundle, assert_public, raw_sum, relin
from composition_optimized import OptimizedRing
from check_tensor_codec import setup as codec_setup


@contextmanager
def charge(times, name):
    started = perf_counter()
    try:
        yield
    finally:
        times[name] = times.get(name, 0.0)+perf_counter()-started


def public_wire_bytes(value, ring):
    """Counting sink for explicit framing + already wire-ordered RNS buffers.

    The body is a read-only byte view; neither copies nor ciphertext contents
    are exported. This is serialization/framing CPU, not memory/network I/O.
    """
    def frame(meta, parts):
        header = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
        count = 8+len(header)
        for part in parts:
            assert part.typecode == "Q" and part.itemsize == 8
            count += 8+len(memoryview(part).cast("B"))
        return count

    common = dict(format="JetHE-core-RNS-NTT-uint64le-v1", dimension=ring.dimension,
                  length=ring.length, primes=list(ring.primes))
    if isinstance(value, Cipher):
        return frame(dict(common, type="cipher", key=value.key, limbs=value.limbs,
                          components=len(value.components)), value.components)
    if isinstance(value, Bank):
        return frame(dict(common, type="bank", source=value.source, destination=value.destination,
                          limbs=value.limbs, payload=value.payload, rows=len(value.rows)),
                     [part for row in value.rows for part in row])
    raise TypeError("Only public ciphertexts and evaluation banks can be serialized")


def evaluate(ring, public, profile, kernels):
    """Public-only schedule; identical raw_sum/relin/drop sequence to the gate."""
    assert_public(public)
    assert len(public.inputs) == profile["encryptions_per_batch"]
    assert len(public.public_keys) == 1
    for ct in public.inputs.values():
        assert ct.key == "s0" and ct.limbs == profile["chain"][0]
        assert len(ct.components) == 2
        for part in ct.components:
            ring.validate(part, ct.limbs)
    current = []
    counts = dict(products=0, rekeys=0, prime_drops=0)
    for row in profile["levels"]:
        index, next_level = row["level"], []
        for i in range(row["nodes"]):
            if index == 1:
                pair = (public.inputs[f"a{i}"], public.inputs[f"b{i}"])
                addend = public.inputs.get(f"c{i}")
            else:
                pair, addend = (current[2*i], current[2*i+1]), None
            with charge(kernels, "multiply_and_add"):
                ct = raw_sum(ring, [pair], addend)
            counts["products"] += 1
            if row["rekey"]:
                with charge(kernels, "independent_rekey"):
                    ct = relin(ring, ct, public.banks[f"level{index}/linear"],
                               public.banks[f"level{index}/quadratic"])
                counts["rekeys"] += 1
            for drop in row["drops"]:
                assert ct.limbs == drop["from_limbs"] and len(ct.components) == 2
                with charge(kernels, "prime_drop"):
                    ct = Cipher(ct.key, drop["to_limbs"],
                                tuple(ring.drop(x, ct.limbs) for x in ct.components))
                counts["prime_drops"] += 1
            next_level.append(ct)
        current = next_level
    assert len(current) == 1 and len(current[0].components) == profile["terminal_components"] == 3
    assert counts == dict(products=profile["products"], rekeys=profile["executed_rekeys"],
                          prime_drops=profile["executed_prime_drops"])
    return current[0], counts


def batch(cell, index, ring, coins, profile, values, expected, keys, pk, banks, rows, inverse):
    family, length, jobs = CELLS[cell]
    del family
    times, kernels = {}, {}
    started = perf_counter()
    with charge(times, "owners_preparation_encoding"):
        plaintexts = {name:encode_lanes(value, inverse, length, jobs) for name,value in values.items()}
    with charge(times, "owners_encryption"):
        encrypted = {name:encrypt(ring, coins, pk, message, f"batch{index}/{name}")
                     for name,message in plaintexts.items()}
    with charge(times, "input_serialization"):
        input_bytes = sum(public_wire_bytes(ct, ring) for ct in encrypted.values())
    with charge(times, "evaluation_total"):
        public = Bundle(encrypted, banks, (pk,))
        terminal, operations = evaluate(ring, public, profile, kernels)
    with charge(times, "output_serialization"):
        output_bytes = public_wire_bytes(terminal, ring)
    with charge(times, "recipient_decryption_decoding"):
        recovered = recover(ring, terminal, keys[terminal.key], rows, jobs)
    with charge(times, "validation"):
        all_match = recovered == expected
        output_hash = sha256(recovered.tobytes()).hexdigest()
        raw_inputs = sum(8*len(x) for ct in encrypted.values() for x in ct.components)
        raw_output = sum(8*len(x) for x in terminal.components)
        assert raw_inputs == profile["raw_rns_input_bytes"] and raw_output == profile["raw_rns_output_bytes"]
    prepared_bytes = sum(len(x) for x in plaintexts.values())
    terminal_key, terminal_limbs = terminal.key, terminal.limbs
    del encrypted, public, terminal, plaintexts
    elapsed = perf_counter()-started
    local = elapsed-times["validation"]
    attributed = sum(v for k,v in times.items() if k != "validation")
    assert local >= attributed >= times["evaluation_total"] > 0
    return dict(index=index, seconds=times, kernel_seconds=kernels,
        batch_wall_seconds=elapsed, local_compute_seconds=local,
        unallocated_charged_seconds=local-attributed, all_outputs_match=all_match,
        output_symbols=len(recovered), output_sha256=output_hash,
        operations=operations, input_bytes_serialized=input_bytes, output_bytes_serialized=output_bytes,
        raw_input_bytes=raw_inputs, raw_output_bytes=raw_output,
        prepared_plaintext_cache_bytes=prepared_bytes,
        terminal_key=terminal_key, terminal_limbs=terminal_limbs, terminal_components=3)


def measure(cell):
    assert __debug__ and sys.byteorder == "little"
    family, length, jobs = CELLS[cell]
    del jobs
    profile = select(length, family, "raw")["selected"]
    values = inputs(cell)
    _, expected = oracle_states(cell, values)  # Validation fixture, not owner computation.
    budget = coin_budget(profile, batches=2)
    setup, ring = {}, None
    try:
        with charge(setup, "public_setup"):
            ring = OptimizedRing(length, profile["chain"][0])
            _, _, _, _, rows, inverse = codec_setup()
        with charge(setup, "keys_and_serialization"):
            coins = BoundedCoins(ring, max_words=budget["word_cap"])
            keys, pk, banks = setup_keys(ring, coins, profile)
            key_bytes = public_wire_bytes(pk, ring)+sum(public_wire_bytes(b, ring) for b in banks.values())
        batches = [batch(cell, index, ring, coins, profile, values, expected, keys, pk, banks, rows, inverse)
                   for index in range(2)]
        assert not coins.failed and coins.words_requested <= budget["word_cap"]
        assert coins.errors == budget["error_vectors"]
        good = all(b["all_outputs_match"] for b in batches)
        return dict(status="CORE_MATCHED_PASS" if good else "CORE_MATCHED_WRONG_OUTPUT",
            compiler="native", cell=cell, profile=profile, fixture=metadata(cell, values),
            setup_seconds=setup, batches=batches,
            first_use_local_seconds=sum(setup.values())+batches[0]["local_compute_seconds"],
            public_key_including_hints_bytes_serialized=key_bytes,
            raw_public_key_bytes=profile["raw_rns_public_key_bytes"], raw_hint_bytes=profile["raw_rns_hint_bytes"],
            coin_budget=budget, actual_words_requested=coins.words_requested, primitive_error_vectors=coins.errors,
            peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            benchmark=True, encrypted_execution=True, security_128_qualified=False,
            bootstrapping=False, process_isolation=False, secret_keys_exported=False,
            phase_diagnostics_exported=False, ciphertext_bodies_exported=False,
            network_transfer_measured=False, binary_build_attestation=False)
    finally:
        if ring is not None:
            ring.close()


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] == "--supervised-cell" and sys.argv[2] in CELLS
    result = measure(sys.argv[2])
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result["status"] == "CORE_MATCHED_PASS" else 2)
