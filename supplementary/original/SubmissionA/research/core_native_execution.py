"""Native six-cell correctness adapter; uses the frozen raw terminal profiles.

Public evaluation has no owner/secret/oracle arguments. The gate remains a
same-process validation, not a deployed isolation or security demonstration.
"""
from array import array
from hashlib import sha256
import json
import sys

from core_grid_fixture import CELLS, inputs as fixture_inputs, metadata, oracle_states
from core_native import BoundedCoins, new_secret, encrypt, encode_lanes, decode_lanes
from core_profile_manifest import select
from composition_full_run import Cipher, Bundle, Trace, assert_public, keygen, make_bank, raw_sum, relin
from composition_optimized import OptimizedRing
from check_tensor_codec import setup as codec_setup


def coin_budget(profile, batches=2):
    n = profile["dimension"]
    masks = sum(v["incoming_rows"]*v["limbs"] for v in profile["key_vertices"])
    rows = 1+profile["hint_rows"]
    ternary = profile["independent_keys"] + batches*profile["encryptions_per_batch"]
    errors = rows + 2*batches*profile["encryptions_per_batch"]
    return dict(mask_channels=masks, ternary_vectors=ternary, error_vectors=errors,
                word_cap=n*(8*(masks+ternary)+errors), rejection_rounds=8)


def setup_keys(ring, coins, profile):
    keys = {v["key"]: new_secret(ring, coins, v["key"], v["limbs"])
            for v in profile["key_vertices"]}
    public_key = keygen(ring, coins, keys["s0"])
    banks = {}
    for level in profile["levels"]:
        if not level["rekey"]:
            continue
        index, a = level["level"], level["limbs"]
        source, destination = keys[f"s{index-1}"], keys[f"s{index}"]
        for kind in ("linear", "quadratic"):
            payload = source.spectra if kind == "linear" else ring.point(source.spectra, source.spectra, a)
            name = f"level{index}/{kind}"
            banks[name] = make_bank(ring, coins, source, destination, payload, name, kind)
    assert sum(len(b.rows) for b in banks.values()) == profile["hint_rows"]
    return keys, public_key, banks


def evaluate(ring, public, profile):
    """Only public ciphertexts, banks and predeclared profile enter evaluation."""
    assert_public(public)
    assert len(public.inputs) == profile["encryptions_per_batch"]
    assert len(public.public_keys) == 1
    for ct in public.inputs.values():
        assert ct.key == "s0" and ct.limbs == profile["chain"][0]
        assert len(ct.components) == 2
        for part in ct.components:
            ring.validate(part, ct.limbs)
    trace = [Trace(name, ct, profile["fresh_bound"]) for name, ct in public.inputs.items()]
    products = rekeys = drops = 0
    current = []
    for row in profile["levels"]:
        index = row["level"]
        next_level = []
        for i in range(row["nodes"]):
            if index == 1:
                pair = (public.inputs[f"a{i}"], public.inputs[f"b{i}"])
                addend = public.inputs.get(f"c{i}")
            else:
                pair, addend = (current[2*i], current[2*i+1]), None
            ct = raw_sum(ring, [pair], addend)
            products += 1
            trace.append(Trace(f"level{index}/{i}/raw", ct, row["raw_bound"]))
            if row["rekey"]:
                ct = relin(ring, ct, public.banks[f"level{index}/linear"],
                           public.banks[f"level{index}/quadratic"])
                rekeys += 1
                trace.append(Trace(f"level{index}/{i}/rekey", ct, row["result_bound"]))
            for drop in row["drops"]:
                assert ct.limbs == drop["from_limbs"] and len(ct.components) == 2
                ct = Cipher(ct.key, drop["to_limbs"], tuple(ring.drop(x, ct.limbs) for x in ct.components))
                drops += 1
                trace.append(Trace(f"level{index}/{i}/drop{ct.limbs}", ct, drop["bound"]))
            next_level.append(ct)
        current = next_level
    assert len(current) == 1
    assert (products, rekeys, drops) == (profile["products"], profile["executed_rekeys"],
                                       profile["executed_prime_drops"])
    assert len(current[0].components) == profile["terminal_components"] == 3
    return current[0], trace, dict(products=products, rekeys=rekeys, prime_drops=drops)


def phase(ring, ct, secret):
    assert ct.key == secret.key and ct.limbs <= secret.limbs
    value = ct.components[-1]
    for component in reversed(ct.components[:-1]):
        value = ring.add(ring.point(value, secret.spectra, ct.limbs), component, ct.limbs)
    return value


def recover(ring, ct, secret, rows, jobs):
    value = phase(ring, ct, secret)
    n, a = ring.dimension, ct.limbs
    residues = [ring.transform(value[j*n:(j+1)*n], j, True) for j in range(a)]
    primes = ring.primes[:a]
    prefixes, inverses, q = [], [], 1
    for p in primes:
        prefixes.append(q)
        inverses.append(pow(q, -1, p))
        q *= p
    bits = bytearray(n)
    for i in range(n):
        x = 0
        for p, prefix, inverse, channel in zip(primes, prefixes, inverses, residues):
            x += prefix*((channel[i]-x)*inverse % p)
        bits[i] = (x-q if x > q//2 else x) & 1
    return decode_lanes(bits, rows, ring.length, jobs)


def gate(cell):
    if sys.byteorder != "little":
        raise RuntimeError("The frozen arithmetic ABI requires little endian")
    family, length, jobs = CELLS[cell]
    profile = select(length, family, "raw")["selected"]
    budget = coin_budget(profile)
    ring = OptimizedRing(length, profile["chain"][0])
    try:
        values = fixture_inputs(cell)
        states, expected = oracle_states(cell, values)
        _, _, _, _, rows, inverse = codec_setup()
        plaintexts = {name: encode_lanes(value, inverse, length, jobs) for name, value in states.items()}
        coins = BoundedCoins(ring, max_words=budget["word_cap"])
        keys, public_key, banks = setup_keys(ring, coins, profile)
        batches = []
        for batch in range(2):
            encrypted = {name: encrypt(ring, coins, public_key, plaintexts[name],
                                       f"batch{batch}/{name}") for name in values}
            public = Bundle(encrypted, banks, (public_key,))
            result, trace, operations = evaluate(ring, public, profile)
            for record in trace:
                oracle_name = "/".join(record.name.split("/")[:2])
                # The numerical phase diagnostic is never exported.
                ring.phase_check(phase(ring, record.cipher, keys[record.cipher.key]),
                                 plaintexts[oracle_name], record.bound, record.cipher.limbs)
            recovered = recover(ring, result, keys[result.key], rows, jobs)
            assert recovered == expected
            raw_inputs = sum(8*len(x) for ct in encrypted.values() for x in ct.components)
            raw_output = sum(8*len(x) for x in result.components)
            assert raw_inputs == profile["raw_rns_input_bytes"]
            assert raw_output == profile["raw_rns_output_bytes"]
            batches.append(dict(index=batch, checked_states=len(trace), output_symbols=len(expected),
                output_sha256=sha256(recovered.tobytes()).hexdigest(), operations=operations,
                raw_input_bytes=raw_inputs, raw_output_bytes=raw_output,
                terminal_key=result.key, terminal_limbs=result.limbs, terminal_components=3))
        hints = sum(8*len(x) for bank in banks.values() for row in bank.rows for x in row)
        pk_bytes = sum(8*len(x) for x in public_key.components)
        assert hints == profile["raw_rns_hint_bytes"] and pk_bytes == profile["raw_rns_public_key_bytes"]
        assert not coins.failed and coins.words_requested <= budget["word_cap"]
        assert coins.errors == budget["error_vectors"]
        return dict(status="CORE_NATIVE_FUNCTIONAL_PASS", cell=cell, fixture=metadata(cell, values),
            profile=profile, actual_gate_encrypted_execution=True, batches=batches,
            raw_hint_bytes=hints, raw_public_key_bytes=pk_bytes, coin_budget=budget,
            actual_words_requested=coins.words_requested, primitive_error_vectors=coins.errors,
            secret_keys_exported=False, phase_diagnostics_exported=False,
            public_fixture_output_digest_only=True, process_isolation=False,
            benchmark=False, security_128_qualified=False, bootstrapping=False)
    finally:
        ring.close()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--supervised-cell" or sys.argv[2] not in CELLS:
        raise SystemExit("Use supervise_core_native.py CELL")
    print(json.dumps(gate(sys.argv[2])), flush=True)
