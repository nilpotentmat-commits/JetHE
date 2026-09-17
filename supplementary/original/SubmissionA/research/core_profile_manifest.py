"""Correctness-only terminal W1/W2 profiles; no HE, sampling or timing.

Compare raw versus rekeyed terminal delivery within four frozen prime prefixes,
width 48, and the balanced declared circuit. This is a bounded public admission
enumeration, not a global compiler/parameter optimum or a security estimate.
"""
import argparse
import hashlib
from itertools import combinations_with_replacement
import json
from pathlib import Path
import time

from core_native import CoreProfile
from check_composition_modulus_chain import drop_noise
from check_composition_rns_arithmetic import CERTIFICATES

if not __debug__:
    raise RuntimeError("Assertions must be enabled")
ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "SubmissionA"


def profile_record(length, family, policy, chain):
    if family not in ("W1", "W2-shallow", "W2-deep"):
        raise ValueError("Unknown core workload")
    if (not chain or any(type(a) is not int or not 1 <= a <= 4 for a in chain)
            or any(a < b for a, b in zip(chain, chain[1:]))):
        raise ValueError("Expected a nonincreasing frozen prime-prefix chain")
    p = CoreProfile(length)
    deep = family == "W2-deep"
    widths = (4, 2, 1) if deep else (1,)
    assert len(chain) == len(widths)
    assert policy in ("raw", "canonical")
    bound, levels, hint_rows, hint_bytes, drops = p.fresh_bound, [], 0, 0, 0
    vertices = [dict(key="s0", incoming_rows=1, limbs=chain[0])]
    for index, (limbs, nodes) in enumerate(zip(chain, widths)):
        raw = p.product_bound(bound, bound)
        if index == 0 and family != "W1":
            raw += p.fresh_bound + 1
        switched = index < len(widths) - 1 or policy == "canonical"
        result = raw + (p.switch_bound(limbs) if switched else 0)
        if p.modulus(limbs) <= 2 + 4 * result:
            return dict(admitted=False, chain=list(chain),
                        failure_level=index + 1, failure="result bound")
        row = dict(level=index + 1, limbs=limbs, nodes=nodes, raw_bound=raw,
                   result_bound=result, rekey=switched, drops=[])
        if switched:
            count = 2 * p.gadget(limbs)
            hint_rows += count
            hint_bytes += count * 2 * limbs * p.dimension * 8
            vertices.append(dict(key="s" + str(index + 1),
                                 incoming_rows=count, limbs=limbs))
        if index + 1 < len(chain):
            assert switched
            for source_limbs in range(limbs, chain[index + 1], -1):
                result = drop_noise(result, p.kappa, CERTIFICATES[source_limbs - 1][0])
                if p.modulus(source_limbs - 1) <= 2 + 4 * result:
                    return dict(admitted=False, chain=list(chain),
                                failure_level=index + 1, failure="drop bound")
                row["drops"].append(dict(from_limbs=source_limbs,
                                         to_limbs=source_limbs - 1, bound=result))
                drops += nodes
        levels.append(row)
        bound = result
    inputs = 12 if deep else 2 if family == "W1" else 3
    arity = 3 if policy == "raw" else 2
    return dict(
        admitted=True, length=length, dimension=p.dimension, family=family,
        terminal_policy=policy, chain=list(chain), width=p.width,
        fresh_bound=p.fresh_bound, levels=levels, final_bound=bound,
        hint_rows=hint_rows, raw_rns_hint_bytes=hint_bytes, key_vertices=vertices,
        independent_keys=len(vertices), owner_public_keys=1,
        encryptions_per_batch=inputs, products=sum(widths),
        multiplicative_depth=len(widths),
        executed_rekeys=sum(x["nodes"] for x in levels if x["rekey"]),
        executed_prime_drops=drops,
        terminal_components=arity,
        raw_rns_public_key_bytes=2 * chain[0] * p.dimension * 8,
        raw_rns_input_bytes=2 * inputs * chain[0] * p.dimension * 8,
        raw_rns_output_bytes=arity * chain[-1] * p.dimension * 8,
        recipient_phase_ring_products=arity - 1,
        ideal_two_batch_gap_factor=2 * (len(vertices) + 2 * inputs),
        largest_creation_row_game=max(v["incoming_rows"] for v in vertices),
        security_128_qualified=False, encrypted_execution=False)


def select(length, family, policy):
    depth = 3 if family == "W2-deep" else 1
    chains = [tuple(reversed(c)) for c in
              combinations_with_replacement(range(1, 5), depth)]
    results = [profile_record(length, family, policy, chain) for chain in chains]
    passing = [row for row in results if row["admitted"]]
    # Public ranking for this finite admission family only.
    selected = min(passing, key=lambda row: (
        row["chain"][0], row["raw_rns_hint_bytes"], sum(row["chain"]), row["chain"]))
    return dict(selected=selected, candidate_count=len(chains),
                admitted_count=len(passing),
                rejected=[row for row in results if not row["admitted"]])


def check():
    started = time.monotonic()
    for family, chain in (("unknown", [2]), ("W2-deep", [2, 3, 1])):
        try:
            profile_record(256, family, "raw", chain)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid profile was not rejected")
    cases = {}
    for length, family in ((16, "W1"), (256, "W1"),
                           (256, "W2-shallow"), (256, "W2-deep")):
        name = f"{family}-L{length}"
        cases[name] = {policy: select(length, family, policy)
                       for policy in ("raw", "canonical")}
    assert cases["W1-L16"]["raw"]["selected"]["chain"] == [1]
    assert cases["W1-L16"]["canonical"]["selected"]["chain"] == [2]
    assert cases["W1-L256"]["raw"]["selected"]["chain"] == [2]
    assert cases["W2-shallow-L256"]["raw"]["selected"]["chain"] == [2]
    raw_deep = cases["W2-deep-L256"]["raw"]["selected"]
    canonical_deep = cases["W2-deep-L256"]["canonical"]["selected"]
    assert raw_deep["chain"] == [3, 2, 1]
    assert canonical_deep["chain"] == [4, 3, 2]
    assert (raw_deep["hint_rows"], raw_deep["raw_rns_hint_bytes"],
            raw_deep["independent_keys"], raw_deep["executed_rekeys"],
            raw_deep["executed_prime_drops"]) == (14, 36 * 2**20, 3, 6, 6)
    assert (canonical_deep["hint_rows"], canonical_deep["raw_rns_hint_bytes"]) == (
        24, 76 * 2**20)
    assert (raw_deep["ideal_two_batch_gap_factor"],
            raw_deep["largest_creation_row_game"]) == (54, 8)
    assert (raw_deep["raw_rns_public_key_bytes"], raw_deep["raw_rns_input_bytes"],
            raw_deep["raw_rns_output_bytes"]) == (3 * 2**20, 36 * 2**20, 3 * 2**19)
    short = cases["W1-L16"]["raw"]["selected"]
    assert (short["raw_rns_public_key_bytes"], short["raw_rns_input_bytes"],
            short["raw_rns_output_bytes"], short["hint_rows"],
            short["ideal_two_batch_gap_factor"]) == (
                64 * 2**10, 128 * 2**10, 96 * 2**10, 0, 10)
    assert cases["W2-shallow-L256"]["raw"]["selected"]["ideal_two_batch_gap_factor"] == 14
    cells = [dict(family=family, length=length, jobs=jobs,
                  native_carriers=1, occupied_lanes=jobs, charged_lanes=16,
                  profile_case=f"{family}-L{length}")
             for family, length, jobs in (
                 ("W1", 16, 1), ("W1", 16, 16), ("W1", 256, 1),
                 ("W1", 256, 16), ("W2-shallow", 256, 16),
                 ("W2-deep", 256, 16))]
    sources = [
        Path(__file__), PAPER / "research/core_native.py",
        PAPER / "research/check_composition_modulus_chain.py",
        PAPER / "research/check_composition_rns_arithmetic.py",
        PAPER / "research/CORE_GRID_V1_DESIGN.md",
        PAPER / "appendices/terminal-core-admission.tex",
    ]
    return dict(
        schema="terminal-core-profile-manifest-v1", cases=cases, primary_cells=cells,
        ranking="top limbs, hint bytes, sum of chain limbs, lexicographic chain",
        scope="width48, frozen four-prime prefixes, balanced circuit, two terminal policies",
        raw_bytes_exclude_metadata_codec_and_peak_workspace=True,
        global_optimum=False, security_128_qualified=False, benchmark=False,
        encrypted_execution=False, conventional_profiles_selected=False,
        immutable_timing_protocol_supplied=False,
        sources_sha256={p.relative_to(ROOT).as_posix():
                        hashlib.sha256(p.read_bytes()).hexdigest().upper()
                        for p in sources},
        verification_seconds=time.monotonic() - started)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--output", type=Path)
    modes.add_argument("--verify", type=Path)
    args = parser.parse_args()
    result = check()
    if args.output:
        destination = args.output.resolve()
        assert destination.parent == (PAPER / "evidence").resolve()
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    if args.verify:
        archived = json.loads(args.verify.read_text(encoding="utf-8"))
        assert {k: v for k, v in archived.items() if k != "verification_seconds"} == {
            k: v for k, v in result.items() if k != "verification_seconds"}
    print(json.dumps(dict(status="PASS", primary_cells=len(result["primary_cells"]),
                         raw_chains={k: v["raw"]["selected"]["chain"]
                                     for k, v in result["cases"].items()},
                         raw_deep_hint_mib=36, canonical_deep_hint_mib=76,
                         security_128_qualified=False, encrypted_execution=False),
                     indent=2))
