"""Fixed public W1/W2 inputs and independent schoolbook plaintext oracles.

This deterministic fixture is not encryption randomness or application demand.
Each named input is separately owned; the generator has no HE dependencies.
"""
from array import array
from hashlib import sha256
from struct import pack

from check_fused_composition_frontier import FastField
from core_terminal_codec import truncated_product

MASK = (1 << 64) - 1
SEED = 0x4A45544845434F52
CELLS = {
    "w1-l16-j1": ("W1", 16, 1),
    "w1-l16-j16": ("W1", 16, 16),
    "w1-l256-j1": ("W1", 256, 1),
    "w1-l256-j16": ("W1", 256, 16),
    "w2-shallow-l256-j16": ("W2-shallow", 256, 16),
    "w2-deep-l256-j16": ("W2-deep", 256, 16),
}


def inputs(cell):
    family, length, jobs = CELLS[cell]
    code = {"W1": 1, "W2-shallow": 2, "W2-deep": 3}[family]
    state = SEED ^ (code << 48) ^ (length << 16) ^ jobs

    def draw():
        nonlocal state
        state = (state + 0x9E3779B97F4A7C15) & MASK
        z = ((state ^ (state >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return (z ^ (z >> 31)) & 65535

    names = ["a0", "b0"] if family == "W1" else [
        f"{name}{i}" for i in range(4 if family == "W2-deep" else 1) for name in "abc"]
    return {name: array("H", (draw() for _ in range(length*jobs))) for name in names}


def metadata(cell, values=None):
    values = inputs(cell) if values is None else values
    family, length, jobs = CELLS[cell]
    raw = b"".join(pack("<"+str(len(value))+"H", *value) for value in values.values())
    fnv = 14695981039346656037
    for byte in raw:
        fnv = ((fnv ^ byte) * 1099511628211) & MASK
    return dict(id="core-grid-v1/"+cell, family=family, length=length, jobs=jobs,
                field_polynomial="0x1100b", input_order=list(values),
                serialization="input-major, job-major, coefficient-major uint16 little endian",
                sha256=sha256(raw).hexdigest(), fnv64=str(fnv), seed_hex=hex(SEED),
                application_distribution=False, encryption_randomness=False)


def oracle_states(cell, values=None):
    values = inputs(cell) if values is None else values
    family, length, jobs = CELLS[cell]
    field = FastField()

    def multiply(left, right):
        out = array("H")
        for j in range(jobs):
            out.extend(truncated_product(field, left[j*length:(j+1)*length],
                                         right[j*length:(j+1)*length], length))
        return out

    states = dict(values)
    current = []
    for i in range(4 if family == "W2-deep" else 1):
        value = multiply(values[f"a{i}"], values[f"b{i}"])
        if family != "W1":
            value = array("H", (a ^ b for a, b in zip(value, values[f"c{i}"])))
        states[f"level1/{i}"] = value
        current.append(value)
    level = 1
    while len(current) > 1:
        level += 1
        current = [multiply(current[i], current[i+1]) for i in range(0, len(current), 2)]
        states.update({f"level{level}/{i}": value for i, value in enumerate(current)})
    return states, current[0]
