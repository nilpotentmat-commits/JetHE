"""Deterministic plaintext checks; no HE execution, timing, or security claim.

The compiler moves Frobenius gates to independently prepared input variants.
An ordinary truncated-polynomial evaluator checks its outputs.  The exact
syntactic gate counts do not assert optimal arithmetic-circuit lower bounds.
"""

from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
import json
from random import Random


def poly_rem(a, b):
    while a and a.bit_length() >= b.bit_length():
        a ^= b << (a.bit_length() - b.bit_length())
    return a


def poly_gcd(a, b):
    while b:
        a, b = b, poly_rem(a, b)
    return a


class Field:
    def __init__(self, degree, modulus):
        self.d, self.modulus = degree, modulus
        assert modulus.bit_length() == degree + 1
        x = poly_rem(2, modulus)
        powers = [x]
        for _ in range(degree):
            powers.append(self.mul(powers[-1], powers[-1]))
        assert powers[-1] == x
        primes = [r for r in range(2, degree + 1)
                  if degree % r == 0 and all(r % j for j in range(2, r))]
        assert all(poly_gcd(powers[degree // r] ^ x, modulus) == 1
                   for r in primes), "Rabin irreducibility certificate failed"

    def mul(self, a, b):
        result = 0
        while b:
            if b & 1:
                result ^= a
            b >>= 1
            a <<= 1
            if a >> self.d:
                a ^= self.modulus
        return result


class Jets:
    def __init__(self, field, length):
        self.field, self.length = field, length
        self.a = (length - 1).bit_length()
        self.states = self.a + field.d

    def canonical(self, state):
        return state if state < self.a else self.a + (state - self.a) % self.field.d

    def add(self, x, y):
        return tuple(a ^ b for a, b in zip(x, y))

    def mul(self, x, y):
        out = [0] * self.length
        for i, a in enumerate(x):
            if a:
                for j, b in enumerate(y[:self.length - i]):
                    if b:
                        out[i + j] ^= self.field.mul(a, b)
        return tuple(out)

    def frobenius_formula(self, x, state):
        out = [0] * self.length
        for j in range((self.length - 1) // (1 << state) + 1):
            c = x[j]
            for _ in range(state % self.field.d):
                c = self.field.mul(c, c)
            out[j << state] = c
        return tuple(out)

    def ordinary_power(self, x, state):
        for _ in range(state):
            x = self.mul(x, x)
        return x

    def random(self, rng):
        return tuple(rng.randrange(1 << self.field.d) for _ in range(self.length))


@dataclass(frozen=True)
class Node:
    op: str
    args: tuple = ()
    data: object = None


class Circuit:
    def __init__(self):
        self.nodes = []

    def node(self, op, *args, data=None):
        self.nodes.append(Node(op, tuple(args), data))
        return len(self.nodes) - 1


def compile_inputs(circuit, outputs, jets):
    target = Circuit()
    demands = set()

    @lru_cache(None)
    def visit(v, state):
        assert state == jets.canonical(state)
        demands.add((v, state))
        node = circuit.nodes[v]
        if node.op == "input":
            return target.node("prepared", data=(node.data, state))
        if node.op == "constant":
            return target.node("constant", data=jets.frobenius_formula(node.data, state))
        if node.op == "square":
            return visit(node.args[0], jets.canonical(state + 1))
        return target.node(node.op, *(visit(w, state) for w in node.args))

    transformed = tuple(visit(v, 0) for v in outputs)
    return target, transformed, demands


def evaluate(circuit, outputs, inputs, jets):
    @lru_cache(None)
    def value(v):
        node = circuit.nodes[v]
        if node.op == "input":
            return inputs[node.data]
        if node.op == "prepared":
            i, state = node.data
            # Independent repeated ordinary multiplication, not the formula.
            return jets.ordinary_power(inputs[i], state)
        if node.op == "constant":
            return node.data
        if node.op == "square":
            x = value(node.args[0])
            return jets.mul(x, x)
        fn = jets.add if node.op == "add" else jets.mul
        return fn(*(value(w) for w in node.args))

    return tuple(value(v) for v in outputs)


def product_depth(circuit, outputs):
    @lru_cache(None)
    def depth(v):
        node = circuit.nodes[v]
        return max((depth(w) for w in node.args), default=0) + (node.op == "mul")
    return max(map(depth, outputs), default=0)


def check_circuit(circuit, outputs, inputs, jets):
    target, new_outputs, demands = compile_inputs(circuit, outputs, jets)
    assert evaluate(circuit, outputs, inputs, jets) == evaluate(target, new_outputs, inputs, jets)
    counts = Counter(n.op for n in target.nodes)
    for op in ("mul", "add"):
        assert counts[op] == sum(circuit.nodes[v].op == op for v, _ in demands)
        assert counts[op] <= jets.states * sum(n.op == op for n in circuit.nodes)
    assert not counts["square"]
    assert product_depth(target, new_outputs) <= product_depth(circuit, outputs)
    return counts, demands


def main():
    rng = Random(20260907)
    fields = [Field(1, 0x3), Field(2, 0x7), Field(3, 0xB), Field(4, 0x13), Field(16, 0x1100B)]
    identities = dags = formulas = 0
    for field in fields:
        for length in (1, 2, 3, 4, 5, 8):
            jets = Jets(field, length)
            x = jets.random(rng)
            for state in range(jets.a + 2 * field.d + 3):
                direct = jets.ordinary_power(x, state)
                assert direct == jets.frobenius_formula(x, state)
                assert direct == jets.frobenius_formula(x, jets.canonical(state))
                identities += 1
            for _ in range(10):
                circuit = Circuit()
                for i in range(3):
                    circuit.node("input", data=i)
                circuit.node("constant", data=jets.random(rng))
                for _ in range(28):
                    op = rng.choice(("add", "mul", "square"))
                    args = [rng.randrange(len(circuit.nodes))
                            for _ in range(1 if op == "square" else 2)]
                    circuit.node(op, *args)
                check_circuit(circuit, (29, 30, 31), [jets.random(rng) for _ in range(3)], jets)
                dags += 1
            for _ in range(5):
                circuit = Circuit()
                leaves = [circuit.node("input", data=i) for i in range(3)]

                def tree(depth):
                    if depth == 0:
                        return rng.choice(leaves)
                    op = rng.choice(("add", "mul", "square"))
                    return circuit.node(op, *(tree(depth - 1)
                                              for _ in range(1 if op == "square" else 2)))

                output = tree(5)
                counts, _ = check_circuit(circuit, (output,), [jets.random(rng) for _ in range(3)], jets)
                assert counts["mul"] == sum(n.op == "mul" for n in circuit.nodes)
                assert counts["add"] == sum(n.op == "add" for n in circuit.nodes)
                formulas += 1

    # Exact full-jet research profile, not merely a constant/low-degree case.
    jets = Jets(fields[-1], 256)
    circuit = Circuit()
    a, b, c = [circuit.node("input", data=i) for i in range(3)]
    d = circuit.node("mul", a, b)
    f = circuit.node("mul", circuit.node("square", d), c)
    counts, _ = check_circuit(circuit, (d, f), [jets.random(rng) for _ in range(3)], jets)
    assert counts["mul"] == 3 and counts["prepared"] == 5
    useful = sum((255 // (1 << state)) + 1 for state in range(jets.states))
    assert jets.states == 24 and useful == 526
    # A shared product requested in every state attains the syntactic S*M
    # ceiling.  Check the same compiler independently on three full lanes.
    stress_jets = Jets(fields[2], 5)
    stress = Circuit()
    x, y = [stress.node("input", data=i) for i in range(2)]
    chain = [stress.node("mul", x, y)]
    for _ in range(stress_jets.states + 2):
        chain.append(stress.node("square", chain[-1]))
    for _ in range(3):
        stress_counts, _ = check_circuit(stress, tuple(chain),
                                        [stress_jets.random(rng) for _ in range(2)], stress_jets)
        assert stress_counts["mul"] == stress_jets.states
        assert stress_counts["prepared"] == 2 * stress_jets.states
    print(json.dumps({
        "scope": "deterministic plaintext and syntactic compiler checks only",
        "irreducible_field_moduli_checked": len(fields),
        "frobenius_state_identities": identities,
        "random_shared_dags": dags,
        "single_output_formulas": formulas,
        "all_state_shared_product_lanes": 3,
        "L256_d16": {"states": jets.states, "useful_positions_per_lane": useful,
                     "shared_AB_kernel_compiled_products": counts["mul"],
                     "shared_AB_kernel_prepared_inputs": counts["prepared"]},
        "security_or_runtime_result": False,
    }, indent=2))


if __name__ == "__main__":
    main()
