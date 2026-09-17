"""Bounded public fusion/hint-bit frontier; NOT HE execution or security admission.

All maps use arbitrary GF(2^16) coefficients. Fused weights are constructed
from evaluation/interpolation, with exact physical C2 x C256 automorphisms.
The finite optimizer minimizes ONLY serialized hint bits under the declared
unscaled deterministic envelope, not runtime, public-key bits or security.
"""

from functools import lru_cache
from itertools import product
from math import gcd
from random import Random
import json

from check_frobenius_compiler import Field
from check_private_composition import value, power, compose, mul
from check_encrypted_transform_compiler import (subspaces, interleaved_composition,
                                                tensor_mul, tensor_auto)
from check_native_composition import bounds as native_bounds, mixed_hasse, frobenius, hasse


class FastField:
    def __init__(self):
        self.d, self.order = 16, 65535
        base = Field(16, 0x1100B)
        generator = next(a for a in range(2, 50)
                         if all(power(a, self.order // p, base) != 1 for p in (3, 5, 17, 257)))
        self.logs, exponents = [0] * 65536, []
        x = 1
        for i in range(self.order):
            self.logs[x] = i
            exponents.append(x)
            x = base.mul(x, generator)
        assert x == 1 and len(set(exponents)) == self.order
        self.exponents = exponents + exponents
        self.frob8 = [0] + [exponents[(256 * self.logs[x]) % self.order] for x in range(1, 65536)]
        for a in (0, 1, 2, 19, 1023, 65535):
            for b in (0, 1, 3, 57, 65534):
                assert self.mul(a, b) == base.mul(a, b)

    def mul(self, a, b):
        return self.exponents[self.logs[a] + self.logs[b]] if a and b else 0


def auto(vector, exponent, field):
    """Physical A^epsilon C^k action; includes nontrivial Frobenius on wrap."""
    epsilon, k = exponent
    out = []
    for row in range(256):
        a, c = divmod(row, 128)
        shift = c + k
        target = 128 * (a ^ epsilon) + shift % 128
        v = vector[target]
        out.append(field.frob8[v] if (shift // 128) & 1 else v)
    return out


def add_entry(weights, row, column, scalar):
    if scalar:
        a0, c0 = divmod(row, 128)
        a1, c1 = divmod(column, 128)
        exponent = (a0 ^ a1, (c1 - c0) % 256)
        weights.setdefault(exponent, [0] * 256)[row] ^= scalar


def apply_weights(weights, vector, field):
    out = [0] * 256
    for exponent, diagonal in weights.items():
        shifted = auto(vector, exponent, field)
        for i, a in enumerate(diagonal):
            if a:
                out[i] ^= field.mul(a, shifted[i])
    return out


def bsgs_support(weight_maps, baby):
    support = {exponent for weights in weight_maps for exponent in weights}
    babies = {t % baby for _, t in support}
    giants = {(a, t - t % baby) for a, t in support}
    return babies, giants


def apply_bsgs(weight_maps, vectors, field, baby):
    babies, giants = bsgs_support(weight_maps, baby)
    shifted = [{j: auto(vector, (0, j), field) for j in babies} for vector in vectors]
    accumulators = {gamma: [0] * 256 for gamma in giants}
    for weights, inputs in zip(weight_maps, shifted):
        for (epsilon, t), diagonal in weights.items():
            j, gamma = t % baby, (epsilon, t - t % baby)
            twisted = auto(diagonal, (gamma[0], (-gamma[1]) % 256), field)
            accumulator = accumulators[gamma]
            for i, a in enumerate(twisted):
                if a:
                    accumulator[i] ^= field.mul(a, inputs[j][i])
    out = [0] * 256
    for gamma, accumulator in accumulators.items():
        shifted = auto(accumulator, gamma, field)
        out = [a ^ b for a, b in zip(out, shifted)]
    return out


def interpolation_matrix(n, field):
    polys, points = subspaces([1 << i for i in range(n.bit_length() - 1)], field)
    vanishing = polys[-1]
    inv_delta = power(vanishing[1], 65534, field)
    rows = [[0] * n for _ in range(n)]
    for column, point in enumerate(points):
        quotient = [0] * n
        quotient[-1] = 1
        for i in reversed(range(n - 1)):
            quotient[i] = vanishing[i + 1] ^ field.mul(point, quotient[i + 1])
        assert field.mul(point, quotient[0]) == vanishing[0]
        for i, c in enumerate(quotient):
            rows[i][column] = field.mul(c, inv_delta)
    return rows


def fused_maps(b, field):
    n, r = 1 << b, 256 >> b
    interpolation = interpolation_matrix(n, field)
    pre, odd, even = {}, {}, {}
    for t in range(r):
        for point in range(n):
            coefficient = 1
            for i in range(n // 2):
                add_entry(pre, t + r * point, t + r + 2 * r * i, coefficient)
                add_entry(odd, t + r + 2 * r * i, t + r * point, interpolation[i][point])
                if i < n // 2 - 1:
                    add_entry(even, t + 2 * r * (i + 1), t + r * point, interpolation[i][point])
                coefficient = field.mul(coefficient, point)
    return tuple({k: v for k, v in weights.items() if any(v)} for weights in (pre, odd, even))


KAPPA, DIGIT, BETA, INITIAL, FRESH = 332661, 128, 20, 1 << 20, 1 << 20
LAM_UNIT = KAPPA * DIGIT * BETA


def methods(weight_maps, raw=False, prune=True):
    """Bank/application counts per physical state group; no public constants are free."""
    count = sum(len(x) for x in weight_maps)
    arity, nu = len(weight_maps), 2 if raw else 1
    result = [{"name": "direct_raw" if raw else "direct", "banks": nu * count,
               "switch": nu * count, "destinations": 1, "ext": nu * count,
               "decompositions": nu * arity, "public_products": count}]
    for baby in (1, 2, 4, 8, 16, 32, 64, 128, 256):
        babies, giants = bsgs_support(weight_maps, baby)
        bb, hh = len(babies), len(giants)
        result.append({"name": f"bsgs{baby}" + ("_raw" if raw else ""),
                       "banks": nu * bb + hh, "switch": nu * count * KAPPA + hh,
                       "destinations": 2, "ext": nu * arity * bb + hh,
                       "decompositions": nu * arity + hh, "public_products": 2 * count})
    # Full physical automorphism tree, including identity switches at each depth.
    result.append({"name": "tree_raw" if raw else "tree", "banks": 18 + 2 * (nu - 1),
                   "switch": count * KAPPA * (9 + nu - 1), "destinations": 9,
                   "ext": arity * (1022 + 2 * (nu - 1)),
                   "decompositions": arity * (511 + nu - 1), "public_products": 2 * count})
    if not prune:
        return result
    # Preserve work tradeoffs in the receipts, but bit-frontier optimization only
    # requires bank/switch nondominance. No runtime optimality follows.
    unique = {}
    for method in result:
        key = (method["banks"], method["switch"])
        old = unique.get(key)
        if old is None or (method["ext"], method["destinations"]) < (old["ext"], old["destinations"]):
            unique[key] = method
    return [m for m in unique.values() if not any(
        other["banks"] <= m["banks"] and other["switch"] <= m["switch"]
        and (other["banks"], other["switch"]) != (m["banks"], m["switch"])
        for other in unique.values())]


def level_options(weight_maps, prune=True):
    pre, odd, even = weight_maps
    p = len(pre)
    post_maps = [odd] + ([even] if even else [])
    h, channels = sum(len(x) for x in post_maps), len(post_maps)
    result = []
    for pm in methods([pre], prune=prune):
        for raw in (False, True):
            for qm in methods(post_maps, raw, prune=prune):
                def step(B, g):
                    lam = LAM_UNIT * g
                    A = p * KAPPA * B + pm["switch"] * lam + (p * KAPPA + 1) // 2
                    P = KAPPA * ((1 + 2 * FRESH) * A + FRESH) + (KAPPA + 1) // 2
                    if not raw:
                        P += 2 * lam
                    return (KAPPA * (h * P + B) + (qm["switch"] + 1) * lam
                            + ((h + 1) * KAPPA + 1) // 2)
                constant = step(0, 0)
                a, c = step(1, 0) - constant, step(0, 1) - constant
                result.append({"pre": pm["name"], "post": qm["name"],
                               "banks": pm["banks"] + qm["banks"] + 1 + (0 if raw else 2),
                               "a": a, "c": c, "z": constant,
                               "destinations": pm["destinations"] + qm["destinations"] + int(not raw),
                               "ext": 2 * (pm["ext"] + qm["ext"] + 1 + (0 if raw else 2 * channels)),
                               "decompositions": 2 * (pm["decompositions"] + qm["decompositions"]
                                                      + 1 + (0 if raw else 2 * channels)),
                               "public_products": 2 * (pm["public_products"] + qm["public_products"] + 1),
                               "raw": raw})
    # These alternatives have exactly the same source gain and constant term.
    assert len({(o["a"], o["z"]) for o in result}) == 1
    return result


def owner_folded_first_level():
    """g-owner prepares (1,g_1^128): one pointwise product is the entire level.

    This uses the EXISTING prepared-inner interface, not extra f preparation.
    Two physical f ciphertexts cover sixteen jobs. All banks share fresh key f.
    """
    return [{"pre": "owner_folded", "post": "relinearize", "banks": 2,
             "a": KAPPA * (1 + 2 * FRESH), "c": 2 * LAM_UNIT,
             "z": KAPPA * FRESH + (KAPPA + 1) // 2,
             "destinations": 1, "ext": 4, "decompositions": 4,
             "public_products": 0, "raw": False}]


def prepared_two_level_prefix():
    """Two f variants and two g variants implement the first TWO levels.

    Sum both raw products before one shared relinearization per physical group.
    Four physical products, not two, are needed for sixteen jobs.
    """
    return [{"pre": "prepared_two_level", "post": "sum_then_relinearize", "banks": 2,
             "a": 2 * KAPPA * (1 + 2 * FRESH), "c": 2 * LAM_UNIT,
             "z": 2 * KAPPA * FRESH + KAPPA,
             "destinations": 1, "ext": 4, "decompositions": 4,
             "public_products": 0, "raw": False}]


def conventional_broadcast_prefix(prefix):
    """Matched 2^k owner f-variants; generic G^i coefficient preparation.

    The two special controls above remain stronger where applicable.
    """
    terms = (1 << prefix) - 1
    return [{"pre": f"broadcast_prefix{prefix}", "post": "sum_then_relinearize", "banks": 2,
             "a": 1 + terms * KAPPA * (1 + 2 * FRESH), "c": 2 * LAM_UNIT,
             "z": terms * KAPPA * FRESH + (terms * KAPPA + 1) // 2,
             "destinations": 1, "ext": 4, "decompositions": 4,
             "public_products": 0, "raw": False}]


def broadcast_prefix_state(f, g, field, prefix):
    n, r = 1 << prefix, len(f) >> prefix
    inner = [power(c, r, field) for c in g[:n]]
    state, current_power = f[:r] + [0] * (len(f) - r), [1] + [0] * (n - 1)
    for i in range(1, n):
        current_power = mul(current_power, inner, n, field)
        for t in range(r):
            for j, coefficient in enumerate(current_power):
                state[t + r * j] ^= field.mul(f[t + r * i], coefficient)
    return state


def collapsed_native(f, g, field, prefix):
    length, ell = len(f), len(f).bit_length() - 1
    tail = ell - prefix
    monomials = [[1] + [0] * (length - 1)]
    for j in range(tail, ell):
        u = frobenius(g, j, field)
        u[1 << j] ^= 1
        monomials += [mul(x, u, length, field) for x in monomials]
    state = list(f)
    for mask in range(1, 1 << prefix):
        term = mul(monomials[mask], mixed_hasse(f, mask << tail), length, field)
        state = [a ^ b for a, b in zip(state, term)]
    for j in reversed(range(tail)):
        u = frobenius(g, j, field)
        u[1 << j] ^= 1
        term = mul(u, hasse(state, 1 << j), length, field)
        state = [a ^ b for a, b in zip(state, term)]
    return state


def collapsed_native_noise(prefix, gadget):
    kappa, lam = 511 * 256, 511 * gadget * DIGIT * BETA
    products, tail = (1 << prefix) - 1, 8 - prefix
    noise = (INITIAL + products * kappa * ((1 + 2 * FRESH) * INITIAL + FRESH)
             + (products * kappa + 1) // 2 + 2 * 256 * lam)
    stages = [noise]
    for _ in range(tail):
        noise = (noise + 3 * 256 * lam
                 + kappa * ((1 + 2 * FRESH) * (noise + 256 * lam) + FRESH)
                 + (kappa + 1) // 2 + 1)
        stages.append(noise)
    return noise, stages


@lru_cache(None)
def admit(slope, constant, conductor):
    # Since g=ceil(bits/8), the exact fixed-point loop increases bits only.
    bits = max(64, (4 * constant + 3).bit_length())
    while bits <= 32768:
        g = (bits + 7) // 8
        noise = slope * g + constant
        required = (4 * noise + 3).bit_length()
        if bits < required:
            bits = required
            continue
        q = (1 << bits) - 1
        if q > 2 + 4 * noise and gcd(q, conductor) == 1:
            # Minimal within this q_bits family, allowing conductor constraints.
            return bits, g
        bits += 1
    raise AssertionError("Bounded modulus search exhausted")


def optimize(all_options):
    states = [{"banks": 0, "slope": 0, "constant": INITIAL,
               "destinations": 0, "ext": 0, "decompositions": 0,
               "public_products": 0, "schedule": []}]
    widths = []
    for options in all_options:
        candidates = {}
        for previous in states:
            for option in options:
                state = {k: previous[k] + option[k] for k in
                         ("banks", "destinations", "ext", "decompositions", "public_products")}
                state.update(slope=option["a"] * previous["slope"] + option["c"],
                             constant=option["a"] * previous["constant"] + option["z"],
                             schedule=previous["schedule"] + [option])
                # For fixed bank count, smaller slope dominates for all g.
                old = candidates.get(state["banks"])
                if old is None or (state["slope"], state["ext"]) < (old["slope"], old["ext"]):
                    candidates[state["banks"]] = state
        assert len({s["constant"] for s in candidates.values()}) == 1
        best_slope, states = None, []
        for bank_count in sorted(candidates):
            state = candidates[bank_count]
            if best_slope is None or state["slope"] < best_slope:
                states.append(state)
                best_slope = state["slope"]
        widths.append(len(states))
    for state in states:
        bits, g = admit(state["slope"], state["constant"], 65535)
        state.update(bits=bits, g=g, hint_bits=2 * 32768 * state["banks"] * g * bits)
    return states, widths


def receipt(state):
    return {"banks": state["banks"], "modulus_bits": state["bits"], "gadget_digits": state["g"],
            "hint_bits": state["hint_bits"], "independent_keys": state["destinations"] + 1,
            "paired_ext_over_g": state["ext"], "coefficient_decompositions_over_mC": state["decompositions"],
            "public_ring_products": state["public_products"],
            "schedule": [[o["pre"], o["post"]] for o in state["schedule"]]}


def evaluate_schedule(schedule):
    state = {k: 0 for k in ("banks", "slope", "destinations", "ext",
                           "decompositions", "public_products")}
    state.update(constant=INITIAL, schedule=list(schedule))
    for option in schedule:
        for key in ("banks", "destinations", "ext", "decompositions", "public_products"):
            state[key] += option[key]
        state["slope"] = option["a"] * state["slope"] + option["c"]
        state["constant"] = option["a"] * state["constant"] + option["z"]
    bits, g = admit(state["slope"], state["constant"], 65535)
    state.update(bits=bits, g=g, hint_bits=2 * 32768 * state["banks"] * g * bits)
    # Independently replay every stage at the selected gadget length.
    noise, q = INITIAL, (1 << bits) - 1
    for option in schedule:
        noise = option["a"] * noise + option["c"] * g + option["z"]
        assert q > 2 + 4 * noise
    assert noise == state["slope"] * g + state["constant"]
    # Exhaustive bit-length check, including conductor exclusions, is bounded.
    for smaller in range(1, bits):
        small_q, small_g = (1 << smaller) - 1, (smaller + 7) // 8
        assert (small_q <= 2 + 4 * (state["slope"] * small_g + state["constant"])
                or gcd(small_q, 65535) != 1)
    return state


def optimizer_checks(all_options):
    # Exhaust all short-prefix choices, independently of DP pruning.
    brute = [evaluate_schedule(schedule) for schedule in product(*all_options[:3])]
    frontier, _ = optimize(all_options[:3])
    for state in brute:
        assert any(x["banks"] <= state["banks"] and x["slope"] <= state["slope"]
                   for x in frontier)
    assert min(x["hint_bits"] for x in brute) == min(x["hint_bits"] for x in frontier)
    return len(brute)


def noisy_transport_checks(rng):
    """Tiny formal integer phases, including shared raw s,s^2 rows; not HE.

    One exact digit is used per coefficient. Its observed bound is charged.
    The order-eight tensor automorphism tree tests the depth recurrence;
    the nine-level physical tree counts are a separate analytic specialization.
    """
    primes, m, kappa, cases = (3, 5), 8, 21, 0
    mul = lambda a, b: tensor_mul(a, b, primes)
    tau = lambda a, e: tensor_auto(a, e, primes)
    add = lambda a, b: [x + y for x, y in zip(a, b)]
    scale = lambda a, n: [n * x for x in a]
    rand = lambda low, high: [rng.randrange(low, high) for _ in range(m)]
    identity = [1] * m  # (-sum zeta_3^i)(-sum zeta_5^j) = 1.
    phase = lambda c, s: add(c[0], mul(c[1], s)) if len(c) == 2 else add(
        add(c[0], mul(c[1], s)), mul(c[2], mul(s, s)))
    for nu, arity, _ in product((1, 2), (1, 2), range(3)):
        secret = rand(-1, 2)
        messages, inputs = [], []
        for _channel in range(arity):
            mu, err = rand(0, 2), rand(-3, 4)
            c = [[0] * m] + [rand(-2, 3) for _ in range(nu)]
            c[0] = add(add(mu, scale(err, 2)), scale(phase(c, secret), -1))
            assert phase(c, secret) == add(mu, scale(err, 2))
            messages.append(mu)
            inputs.append(c)
        weights = [{e: rand(0, 2) for e in (1, 2, 4, 7, 8, 11, 13, 14)}
                   for _ in range(arity)]
        clean = [0] * m
        for mu, coefficients in zip(messages, weights):
            for e, a in coefficients.items():
                clean = add(clean, mul(a, tau(mu, e)))
        canonical = [x % 2 for x in clean]
        for mode in ("bsgs", "tree"):
            digit_bound, cache = [1], {}

            def switch(c, source, destination, exponent, level):
                out = [tau(c[0], exponent), [0] * m]
                secret_power = list(identity)
                for index, component in enumerate(c[1:], 1):
                    secret_power = mul(secret_power, source)
                    key = (level, exponent, index)
                    if key not in cache:
                        mask, row_error = rand(-2, 3), rand(-2, 3)
                        payload = tau(secret_power, exponent)
                        cache[key] = (add(add(payload, scale(row_error, 2)),
                                          scale(mul(mask, destination), -1)), mask, row_error)
                    row0, row1, _error = cache[key]
                    digit = tau(component, exponent)
                    digit_bound[0] = max(digit_bound[0], max(map(abs, digit)))
                    out[0] = add(out[0], mul(digit, row0))
                    out[1] = add(out[1], mul(digit, row1))
                return out

            if mode == "bsgs":
                middle, final = rand(-1, 2), rand(-1, 2)
                babies, giants = (1, 2), (1, 4, 7, 13)
                baby_inputs = [{j: switch(c, secret, middle, j, 0) for j in babies}
                               for c in inputs]
                output = [[0] * m, [0] * m]
                for giant in giants:
                    accumulator = [[0] * m, [0] * m]
                    for coefficients, channel in zip(weights, baby_inputs):
                        for baby in babies:
                            twisted = tau(coefficients[giant * baby % 15], pow(giant, -1, 15))
                            for component in (0, 1):
                                accumulator[component] = add(accumulator[component],
                                                              mul(twisted, channel[baby][component]))
                    shifted = switch(accumulator, middle, final, giant, 1)
                    output = [add(a, b) for a, b in zip(output, shifted)]
                bank_count, switching = nu * 2 + 4, nu * 8 * arity * kappa + 4
            else:
                destinations = [rand(-1, 2) for _ in range(3)]
                output = [[0] * m, [0] * m]
                for coefficients, c in zip(weights, inputs):
                    nodes, source = {1: c}, secret
                    for level, generator in enumerate((14, 2, 4)):
                        target, new_nodes = destinations[level], {}
                        for e, node in nodes.items():
                            for rotation in (1, generator):
                                new_nodes[e * rotation % 15] = switch(node, source, target, rotation, level)
                        nodes, source = new_nodes, target
                    assert len(nodes) == 8
                    for e, node in nodes.items():
                        output = [add(a, mul(coefficients[e], b)) for a, b in zip(output, node)]
                final = destinations[-1]
                bank_count, switching = 6 + 2 * (nu - 1), 8 * arity * kappa * (3 + nu - 1)
            assert len(cache) == bank_count
            actual_phase = phase(output, final)
            assert all((x - y) % 2 == 0 for x, y in zip(actual_phase, canonical))
            error = [(x - y) // 2 for x, y in zip(actual_phase, canonical)]
            lam = kappa * digit_bound[0] * 2
            bound = 8 * arity * kappa * 3 + switching * lam + (8 * arity * kappa + 1) // 2
            assert max(map(abs, error)) <= bound
            q = 4 * bound + 3
            assert [((x + q // 2) % q - q // 2) % 2 for x in actual_phase] == canonical
            cases += 1
    return cases


def raw_sum_phase_checks(rng):
    """One joint canonical carry for sums of private products, with/without f0."""
    primes, m, kappa, cases = (3, 5), 8, 21, 0
    mul_t = lambda a, b: tensor_mul(a, b, primes)
    add = lambda a, b: [x + y for x, y in zip(a, b)]
    rand = lambda low, high: [rng.randrange(low, high) for _ in range(m)]
    for bypass, terms, _ in product((False, True), (1, 2, 3, 15), range(3)):
        mu0, e0 = (rand(0, 2), rand(-3, 4)) if bypass else ([0] * m, [0] * m)
        clean, phase = list(mu0), [a + 2 * e for a, e in zip(mu0, e0)]
        for _term in range(terms):
            a, b, ea, eb = rand(0, 2), rand(0, 2), rand(-3, 4), rand(-2, 3)
            clean = add(clean, mul_t(a, b))
            phase = add(phase, mul_t([x + 2 * e for x, e in zip(a, ea)],
                                    [x + 2 * e for x, e in zip(b, eb)]))
        relin_error = rand(-4, 5)
        phase = [x + 2 * e for x, e in zip(phase, relin_error)]
        canonical = [x % 2 for x in clean]
        carry = [(x - y) // 2 for x, y in zip(clean, canonical)]
        assert max(map(abs, carry)) <= (terms * kappa + 1) // 2
        bound = 3 * int(bypass) + terms * kappa * ((1 + 2 * 2) * 3 + 2) + (terms * kappa + 1) // 2 + 4
        assert max(abs((x - y) // 2) for x, y in zip(phase, canonical)) <= bound
        assert all((x - y) % 2 == 0 for x, y in zip(phase, canonical))
        cases += 1
    return cases


def main():
    field, rng = FastField(), Random(2026090810)
    maps, profiles, bsgs_cases = [], [], 0
    for b in range(1, 9):
        pre, odd, even = fused_maps(b, field)
        maps.append((pre, odd, even))
        profiles.append([b, len(pre), len(odd), len(even)])
        x, y = ([rng.randrange(65536) for _ in range(256)] for _ in range(2))
        for baby in (1, 2, 4, 8, 16, 32, 64, 128, 256):
            assert apply_bsgs([pre], [x], field, baby) == apply_weights(pre, x, field)
            target = [a ^ b for a, b in zip(apply_weights(odd, x, field), apply_weights(even, y, field))]
            assert apply_bsgs([odd, even], [x, y], field, baby) == target
            bsgs_cases += 2
    f, g = ([rng.randrange(65536) for _ in range(256)] for _ in range(2))
    g[0], state, state_history = 0, list(f), []
    for b, (pre, odd, even) in enumerate(maps, 1):
        j, r, n = 8 - b, 256 >> b, 1 << b
        inner = [power(c, 1 << j, field) for c in g[:n]]
        prepared_odd = [value(inner[1::2], i // r, field) for i in range(256)]
        prepared_even = [value(inner[2::2], i // r, field) for i in range(256)]
        v = apply_weights(pre, state, field)
        po = [field.mul(a, z) for a, z in zip(v, prepared_odd)]
        pe = [field.mul(a, z) for a, z in zip(v, prepared_even)]
        left, right = apply_weights(odd, po, field), apply_weights(even, pe, field)
        updated = [a ^ b ^ (c if not i & r else 0) for i, (a, b, c) in enumerate(zip(left, right, state))]
        if b == 1:
            diagonal = [1 if i < 128 else power(g[1], 128, field) for i in range(256)]
            assert updated == [field.mul(a, z) for a, z in zip(state, diagonal)]
        if b == 2:
            # Direct owner-prepared XY+VW control, in the original four-slot blocks.
            h = [power(c, 64, field) for c in g[:4]]
            prepared = [0] * 256
            for t in range(64):
                prepared[t] = f[t]
                prepared[t + 64] = field.mul(h[1], f[t + 64])
                prepared[t + 128] = (field.mul(h[2], f[t + 64])
                                      ^ field.mul(power(h[1], 2, field), f[t + 128]))
                prepared[t + 192] = (field.mul(h[3], f[t + 64])
                                      ^ field.mul(power(h[1], 3, field), f[t + 192]))
            assert prepared == updated
        state = updated
        state_history.append(list(state))
    assert state == compose(f, g, 256, field) == interleaved_composition(f, g, field)
    all_options = [owner_folded_first_level()] + [level_options(weights) for weights in maps[1:]]
    frontier, widths = optimize(all_options)
    winner = min(frontier, key=lambda s: s["hint_bits"])
    for state in frontier:
        assert receipt(evaluate_schedule(state["schedule"])) == receipt(state)
    # This row is chosen from ALL methods, not the bank/noise-pruned family.
    # It minimizes paired external-product applications, not total runtime.
    work_options = [owner_folded_first_level()] + [level_options(weights, prune=False) for weights in maps[1:]]
    work_row = evaluate_schedule([min(options, key=lambda o:
                                 (o["ext"], o["decompositions"], o["banks"], o["c"]))
                                 for options in work_options])
    brute_cases = optimizer_checks(all_options)
    prepared_options = [prepared_two_level_prefix()] + all_options[2:]
    prepared_frontier, prepared_widths = optimize(prepared_options)
    prepared_winner = min(prepared_frontier, key=lambda s: s["hint_bits"])
    prepared_work = evaluate_schedule([prepared_two_level_prefix()[0]] + [min(options, key=lambda o:
                                      (o["ext"], o["decompositions"], o["banks"], o["c"]))
                                      for options in work_options[2:]])
    for state in prepared_frontier:
        assert receipt(evaluate_schedule(state["schedule"])) == receipt(state)
    broadcast_k = 4
    assert broadcast_prefix_state(f, g, field, broadcast_k) == state_history[broadcast_k - 1]
    broadcast_options = [conventional_broadcast_prefix(broadcast_k)] + all_options[broadcast_k:]
    broadcast_frontier, _ = optimize(broadcast_options)
    broadcast_winner = min(broadcast_frontier, key=lambda s: s["hint_bits"])
    broadcast_work = evaluate_schedule([conventional_broadcast_prefix(broadcast_k)[0]] + [min(options, key=lambda o:
                                      (o["ext"], o["decompositions"], o["banks"], o["c"]))
                                      for options in work_options[broadcast_k:]])
    for state in broadcast_frontier:
        assert receipt(evaluate_schedule(state["schedule"])) == receipt(state)
    collapsed_cases = 0
    for length in (16, 32, 256):
        ff, gg = f[:length], g[:length]
        target = compose(ff, gg, length, field)
        prefixes = range(1, length.bit_length()) if length < 256 else (1, 2, 4)
        for prefix in prefixes:
            assert collapsed_native(ff, gg, field, prefix) == target
            collapsed_cases += 1
    native = []
    for prefix in range(9):
        at1 = native_bounds(256, 8, INITIAL, FRESH, prefix=prefix)[0]
        at2 = native_bounds(256, 16, INITIAL, FRESH, prefix=prefix)[0]
        slope, constant = at2 - at1, 2 * at1 - at2
        bits, digits = admit(slope, constant, 257)
        hint_units = 4 * ((256 >> prefix) - 1) + 48 - 2 * prefix
        native.append({"prefix": prefix, "products": (1 << prefix) - 1 + 8 - prefix,
                       "hint_units_over_g_mJ": hint_units, "modulus_bits": bits, "gadget_digits": digits,
                       "hint_bits": hint_units * 65536 * digits * bits})
    collapsed = []
    for prefix in range(1, 9):
        at1, at2 = (collapsed_native_noise(prefix, gadget)[0] for gadget in (1, 2))
        slope, constant = at2 - at1, 2 * at1 - at2
        bits, gadget = admit(slope, constant, 257)
        noise, stages = collapsed_native_noise(prefix, gadget)
        assert noise == slope * gadget + constant
        assert all((1 << bits) - 1 > 2 + 4 * n for n in stages)
        for smaller in range(1, bits):
            q, gg = (1 << smaller) - 1, (smaller + 7) // 8
            assert q <= 2 + 4 * (slope * gg + constant) or gcd(q, 257) != 1
        tail, products = 8 - prefix, (1 << prefix) - 1 + 8 - prefix
        hints = 4 * (1 << tail) + 6 * tail
        collapsed.append({"prefix": prefix, "products": products, "nonlinear_depth": tail + 1,
                          "f_inputs": 1 << prefix, "g_inputs": products, "independent_keys": 2 * tail + 2,
                          "hint_units_over_g_mJ": hints, "modulus_bits": bits, "gadget_digits": gadget,
                          "hint_bits": hints * 65536 * gadget * bits,
                          "paired_ext_over_g": 2 * (1 << tail) + 3 * tail,
                          "coefficient_decompositions_over_mJ": 2 + 4 * tail})
    print(json.dumps({"status": "PASS_PUBLIC_FUSION_AND_CORRECTNESS_ENVELOPES_ONLY",
                      "fused_map_counts_b_pre_odd_even": profiles, "bsgs_map_fixtures": bsgs_cases,
                      "full_L256_composition_fixtures": 1, "frontier_widths": widths,
                      "owner_folded_first_level_fixtures": 1,
                      "prepared_two_level_fixtures": 1,
                      "prepared_broadcast_k4_fixtures": 1,
                      "collapsed_native_prefix_fixtures": collapsed_cases,
                      "integer_noisy_bsgs_and_tree_phase_fixtures": noisy_transport_checks(rng),
                      "raw_product_sum_phase_fixtures": raw_sum_phase_checks(rng),
                      "finite_options_per_level": list(map(len, all_options)),
                      "exhaustive_three_level_optimizer_fixtures": brute_cases,
                      "full_schedule_modulus_replays": len(frontier) + len(prepared_frontier) + len(broadcast_frontier) + 3,
                      "minimum_hint_bits_in_declared_fused_family": receipt(winner),
                      "minimum_bank_count": receipt(min(frontier, key=lambda s: s["banks"])),
                      "minimum_noise_slope": receipt(min(frontier, key=lambda s: s["slope"])),
                      "minimum_ext_applications_in_unpruned_fused_family": receipt(work_row),
                      "two_f_variant_control": {
                          "products": 28, "f_inputs": 4, "g_inputs": 28, "nonlinear_depth": 7,
                          "frontier_widths": prepared_widths,
                          "minimum_hint_bits": receipt(prepared_winner),
                          "minimum_ext_applications": receipt(prepared_work)},
                      "sixteen_f_variant_broadcast_control": {
                          "products": 46, "f_inputs": 32, "g_inputs": 46, "nonlinear_depth": 5,
                          "minimum_hint_bits": receipt(broadcast_winner),
                          "minimum_ext_applications": receipt(broadcast_work)},
                      "native_prepared_family": native,
                      "native_owner_product_collapsed_family": collapsed,
                      "scope": "Not a global compiler optimum, runtime result, secure modulus choice or benchmark"}, indent=2))


if __name__ == "__main__":
    main()
