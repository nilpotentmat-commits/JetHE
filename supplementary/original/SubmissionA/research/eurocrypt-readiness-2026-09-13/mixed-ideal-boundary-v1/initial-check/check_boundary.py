"""Independent finite-ring evaluations of the written mixed-ideal argument.

All inputs are known public values. No encryption, timing comparison or proof
certificate is produced. Four-corner values are evaluated separately.
"""
from pathlib import Path
from itertools import product
from hashlib import sha256
import json
import random
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


class Ring:
    def __init__(self, q, length, lanes):
        self.q, self.l, self.h = q, length, lanes
        self.zero = (0,) * (length * lanes)
        self.one = tuple(int(i % length == 0) for i in range(length * lanes))

    def fa(self, a, b):
        return a ^ b if self.q == 4 else (a + b) % self.q

    def fm(self, a, b):
        if self.q != 4:
            return a * b % self.q
        c = 0
        while b:
            if b & 1:
                c ^= a
            a <<= 1
            if a & 4:
                a ^= 7  # X^2+X+1
            b >>= 1
        return c

    def add(self, a, b):
        return tuple(self.fa(x, y) for x, y in zip(a, b))

    def neg(self, a):
        return a if self.q in (2, 4) else tuple(-x % self.q for x in a)

    def sub(self, a, b):
        return self.add(a, self.neg(b))

    def mul(self, a, b):
        out = [0] * len(a)
        for lane in range(self.h):
            o = lane * self.l
            for i in range(self.l):
                for j in range(self.l - i):
                    out[o+i+j] = self.fa(out[o+i+j], self.fm(a[o+i], b[o+j]))
        return tuple(out)

    def ideal(self, a, r):
        return all(a[j*self.l+i] == 0 for j in range(self.h) for i in range(min(r, self.l)))

    def draw(self, rng, r=0):
        return tuple(rng.randrange(self.q) if i % self.l >= r else 0 for i in range(len(self.zero)))

    def elements(self, r=0):
        positions = [i for i in range(len(self.zero)) if i % self.l >= r]
        for values in product(range(self.q), repeat=len(positions)):
            out = list(self.zero)
            for i, v in zip(positions, values):
                out[i] = v
            yield tuple(out)

    def compose(self, f, g):
        out = self.zero
        for i in reversed(range(self.l)):
            c = tuple(f[j//self.l*self.l+i] if j % self.l == 0 else 0 for j in range(len(f)))
            out = self.add(self.mul(out, g), c)
        return out

    def automorphism(self, a, permutation, zs, frobenius):
        out = list(self.zero)
        for target, source in enumerate(permutation):
            lane = Ring(self.q, self.l, 1)
            power, val = lane.one, lane.zero
            for i in range(self.l):
                c = a[source*self.l+i]
                if frobenius[target]:
                    c = self.fm(c, c)
                val = lane.add(val, tuple(self.fm(c, x) for x in power))
                power = lane.mul(power, zs[target])
            out[target*self.l:(target+1)*self.l] = val
        return tuple(out)


def mixed(ring, values):
    # Ordering 00,10,01,11; this is direct evaluation, not a symbolic recurrence.
    return ring.add(ring.sub(ring.sub(values[3], values[1]), values[2]), values[0])


def check_quad(ring, quad, a, b):
    assert ring.ideal(ring.sub(quad[1], quad[0]), a)
    assert ring.ideal(ring.sub(quad[3], quad[2]), a)
    assert ring.ideal(ring.sub(quad[2], quad[0]), b)
    assert ring.ideal(ring.sub(quad[3], quad[1]), b)
    assert ring.ideal(mixed(ring, quad), a+b)


def map_quad(fn, *quads):
    return tuple(fn(*args) for args in zip(*quads))


def main():
    started = time.perf_counter()
    rng = random.Random(2026091561)
    exhaustive = []
    for q, l, h, a, b in [(2,2,1,1,1),(3,2,1,1,1),(2,3,1,1,2),
                          (2,3,1,1,1),(2,2,2,1,1),(4,2,1,1,1)]:
        r = Ring(q,l,h)
        quads = []
        for u, dx, dy, dm in product(r.elements(), r.elements(a), r.elements(b), r.elements(a+b)):
            quads.append((u,r.add(u,dx),r.add(u,dy),r.add(r.add(r.add(u,dx),dy),dm)))
        count = 0
        for u, v in product(quads, repeat=2):
            for fn in (r.add, r.mul):
                check_quad(r, map_quad(fn,u,v), a,b)
                count += 1
        exhaustive.append(dict(q=q,length=l,lanes=h,a=a,b=b,quads=len(quads),gate_quads=count))
    circuits = []
    auto_tests = 0
    for q,l,h in product((2,3,4),(2,3,4,8),(1,2)):
        r = Ring(q,l,h)
        gates = 0
        for trial in range(30):
            a,b = (1,l-1) if trial % 2 == 0 else (rng.randrange(1,l),rng.randrange(1,l))
            x,y,dx,dy = r.draw(rng),r.draw(rng),r.draw(rng,a),r.draw(rng,b)
            pool = [(x,r.add(x,dx),x,r.add(x,dx)),(y,y,r.add(y,dy),r.add(y,dy))]
            perm = list(range(h));rng.shuffle(perm)
            zs = [tuple([0,rng.randrange(1,q)]+[rng.randrange(q) for _ in range(l-2)]) for _ in range(h)]
            frob = [q == 4 and bool(rng.randrange(2)) for _ in range(h)]
            auto = lambda z:r.automorphism(z,perm,zs,frob)
            assert auto(r.add(x,y)) == r.add(auto(x),auto(y))
            assert auto(r.mul(x,y)) == r.mul(auto(x),auto(y))
            assert auto(r.one) == r.one
            auto_tests += 3
            for depth in range(24):
                u = pool[-1]
                v = pool[rng.randrange(len(pool))]
                c = (r.draw(rng),)*4
                for quad in (map_quad(r.add,u,c),map_quad(r.mul,u,v),map_quad(r.neg,u),map_quad(auto,u)):
                    check_quad(r,quad,a,b);pool.append(quad);gates += 1
            if a+b >= l:
                # A random prime-field-linear decoder mixes all coordinates,
                # including maps that do not preserve the z-adic filtration.
                outs = [pool[-i] for i in (1,3,6)]
                bits = 2 if q == 4 else 1
                modulus = 2 if q == 4 else q
                weights = [rng.randrange(modulus) for _ in range(3*l*h*bits)]
                def decode(corner):
                    vals = [v[corner] for v in outs]
                    coords = [((x >> k)&1) if q == 4 else x for v in vals for x in v for k in range(bits)]
                    return sum(w*x for w,x in zip(weights,coords)) % modulus
                assert (decode(3)-decode(1)-decode(2)+decode(0)) % modulus == 0
        circuits.append(dict(q=q,length=l,lanes=h,trials=30,depth_steps=24,gate_quads=gates))
    witnesses = []
    for q,l,h in product((2,3,4),(2,3,4,8),(1,2)):
        r=Ring(q,l,h);f=list(r.zero);g=list(r.zero);f[1]=1;g[l-1]=1;f,g=tuple(f),tuple(g)
        values=(r.compose(r.zero,r.zero),r.compose(f,r.zero),r.compose(r.zero,g),r.compose(f,g))
        assert mixed(r,values)==g and g!=r.zero and r.mul(f,g)==r.zero
        coeff1=tuple(f[j//l*l+1] if j%l==0 else 0 for j in range(len(f)))
        assert not r.ideal(coeff1,1) and r.mul(coeff1,g)==g
        if l>=3:
            fg=r.mul(f,f)
            shifted=tuple(fg[j+1] if j%l < l-1 else 0 for j in range(len(fg)))
            assert shifted==f  # why the original witness needs strengthening
        witnesses.append(dict(q=q,length=l,lanes=h,composition=list(g),raw_mixed_zero_required=True,
                              coefficient_preparation_escapes=True,nonlinear_relay_escapes=True))
    horner = []
    for q,l in [(2,2),(2,3),(2,4),(3,2),(3,3),(4,2),(4,3)]:
        r=Ring(q,l,1);count=0
        for f,g in product(r.elements(),r.elements(1)):
            acc=(f[l-1],)+(0,)*(l-1)
            for i in reversed(range(l-1)):
                acc=r.add(r.mul(acc,g),(f[i],)+(0,)*(l-1))
            # Independent power-sum oracle, rather than calling Horner again.
            expected=r.zero;power=r.one
            for i in range(l):
                expected=r.add(expected,tuple(r.fm(f[i],x) for x in power))
                power=r.mul(power,g)
            assert acc==expected
            count+=1
        horner.append(dict(q=q,length=l,input_pairs=count,outer_carriers=l,inner_carriers=1,private_products=l-1))
    bindings={}
    for p in [HERE/'PLAN.md',HERE/'PROOF.md',HERE/'SOURCE_NOTES.md',Path(__file__),
              HERE.parent/'checkpoint-v39/manuscript/appendices/recovery-interface.tex',
              HERE.parent/'checkpoint-v39/manuscript/appendices/conventional-compiler-transfer.tex']:
        raw=p.read_bytes();bindings[p.relative_to(ROOT).as_posix()]=dict(bytes=len(raw),sha256=sha256(raw).hexdigest())
    result=dict(status='MIXED_IDEAL_BOUNDARY_PUBLIC_CHECK_PASS',exhaustive=exhaustive,circuits=circuits,
                witnesses=witnesses,horner=horner,automorphism_law_checks=auto_tests,
                exhaustive_gate_quads=sum(x['gate_quads'] for x in exhaustive),
                sampled_gate_quads=sum(x['gate_quads'] for x in circuits),
                horner_input_pairs=sum(x['input_pairs'] for x in horner),
                elapsed_seconds=time.perf_counter()-started,source_bindings=bindings,
                new_he_execution=False,new_timing_comparison=False,arbitrary_he_impossibility=False,
                arbitrary_preparation_lower_bound=False,independent_proof_review=False,security_bits=None)
    (HERE/'check.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('exhaustive','circuits','witnesses','horner','source_bindings')}))


if __name__ == '__main__':
    main()
