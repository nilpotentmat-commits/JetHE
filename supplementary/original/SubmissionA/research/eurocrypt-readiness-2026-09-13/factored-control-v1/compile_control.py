"""Fixed public CRT-factor composition graphs and conventional HE accounting.

This executes field arithmetic, not encryption. Earlier evidence is read-only.
"""
from array import array
from collections import Counter
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parents[1]
ROOT = RESEARCH.parents[1]
sys.path.insert(0, str(RESEARCH / 'existing-results-revision-2026-09-13'))
import prepared_w0_analysis as analysis
from crt_factors import FIELD, factors, identity, check as check_factors, transform
from composition_fixture import inputs, metadata

S, L, JOBS = 2048, 256, 16


def blocks(j):
    r = 1 << j
    n, m = L // r, L // (2*r)
    result, offset = [], 0
    for kind, length in (('O', m), ('E', m-1)):
        if not length:
            continue
        points = 1 << (2*length-2).bit_length()
        for job in range(JOBS):
            for branch in range(r):
                result.append(dict(kind=kind, job=job, branch=branch,
                                   offset=offset, length=length, points=points))
                offset += points
    return result, (offset+S-1)//S


class Builder:
    def __init__(self, width):
        self.width = width
        self.ops, self.values, self.summary, self.checkpoints = [], {}, {}, []
        self.keys, self.key = {}, 0
        self.owner_work = Counter()
        self.edge_count = 0
        self.powers, _, self.orbit = analysis.compiler.group_data()

    def record(self, op, value):
        assert len(value) == S*op['carriers']
        self.ops.append(op)
        self.values[op['node']] = value
        self.keys[op['node']] = op['key']
        self.checkpoints.append(dict(node=op['node'], sha256=sha256(value.tobytes()).hexdigest()))

    def input(self, name, value):
        value = array('H', value)
        value.extend([0]*((-len(value)) % S))
        self.record(dict(node=name, op='input', args=[], key=0, carriers=len(value)//S), value)

    def linear(self, name, carriers, edges):
        """Edges have distinct (target, source-node, source-coordinate).

        Local factors are already coalesced over GF(65536). Block embeddings,
        coordinate selections, and the two differently sourced return terms
        preserve uniqueness, so no integer-lift cancellation is assumed here.
        """
        result = array('H', [0])*(carriers*S)
        groups = {}
        for target, source, index, scalar in edges:
            assert 0 < scalar < 65536
            assert 0 <= target < len(result) and 0 <= index < len(self.values[source])
            out, t = divmod(target, S)
            inc, s = divmod(index, S)
            group = groups.setdefault((out, source, inc),
                dict(exponents=set(), targets=set(), count=0, digest=sha256()))
            ell = (s-t) % 32768
            exponent = self.powers[t]*self.powers[ell] % 65537
            assert self.orbit[min(exponent, 65537-exponent)] == (s, 0)
            group['exponents'].add((0, ell))
            group['targets'].add(t)
            group['count'] += 1
            group['digest'].update(struct.pack('<HHH', t, s, scalar))
            result[target] ^= FIELD.mul(scalar, self.values[source][index])
            self.edge_count += 1
        recipes = [[] for _ in range(carriers)]
        for (out, source, inc), group in sorted(groups.items()):
            digest = group['digest'].hexdigest()
            map_name = 'map-'+digest
            desc = dict(exponents=sorted(group['exponents']), diagonals=len(group['exponents']),
                        active_targets=len(group['targets']), edges=group['count'], parity=0,
                        edge_stream_sha256=digest)
            if map_name in self.summary:
                assert self.summary[map_name] == desc
            self.summary[map_name] = desc
            recipes[out].append([source, inc, map_name])
        self.key += 1
        self.record(dict(node=name, op='linear', args=sorted({g[1] for g in groups}),
                         key=self.key, carriers=carriers, recipes=recipes), result)
        return name

    def transform_node(self, source, j, direction):
        layout, carriers = blocks(j)
        schedules = {b['points']: factors(b['points'], direction, self.width) for b in layout}
        for stage in range(max(map(len, schedules.values()))):
            def edges():
                for b in layout:
                    p, base = b['points'], b['offset']
                    schedule = schedules[p]
                    matrix = schedule[stage][1] if stage < len(schedule) else identity(p)
                    for target, row in enumerate(matrix):
                        for index, scalar in row:
                            yield base+target, source, base+index, scalar
            source = self.linear(f'{direction}:{j}:{stage}', carriers, edges())
        return source

    def product(self, name, a, b):
        assert len(self.values[a]) == len(self.values[b])
        value = array('H', (FIELD.mul(x, y) for x, y in zip(self.values[a], self.values[b])))
        self.key += 1
        self.record(dict(node=name, op='field_product', args=[a, b], key=self.key,
                         carriers=len(value)//S, source_keys=[self.keys[a], self.keys[b]]), value)
        return name

    def layout_edges(self, j, previous):
        layout, _ = blocks(j)
        r, m = 1 << j, L // (2 << j)
        for b in layout:
            for a in range(b['length']):
                yield b['offset']+a, previous, b['job']*L+(b['branch']+r)*m+a, 1

    def return_edges(self, j, product, previous):
        layout, _ = blocks(j)
        r, n, m = 1 << j, L // (1 << j), L // (2 << j)
        for b in layout:
            offset = 1 if b['kind']=='O' else 2
            for a in range(b['length']):
                yield b['job']*L+b['branch']*n+2*a+offset, product, b['offset']+a, 1
        for job in range(JOBS):
            for branch in range(r):
                for a in range(m):
                    yield job*L+branch*n+2*a, previous, job*L+branch*m+a, 1

    def build(self, fs, gs):
        self.input('f', [x for f in fs for x in f])
        for j in range(7, -1, -1):
            layout, carriers = blocks(j)
            value = array('H', [0])*(carriers*S)
            cache = {}
            for b in layout:
                ck = b['kind'], b['job']
                if ck not in cache:
                    offset = 1 if b['kind']=='O' else 2
                    coefficients = [FIELD.exponents[(FIELD.logs[x]*(1 << j)) % FIELD.order] if x else 0
                                    for x in (gs[b['job']][2*a+offset] for a in range(b['length']))]
                    self.owner_work['coefficient_frobenius_calls'] += len(coefficients)
                    coefficients.extend([0]*(b['points']-len(coefficients)))
                    for _, matrix in factors(b['points'], 'forward', self.width):
                        self.owner_work['transform_field_multiplications_upper'] += sum(map(len, matrix))
                        self.owner_work['transform_field_additions_upper'] += sum(map(len, matrix))
                    cache[ck] = array('H', transform(coefficients, 'forward', self.width))
                value[b['offset']:b['offset']+b['points']] = cache[ck]
                self.owner_work['prepared_field_elements_written'] += b['points']
            self.input(f'inner:{j}', value)
        first = array('H', [0])*S
        for target, _, index, scalar in self.layout_edges(7, 'f'):
            first[target] = self.values['f'][index]
            self.owner_work['first_odd_coefficient_copies'] += 1
        self.input('odd:7', first)
        previous = 'f'
        for j in range(7, -1, -1):
            _, carriers = blocks(j)
            if j==7:
                outer = 'odd:7'
            else:
                outer = self.linear(f'layout:{j}', carriers, self.layout_edges(j, previous))
                outer = self.transform_node(outer, j, 'forward')
            product = self.product(f'field:{j}', outer, f'inner:{j}')
            if j:
                coefficients = self.transform_node(product, j, 'inverse')
                previous = self.linear(f'return:{j}', 2, self.return_edges(j, coefficients, previous))
        G = dict(program=f'prepared-factored-W0-width{self.width}', conductor=65537,
                 operations=self.ops, outputs=[dict(products='field:0', bypass=previous)],
                 job_count=JOBS, length=L, physical_slot_count=S, physical_degree=32768,
                 slot_degree=16, owner_public_keys=1)
        # Terminal transforms and recombination are explicitly public after decryption.
        public = array('H', self.values['field:0'])
        terminal_work = Counter()
        for b in blocks(0)[0]:
            p, base = b['points'], b['offset']
            public[base:base+p] = array('H', transform(public[base:base+p], 'inverse', self.width))
            terminal_work['inverse_transform_field_multiplications_upper'] += sum(
                sum(map(len, matrix)) for _, matrix in factors(p, 'inverse', self.width))
        self.values['public_coefficients'] = public
        result, omitted = array('H', [0])*(JOBS*L), array('H', [0])*(JOBS*L)
        for target, source, index, scalar in self.return_edges(0, 'public_coefficients', previous):
            term = FIELD.mul(scalar, self.values[source][index])
            result[target] ^= term
            if source=='public_coefficients':
                omitted[target] ^= term
            terminal_work['return_field_additions_upper'] += 1
        terminal_work['inverse_transform_field_additions_upper'] = terminal_work['inverse_transform_field_multiplications_upper']
        terminal_work['return_field_multiplications_upper'] = terminal_work['return_field_additions_upper']
        assert omitted != result
        return G, result, dict(owner=dict(self.owner_work), terminal=dict(terminal_work),
                              omitted_terminal_bypass_detected=True)


def independent_expected(fs, gs):
    if os.name=='nt':
        from composition_native import NativeRing, DLL_PATH
        ring, library = NativeRing(256, 4), DLL_PATH
    else:
        from composition_optimized import OptimizedRing, LIBRARY
        ring = OptimizedRing(256, 4)
    try:
        expected = ring.series(*(array('H', [x for f in jobs for x in f]) for jobs in (fs, gs)), 256, horner=True)
    finally:
        ring.close()
    assert sha256(expected.tobytes()).hexdigest() == 'd22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
    return expected, Path(library)


def imported_bindings(extra=()):
    paths = {Path(__file__), *extra}
    for module in list(sys.modules.values()):
        p = getattr(module, '__file__', None)
        if p and Path(p).resolve().is_relative_to(RESEARCH):
            paths.add(Path(p).resolve())
    return {p.relative_to(ROOT).as_posix(): analysis.compiler.bind(p) for p in sorted(paths)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--width', type=int, choices=(1, 2, 4, 8, 16), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--search', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.parent != HERE or output.exists():
        parser.error('Exclusive output within this trial directory is required.')
    fs, gs = inputs()
    expected, library = independent_expected(fs, gs)
    before = imported_bindings([library, HERE/'PLAN.md'])
    print(json.dumps(dict(stage='compile', width=args.width)), flush=True)
    builder = Builder(args.width)
    G, actual, field_work = builder.build(fs, gs)
    assert actual == expected
    print(json.dumps(dict(stage='field_graph_pass', width=args.width,
                         nodes=len(G['operations']), edges=builder.edge_count)), flush=True)
    C, inv = analysis.compiler.compile_graph(G, builder.summary, 32769)
    assert (inv['owner_ciphertexts'], inv['output_ciphertexts'], inv['field_ciphertext_products']) == (31, 6, 28)
    signs = analysis.signed_contract(G, builder.summary, C)
    rec = dict(geometry=analysis.compiler.geometry(False), inventory=inv, symbolic_contract=C, threshold=32769)
    loads, dependencies = analysis.reuse.contract(rec, G, builder.summary)
    par = analysis.reuse.parameters(rec, G)
    floor = analysis.terminal_floor(rec, G, par)
    print(json.dumps(dict(stage='noise_floor', width=args.width, bits=floor['q_bits'],
                         independent_secrets=inv['independent_secrets'],
                         map_families=inv['modes']['diagonal']['payload_families'],
                         mask_products=inv['ciphertext_by_plaintext_products'])), flush=True)
    result = dict(status='FACTORED_CONTROL_FIELD_AND_GRAPH_PASS', fusion_width=args.width,
                  fixture=metadata(), graph=G, map_summary=builder.summary, graph_edge_checks=builder.edge_count,
                  field_elements_checked=len(actual), full_vector_sha256=sha256(actual.tobytes()).hexdigest(),
                  field_work=field_work, checkpoints=builder.checkpoints, source_parameters=par,
                  signs=signs, no_self_dependency_checks=dependencies, linear_variance_contract=loads,
                  record=rec, recurrence_floor=floor,
                  scope='Exact public field circuit and conditional symbolic HE bounds; no encryption or end-to-end timing.')
    if args.search:
        result['search'] = analysis.search(rec, G, loads, par)
        print(json.dumps(dict(stage='grid_pass', width=args.width,
            selected={k:v for k,v in result['search']['selected'].items() if k not in ('bounds','terminal_ciphertext_bounds')})), flush=True)
    after = imported_bindings([library, HERE/'PLAN.md'])
    assert before == after
    result.update(bindings_before=before, bindings_after=after)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, separators=(',', ':'))


if __name__=='__main__':
    main()
