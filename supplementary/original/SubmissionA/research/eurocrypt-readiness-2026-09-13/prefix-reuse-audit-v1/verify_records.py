"""Validate saved public counts and compute the exact same-source subset."""
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def binding(p):
    data = p.read_bytes()
    return dict(bytes=len(data), sha256=sha256(data).hexdigest())


def main():
    audit = read(HERE / 'audit.json')
    assert audit['status'] == 'PREFIX_REUSE_EXACT_ADMISSION_AND_COUNT_AUDIT_PASS'
    # This manuscript context was read by the recorded audit, not executed.
    # V39 edits its prose; require the exact old bytes in the frozen V38 copy.
    context = 'SubmissionA/research/eurocrypt-readiness-2026-09-13/manuscript/sections/prepared-composition.tex'
    archived = context.replace('/manuscript/', '/checkpoint-v38/manuscript/')
    for rel, want in audit['source_bindings'].items():
        assert binding(ROOT / (archived if rel == context else rel)) == want, rel
    execution = read(HERE / 'execution.json')
    assert execution['returncode'] == 0 and execution['new_he_execution'] is False
    assert binding(HERE / 'check.stdout.txt')['sha256'] == execution['stdout_sha256']
    assert binding(HERE / 'check.stderr.txt')['sha256'] == execution['stderr_sha256']
    assert not (HERE / 'check.stderr.txt').read_bytes()
    profiles = horizons = 0
    common = []
    for family in audit['families']:
        rows = family['profiles']
        base = next(r for r in rows if r['prefix'] == family['balanced_prefix'])
        shared = []
        for r in rows:
            profiles += 1
            g, tau, I, H = r['gadget'], r['tail'], r['inputs'], r['hint_rows']
            x = 1 << r['prefix']
            assert H == g * ((1 << (tau + 1)) + 3 * tau)
            assert I == 2 * x - 1 + tau
            assert r['ring_products_setup'] == H + 2 * tau + 2
            assert r['ring_products_warm'] == 7 * x + 5 * tau + 2 * H - 4
            assert sum(r['vertex_rows']) == H + tau + 1
            assert r['source_rows'] == max(2, *r['vertex_rows'])
            for h in r['horizons']:
                horizons += 1
                B = h['batches']
                assert h['gaussian_polynomials'] == H + 3 * tau + 3 + 3 * B * I
                assert h['uniform_polynomials'] == H + tau + 1
                assert h['query_positions'] == B * I
                assert h['padded_hybrids'] == 1 << (2 * tau + 2 + B * I - 1).bit_length()
                assert h['source_gap_factor'] == 2 * h['padded_hybrids']
                assert h['ring_products_total'] == r['ring_products_setup'] + B * r['ring_products_warm']
                assert h['ring_products_amortized'] == str(Fraction(h['ring_products_total'], B))
            if r['balanced_interval_test']['correctness_and_source_projection']:
                # Use the original interval's gadget, not this row's own interval.
                bg = base['gadget']
                shared_H = bg * ((1 << (tau + 1)) + 3 * tau)
                source = 2 * bg if tau == 0 else max(3 * bg, (1 << tau) * bg + 1)
                assert source == r['balanced_interval_test']['source_rows'] <= base['source_rows']
                shared.append(dict(prefix=r['prefix'], hint_rows=shared_H, inputs=I,
                                   source_rows=source, setup_products=shared_H + 2 * tau + 2,
                                   warm_products=7 * x + 5 * tau + 2 * shared_H - 4))
        own_minima = []
        common_minima = []
        for i, h in enumerate(base['horizons']):
            B = h['batches']
            best = min(r['horizons'][i]['ring_products_total'] for r in rows)
            winners = [r['prefix'] for r in rows if r['horizons'][i]['ring_products_total'] == best]
            saved = family['ring_count_minima'][i]
            assert (saved['batches'], saved['prefixes'], saved['ring_products_total']) == (B, winners, best)
            own_minima.append(winners)
            cbest = min(r['setup_products'] + B * r['warm_products'] for r in shared)
            common_minima.append(dict(batches=B, prefixes=[r['prefix'] for r in shared if r['setup_products'] + B * r['warm_products'] == cbest], total_products=cbest))
        common.append(dict(parameter=family['parameter'], radix_bits=family['radix_bits'],
                           original_prefix=family['balanced_prefix'], original_modulus_bits=base['modulus_bits'],
                           original_source_rows=base['source_rows'], admitted_projectable_profiles=shared,
                           ring_count_minima=common_minima))
    assert (len(common), profiles, horizons) == (18, 192, 1122)
    files = [HERE / n for n in ('PLAN.md', 'PROOF.md', 'check_reuse.py', 'audit.json', 'execution.json',
                               'check.stdout.txt', 'check.stderr.txt', 'verify_records.py', 'RESULTS.md')]
    out = dict(status='PREFIX_REUSE_RECORDED_COUNTS_AND_SAME_SOURCE_READBACK_PASS',
               historical_manuscript_context={context: archived},
               source_files=len(audit['source_bindings']), prefix_profiles=profiles, horizon_profiles=horizons,
               same_source_families=common, new_he_execution=False, new_timing=False,
               mathematical_proof_machine_checked=False, security_bits=None,
               scope='Readback and finite common-interval row-count projection; no runtime or global optimality certificate',
               files={p.relative_to(HERE).as_posix(): binding(p) for p in files})
    (HERE / 'verification.json').write_text(json.dumps(out, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in out.items() if k not in ('files', 'same_source_families')}, indent=2))
    print(json.dumps(dict(all_common_source_minima_are_original_prefix=all(m['prefixes'] == [f['original_prefix']] for f in common for m in f['ring_count_minima']))))


if __name__ == '__main__':
    main()
