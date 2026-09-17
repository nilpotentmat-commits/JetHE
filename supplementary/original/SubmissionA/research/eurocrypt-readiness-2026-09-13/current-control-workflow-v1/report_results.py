"""Render complete campaign evidence, including adverse dimensions and all samples."""
import json
from pathlib import Path
from statistics import median
HERE=Path(__file__).resolve().parent

def render():
    s=json.loads((HERE/'campaign-v1/summary.json').read_text())
    assert s['status']=='CURRENT_CONTROL_DIRECT_WORKFLOW_PASS'
    arms=('native','control');v=s['summary'];ratios=s['control_over_native_median_ratios']
    rows=[json.loads((HERE/'campaign-v1'/f'{i:02d}-{a}.json').read_text())['result'] for i,a in enumerate(s['order'])]
    lines=['# Direct current JetHE / one-prime control result','',
        '15 September 2026. Fresh encrypted comparison of the existing 102-row JetHE compiler and the one-prime prepared control, both using the identical current fixed_core.so arithmetic backend. This closes the missing direct current-profile comparison; it does not establish EUROCRYPT readiness.','',
        f"Complete warm medians are {v['native']['warm']['median']:.6f} seconds for JetHE and {v['control']['warm']['median']:.6f} seconds for the control: a {ratios['warm']:.6f} control/JetHE ratio. First-use medians are {v['native']['first_use']['median']:.6f} and {v['control']['first_use']['median']:.6f} seconds, a {ratios['first_use']:.6f} ratio. These ratios are calculated solely from this predeclared campaign.",'',
        '## All complete-cost and phase summaries','',
        '| Metric | JetHE median [min, max] | Control median [min, max] | Control / JetHE median |','|---|---:|---:|---:|']
    names=dict(setup='Setup (s)',cold='First batch (s)',warm='Complete warm batch (s)',first_use='Setup + own first batch (s)',warm_encryption='Warm encryption (s)',warm_evaluation='Warm evaluator (s)',peak_rss_MiB='Peak process RSS (MiB)')
    for k,name in names.items():
        cells=[]
        for a in arms:
            z=v[a][k];cells.append(f"{z['median']:.6f} [{z['minimum']:.6f}, {z['maximum']:.6f}]")
        lines.append(f'| {name} | '+ ' | '.join(cells)+f' | {ratios[k]:.6f} |')
    lines += ['', 'Ratios below one favor the control in that measured dimension. Phase medians are descriptive and do not add to a median complete wall time.','',
        '| Warm phase (s) | JetHE median | Control median |','|---|---:|---:|']
    phases=sorted({k for r in rows for k in r['batches'][1]['seconds']})
    for k in phases:
        cells=[]
        for a in arms:
            samples=[r['batches'][1]['seconds'][k] for r in rows if r['arm']==a and k in r['batches'][1]['seconds']]
            cells.append(f'{median(samples):.6f}' if samples else 'Not used')
        lines.append('| '+k.replace('_',' ')+' | '+' | '.join(cells)+' |')
    lines += ['', '## Material and algorithm tradeoffs','',
        '| Quantity per setup or batch | JetHE | One-prime control |','|---|---:|---:|',
        '| Independent secrets / owner public keys / hint rows | 9 / 5 / 102 | 1 / 1 / 0 |',
        '| Input ciphertexts / ciphertext products / terminal outputs | 35 / 19 / 1 | 346 / 86 / 88 |',
        '| Public / input / output raw polynomial payload (MiB) | 297 / 103 / 3 | 1 / 346 / 131 |']
    for kind in ('public','input','output'):
        cells=[]
        for a in arms:
            selected=[r for r in rows if r['arm']==a]
            vals={r['material']['public_material_serialized_bytes'] for r in selected} if kind=='public' else {b['wire'][kind+'_wire_bytes'] for r in selected for b in r['batches']}
            assert len(vals)==1
            cells.append(str(vals.pop()))
        lines.append('| '+kind.capitalize()+' serialized bytes | '+' | '.join(cells)+' |')
    lines += ['',
        'JetHE reduces complete latency and input/output traffic for this filled sixteen-job fixture. The control retains much smaller setup and public material, lower RSS, and the faster evaluator phase. The gain is an all-party workflow result; fewer products alone do not explain total time. Both preparation/recovery circuits and the underlying arithmetic are existing project implementations. This is not an independently implemented mature-library compiler comparison.','',
        '## Every measured setup in frozen order','',
        '| Index | Arm | Setup (s) | First batch (s) | Warm batch (s) | Setup + first (s) | RSS (MiB) |','|---:|---|---:|---:|---:|---:|---:|']
    for r in rows:
        cold,warm=[b['batch_wall_seconds'] for b in r['batches']];setup=r['setup_wall_seconds']
        lines.append(f"| {r['index']} | {r['arm']} | {setup:.9f} | {cold:.9f} | {warm:.9f} | {setup+cold:.9f} | {r['peak_rss_kib']/1024:.6f} |")
    lines += ['', '## Validation and interpretation','',
        'The public preflight verifies one-prime arithmetic, sampler and explicit-coin encryption agreement with the historical control, plus the current source projection/deletion and unchanged 155-file native source closure. It performs no fresh HE. Both separate fresh encrypted gates then pass: 57 native and 434 control phase states, totaling 32,178,176 coefficient checks. Every gate output is correct. All eight measurement setups and sixteen measured batches pass all 4096 output coefficients (65,536 measured output checks), with fresh setup/encryption coins and no diagnostic phase checks inside the measured runs. Every worker exits zero with empty worker stderr. Launcher stdout/stderr, including the WSL proxy warning where present, are retained separately.','',
        f"The campaign binds {len(s['source_manifest'])} local sources and {len(s['runtime_manifest'])} recorded runtime files before and after each worker. One CPU thread, affinity 0, serial workers, 2 GiB address-space / 900 CPU-second / 960 wall-second caps. Fresh Windows/WSL process observations show no identified competing workspace worker; they are snapshots, not exclusive-host guarantees. No failed sample or restart was discarded.",'',
        'Warm means the complete second batch with setup already available: owner preparation, interpolation/codecs, fresh sampling/encryption, local serialization, evaluation and recipient decryption/recovery. First use includes its own setup and first batch. Context/table/key/hint construction, recipient square and public serialization are charged. Interpreter/import startup, public fixture/oracle generation and physical transport are excluded. Serialization uses a count sink; no network throughput is inferred. Four samples per arm support descriptive medians and ranges, not population confidence or workload-general scaling.','',
        'Both algorithms admit the stated fixed inputs conditionally; native and control ideal correctness bounds are below 2^-129 and 2^-149 respectively for up to 1024 fixed batches. Their common sufficient ordinary source premise is q3/37 with trit secrets and CBD20 primitive errors. At two batches, evaluator-view gap factors are 158 and 1386, with distinct complete simulation time and actual-source deviations. A common source premise is not equal certified 128-bit security. See PROOF.md for the exact direction of projection, per-setup horizon and source budgets. The Gaussian joint-batch theorem is a separate profile and is not measured here.','',
        'The older 134-row versus one-prime campaign and the 102-row native-versus-native optimization campaign remain unchanged. This new pair must replace, rather than be multiplied into, a cross-campaign ratio. This campaign completed against version 41; subsequent manuscript integration is tracked in the root versioned navigation and build receipts. Scientific significance, stronger deeper alternatives, numerical security matching and independent proof/implementation review remain readiness gates.','']
    return '\n'.join(lines)

if __name__=='__main__':
    (HERE/'RESULTS.md').write_text(render(),encoding='utf-8')
    print('CURRENT_CONTROL_RESULTS_RENDERED')
