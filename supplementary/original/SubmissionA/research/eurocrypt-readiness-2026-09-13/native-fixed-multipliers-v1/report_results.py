"""Render every predeclared complete-workflow sample from the recorded campaign."""
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def render():
    c=json.loads((HERE/'campaign-v1/summary.json').read_text())
    gate=json.loads((HERE/'gate-v1/summary.json').read_text())
    check=json.loads((HERE/'public-check.json').read_text())
    assert c['status']=='NATIVE_FIXED_MULTIPLIER_CONTROLLED_WORKFLOW_PASS'
    s=c['summary'];ratio=c['baseline_over_fixed_median_ratios']
    b,f=s['baseline'],s['fixed']
    lines=['# Native fixed-multiplier complete-workflow results','','14 September 2026. Fresh comparison against the frozen extension-axis implementation. Both use the same 102-row construction, parameters, independent randomness and complete accounting. Only public fixed-multiplier precomputation changes. This is a standard implementation optimization, not a new construction.','',f"Warm medians: {b['warm']['median']:.6f}/{f['warm']['median']:.6f} seconds (baseline/candidate), ratio {ratio['warm']:.6f}, {100*(1-1/ratio['warm']):.3f}% less time. Setup-plus-cold medians: {b['first_use']['median']:.6f}/{f['first_use']['median']:.6f}, ratio {ratio['first_use']:.6f}, {100*(1-1/ratio['first_use']):.3f}% less time. These descriptive medians are not population confidence bounds.",'','| Metric | Baseline | Fixed multipliers | Baseline/candidate |','| --- | ---: | ---: | ---: |']
    for key,label in [('setup','Setup, seconds'),('cold','Cold, seconds'),('warm','Warm, seconds'),('first_use','Setup + cold, seconds'),('warm_encryption','Warm encryption, seconds'),('warm_evaluation','Warm evaluation, seconds'),('peak_rss_MiB','Peak RSS, MiB')]:
        lines.append(f"| {label} | {b[key]['median']:.6f} | {f[key]['median']:.6f} | {ratio[key]:.6f} |")
    lines+=['','Both arms use 297 MiB public polynomial material, 103/3 MiB input/output, nine independent keys, five public keys and 102 evaluation rows. Each batch uses 35 fresh encryptions, 105 small vectors including 70 errors, and 19 products at depth five. The extra public quotient-array payload is at most 36,816 bytes for all three-limb dyadic lengths; allocator overhead and observed RSS are additional. Precomputation and allocation stay inside setup or the first timed use.','','| Index | Arm | Setup | Cold | Warm | First use | RSS MiB |','| ---: | --- | ---: | ---: | ---: | ---: | ---: |']
    counts={'baseline':0,'fixed':0}
    for i,arm in enumerate(c['order']):
        j=counts[arm];counts[arm]+=1
        values=[s[arm][key]['samples'][j] for key in ['setup','cold','warm','first_use','peak_rss_MiB']]
        lines.append(f'| {i} | {arm} | '+' | '.join(f'{x:.6f}' for x in values)+' |')
    assert counts=={'baseline':4,'fixed':4}
    lines+=['',f"Both fresh gates pass 57 states and 3,735,552 phase coefficients. Eight setups and sixteen measured batches pass all 4096 output checks. There are {len(gate['source_manifest'])} source and {len(gate['runtime_manifest'])} recorded runtime bindings. The separate deterministic public encryption-kernel ratio is {check['kernel_baseline_over_candidate']:.6f}; it is not the complete-workflow ratio.",'','The equivalence proof in PROOF.md establishes canonical modular products with precomputed public quotients. It changes neither noise nor source laws. The existing conditional reductions and heuristic assessment remain qualified. No new numerical-security match, attack method or OpenFHE optimization is supplied.','','WORKFLOW_PLAN.md specifies every charged phase and exclusion. Host observations do not establish exclusive use. Network transport, imports/startup and fixed public oracle generation are excluded equally. Do not add phase medians, discard samples or multiply cross-campaign ratios. Earlier conventional controls and the faster unrestricted relay remain visible in the main dossier. The result does not establish global optimality or close the scientific-significance gate.','','Actual build, screen, gate and campaign exits are recorded in execution.json and stage receipts. verify_records.py reads the recorded evidence; it does not replay encryption or certify scientific readiness.','']
    return '\n'.join(lines)
if __name__=='__main__':
    (HERE/'RESULTS.md').write_text(render(),encoding='utf-8')
    print('Complete campaign report rendered.')
