"""Render the complete campaign without selecting samples or combining campaigns."""
import json
from pathlib import Path
HERE = Path(__file__).resolve().parent


def render():
    campaign = json.loads((HERE / 'campaign-v1/summary.json').read_text())
    assert campaign['status'] == 'NATIVE_EXTENSION_AXIS_CONTROLLED_WORKFLOW_PASS'
    summary = campaign['summary']
    baseline, candidate = summary['baseline'], summary['extension']
    ratio = campaign['baseline_over_extension_median_ratios']
    reduction = 100 * (1 - candidate['warm']['median'] / baseline['warm']['median'])
    first_reduction = 100 * (1 - candidate['first_use']['median'] / baseline['first_use']['median'])
    lines = [
        '# Native extension-axis complete-workflow results', '',
        '14 September 2026. This is a fresh comparison of two implementations of the same '
        '102-row stage-gadget construction. The baseline is native-tensor-axis-v1; the candidate '
        'also batches the extension-axis transforms. No OpenFHE optimization, source-law change '
        'or new construction is involved.', '',
        f"Complete warm medians are {baseline['warm']['median']:.6f}/{candidate['warm']['median']:.6f} "
        f"seconds (baseline/candidate), ratio {ratio['warm']:.6f}, or {reduction:.3f}% less time. "
        f"Setup-plus-cold medians are {baseline['first_use']['median']:.6f}/{candidate['first_use']['median']:.6f} "
        f"seconds, ratio {ratio['first_use']:.6f}, or {first_reduction:.3f}% less time. "
        'These are descriptive medians from this campaign, not population confidence bounds.', '',
        '| Complete local cost | Tensor-axis baseline | Extension-axis candidate | Baseline / candidate |',
        '|---|---:|---:|---:|']
    for key, label in [('setup', 'Setup, seconds'), ('cold', 'Cold batch, seconds'),
                       ('warm', 'Warm batch, seconds'), ('first_use', 'Setup + cold, seconds'),
                       ('warm_encryption', 'Warm encryption, seconds'),
                       ('warm_evaluation', 'Warm evaluation, seconds'),
                       ('peak_rss_MiB', 'Peak RSS, MiB')]:
        lines.append(f"| {label} | {baseline[key]['median']:.6f} | {candidate[key]['median']:.6f} | {ratio[key]:.6f} |")
    lines += ['',
        'Both arms retain 297 MiB of public polynomial material, 103 MiB input material and '
        '3 MiB output material. Each batch has 35 fresh encryptions, 105 small vectors including '
        '70 error vectors, and 19 products at depth five. Setup uses nine independent secrets, '
        'five public keys and 102 hint rows. Serialization framing is retained in each raw record.', '',
        '## Every measured setup', '',
        '| Index | Variant | Setup (s) | Cold (s) | Warm (s) | Setup + cold (s) | Peak RSS (MiB) |',
        '|---:|---|---:|---:|---:|---:|---:|']
    indices = {'baseline': 0, 'extension': 0}
    for index, arm in enumerate(campaign['order']):
        j = indices[arm]
        row = [summary[arm][key]['samples'][j] for key in ('setup', 'cold', 'warm', 'first_use', 'peak_rss_MiB')]
        lines.append(f'| {index} | {arm} | ' + ' | '.join(f'{value:.6f}' for value in row) + ' |')
        indices[arm] += 1
    assert indices == {'baseline': 4, 'extension': 4}
    lines += ['', '## Correctness, attribution and limits', '',
        'Both fresh whole-circuit gates pass 57 states and 3,735,552 phase coefficients. '
        'All eight setups and sixteen measured batches pass complete 4096-symbol output checks. '
        'The executed input manifests contain 140 workspace files and thirteen runtime bindings. '
        'The exact public screen checks all supported relative lengths and primes, independent '
        'sparse evaluations and affected exported operations; its baseline/candidate kernel ratio '
        'is 1.260106. The fresh workflow result is separate from that public fixed-coin screen.', '',
        'The [equivalence argument](PROOF.md) shows the same per-row NTTs, kernel products and '
        'permutations under a different loop order, with unchanged asymptotic work. The extension '
        'pass allocates at most 512 KiB temporary workspace, charged inside the transform. '
        'Actual process RSS is reported above. The gain is an implementation result; it does '
        'not change the ciphertext count, source premise or theoretical compiler contribution.', '',
        'All setup and batch boundaries in [WORKFLOW_PLAN.md](WORKFLOW_PLAN.md) remain charged. '
        'Each setup and batch uses fresh independent coins. Network transport, process imports/startup '
        'and fixed public oracle generation are excluded in both arms. Host observations are snapshots '
        'and do not establish exclusive host use. Phase medians must not be added to reconstruct '
        'the median total.', '',
        'Do not multiply this ratio into earlier native or conventional campaigns. The earlier '
        '134-row same-algebra comparison, eligible unrestricted relay and adverse optimization '
        'results retain their own measurements. This is not a security-matched ranking, a global '
        'runtime optimum or evidence that the EUROCRYPT significance gate is closed.', '',
        'Actual outer exits are recorded in execution.json; raw child exits, stdout, stderr and '
        'phase/batch accounting are retained under gate-v1/ and campaign-v1/. The portable reader '
        'validates recorded consistency; it does not replay secrets or certify scientific readiness.', '']
    return '\n'.join(lines)


if __name__ == '__main__':
    (HERE / 'RESULTS.md').write_text(render(), encoding='utf-8')
    print('complete campaign report rendered')
