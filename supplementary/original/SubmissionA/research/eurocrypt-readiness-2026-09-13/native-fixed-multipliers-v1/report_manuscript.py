"""Generate manuscript tables from the frozen, checked fixed-multiplier campaign."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / 'manuscript/generated'


def tables(receipt):
    assert receipt['status'] == 'NATIVE_FIXED_MULTIPLIER_RECORDED_WORKFLOW_READBACK_PASS'
    assert (receipt['measured_setups'], receipt['measured_batches']) == (8, 16)
    assert not receipt['new_he_execution'] and receipt['security_bits'] is None
    summary = receipt['summary']
    main = [r'\begin{table}[ht]', r'\centering\small', r'\setlength{\tabcolsep}{3pt}',
            r'\caption{Native fixed-multiplier campaign: median (minimum--maximum) over four fresh setups per arm. Both use the 102-row stage construction and identical complete accounting. Times are seconds; RSS is MiB.}',
            r'\label{tab:fixed-multiplier-workflow}', r'\begin{tabular}{lrr}', r'\toprule',
            r'Metric & Extension baseline & Fixed multipliers\\', r'\midrule']
    for key, label in [('setup', 'Setup'), ('cold', 'Cold batch'), ('warm', 'Warm batch'),
                       ('first_use', 'Setup + cold'), ('warm_encryption', 'Warm encryption'),
                       ('warm_evaluation', 'Warm evaluation'), ('peak_rss_MiB', 'Peak RSS')]:
        cells = []
        for arm in ('baseline', 'fixed'):
            row = summary[arm][key]
            cells.append(f"{row['median']:.3f} ({row['minimum']:.3f}--{row['maximum']:.3f})")
        main.append(label + ' & ' + ' & '.join(cells) + r'\\')
    main += [r'\bottomrule', r'\end{tabular}', r'\end{table}']
    samples = [r'\begin{table}[ht]', r'\centering\small', r'\setlength{\tabcolsep}{3pt}',
               r'\caption{Every fixed-multiplier setup in predeclared order. B is the extension-axis implementation; F precomputes fixed multiplier quotients. Times are seconds; RSS is MiB. No sample is discarded.}',
               r'\label{tab:fixed-multiplier-samples}', r'\begin{tabular}{rlrrrrr}', r'\toprule',
               r'Index & Arm & Setup & Cold & Warm & First use & RSS\\', r'\midrule']
    counts = dict(baseline=0, fixed=0)
    for index, arm in enumerate(('baseline', 'fixed', 'fixed', 'baseline',
                                  'baseline', 'fixed', 'fixed', 'baseline')):
        j = counts[arm]
        counts[arm] += 1
        values = [summary[arm][key]['samples'][j]
                  for key in ('setup', 'cold', 'warm', 'first_use', 'peak_rss_MiB')]
        samples.append(f"{index} & {'B' if arm == 'baseline' else 'F'} & " +
                       ' & '.join(f'{v:.3f}' for v in values) + r'\\')
    samples += [r'\bottomrule', r'\end{tabular}', r'\end{table}']
    return {'fixed-multiplier-workflow.tex': '\n'.join(main) + '\n',
            'fixed-multiplier-samples.tex': '\n'.join(samples) + '\n'}


if __name__ == '__main__':
    receipt = json.loads((HERE / 'verification.json').read_text())
    generated = tables(receipt)
    for name, body in generated.items():
        (OUT / name).write_text(body, encoding='utf-8')
    print(json.dumps(dict(status='FIXED_MULTIPLIER_RECORDED_TABLES_GENERATED',
                         files=list(generated), new_he_execution=False)))
