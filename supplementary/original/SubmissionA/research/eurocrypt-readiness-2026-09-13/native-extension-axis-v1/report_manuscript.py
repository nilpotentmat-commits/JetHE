"""Generate manuscript tables from the frozen, checked extension-axis campaign."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / 'manuscript/generated'


def tables(receipt):
    assert receipt['status'] == 'NATIVE_EXTENSION_AXIS_RECORDED_WORKFLOW_READBACK_PASS'
    assert (receipt['measured_setups'], receipt['measured_batches']) == (8, 16)
    assert not receipt['new_he_execution'] and receipt['security_bits'] is None
    summary = receipt['summary']
    main = [r'\begin{table}[ht]', r'\centering\small', r'\setlength{\tabcolsep}{3pt}',
            r'\caption{Native extension-axis campaign: median (minimum--maximum) over four fresh setups per arm. Both use the 102-row stage construction and identical complete accounting. Times are seconds; RSS is MiB.}',
            r'\label{tab:extension-axis-workflow}', r'\begin{tabular}{lrr}', r'\toprule',
            r'Metric & Tensor baseline & Both axes batched\\', r'\midrule']
    for key, label in [('setup', 'Setup'), ('cold', 'Cold batch'), ('warm', 'Warm batch'),
                       ('first_use', 'Setup + cold'), ('warm_encryption', 'Warm encryption'),
                       ('warm_evaluation', 'Warm evaluation'), ('peak_rss_MiB', 'Peak RSS')]:
        cells = []
        for arm in ('baseline', 'extension'):
            row = summary[arm][key]
            cells.append(f"{row['median']:.3f} ({row['minimum']:.3f}--{row['maximum']:.3f})")
        main.append(label + ' & ' + ' & '.join(cells) + r'\\')
    main += [r'\bottomrule', r'\end{tabular}', r'\end{table}']
    samples = [r'\begin{table}[ht]', r'\centering\small', r'\setlength{\tabcolsep}{3pt}',
               r'\caption{Every extension-axis setup in predeclared order. B is the preceding tensor-axis implementation; E also batches the extension axis. Times are seconds; RSS is MiB. No sample is discarded.}',
               r'\label{tab:extension-axis-samples}', r'\begin{tabular}{rlrrrrr}', r'\toprule',
               r'Index & Arm & Setup & Cold & Warm & First use & RSS\\', r'\midrule']
    counts = dict(baseline=0, extension=0)
    for index, arm in enumerate(('baseline', 'extension', 'extension', 'baseline',
                                  'baseline', 'extension', 'extension', 'baseline')):
        j = counts[arm]
        counts[arm] += 1
        values = [summary[arm][key]['samples'][j]
                  for key in ('setup', 'cold', 'warm', 'first_use', 'peak_rss_MiB')]
        samples.append(f"{index} & {'B' if arm == 'baseline' else 'E'} & " +
                       ' & '.join(f'{v:.3f}' for v in values) + r'\\')
    samples += [r'\bottomrule', r'\end{tabular}', r'\end{table}']
    return {'extension-axis-workflow.tex': '\n'.join(main) + '\n',
            'extension-axis-samples.tex': '\n'.join(samples) + '\n'}


if __name__ == '__main__':
    receipt = json.loads((HERE / 'verification.json').read_text())
    generated = tables(receipt)
    for name, body in generated.items():
        (OUT / name).write_text(body, encoding='utf-8')
    print(json.dumps(dict(status='EXTENSION_AXIS_RECORDED_TABLES_GENERATED',
                         files=list(generated), new_he_execution=False)))
