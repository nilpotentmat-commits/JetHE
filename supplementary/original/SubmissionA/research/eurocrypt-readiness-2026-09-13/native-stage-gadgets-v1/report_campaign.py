"""Generate descriptive tables from the completed stage-gadget campaign."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent/'manuscript/generated'


def tables(receipt):
    assert receipt['status']=='NATIVE_STAGE_GADGET_RECORDED_WORKFLOW_READBACK_PASS'
    assert receipt['measured_setups']==8 and not receipt['new_he_execution']
    summary=receipt['summary']
    lines=[r'\begin{table}[ht]',r'\centering\small',r'\setlength{\tabcolsep}{3pt}',
        r'\caption{Native stage-gadget campaign: median (minimum--maximum) across four fresh setups per arm. Times are seconds; RSS is MiB. Both arms use lazy NTT and the same complete local accounting.}',
        r'\label{tab:stage-gadget-workflow}',r'\begin{tabular}{lrr}',r'\toprule',
        r'Metric & Uniform width 44 & Stage widths\\',r'\midrule']
    for key,label in [('setup','Setup'),('cold','Cold batch'),('warm','Warm batch'),
                      ('first_use','Setup + cold'),('warm_encryption','Warm encryption'),
                      ('warm_evaluation','Warm evaluation'),('peak_rss_MiB','Peak RSS')]:
        cells=[]
        for arm in ('baseline','stage'):
            row=summary[arm][key]
            cells.append(f"{row['median']:.3f} ({row['minimum']:.3f}--{row['maximum']:.3f})")
        lines.append(label+' & '+' & '.join(cells)+r'\\')
    lines += [r'\bottomrule',r'\end{tabular}',r'\end{table}']
    detail=[r'\begin{table}[ht]',r'\centering\small',r'\setlength{\tabcolsep}{3pt}',
        r'\caption{Every stage-gadget setup in its predeclared order. B is the uniform-width lazy baseline; S uses stage widths. Times are seconds; RSS is MiB. No sample is discarded.}',
        r'\label{tab:stage-gadget-samples}',r'\begin{tabular}{rlrrrrr}',r'\toprule',
        r'Index & Arm & Setup & Cold & Warm & First use & RSS\\',r'\midrule']
    counts=dict(baseline=0,stage=0)
    for index,arm in enumerate(('baseline','stage','stage','baseline','baseline','stage','stage','baseline')):
        j=counts[arm];counts[arm]+=1
        values=[summary[arm][key]['samples'][j] for key in ('setup','cold','warm','first_use','peak_rss_MiB')]
        detail.append(f"{index} & {'B' if arm=='baseline' else 'S'} & "+' & '.join(f'{v:.3f}' for v in values)+r'\\')
    detail += [r'\bottomrule',r'\end{tabular}',r'\end{table}']
    return {'stage-gadget-workflow.tex':'\n'.join(lines)+'\n',
            'stage-gadget-samples.tex':'\n'.join(detail)+'\n'}


if __name__=='__main__':
    receipt=json.loads((HERE/'verification.json').read_text())
    for name,body in tables(receipt).items():
        (OUT/name).write_text(body,encoding='utf-8')
    print(json.dumps(dict(status='STAGE_GADGET_RECORDED_TABLES_GENERATED',
                         new_he_execution=False,files=list(tables(receipt)))))
