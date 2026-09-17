"""Generate manuscript tables from the completed, verified workflow campaign."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent/'manuscript/generated'


def tables(receipt):
    assert receipt['status']=='SAME_ALGEBRA_WORKFLOW_CAMPAIGN_READBACK_PASS'
    assert receipt['campaign_verified'] and not receipt['new_he_execution']
    summary=receipt['summary']
    lines=[r'\begin{table}[ht]',r'\centering\small',r'\setlength{\tabcolsep}{4pt}',
           r'\caption{The new native-algebra campaign: median (minimum--maximum) over three fresh setups per arm. Times are seconds; RSS is MiB. All complete local batch work is charged. These are descriptive samples under the stated source assumptions, not a numerical security match.}',
           r'\label{tab:same-algebra-workflow}',r'\begin{tabular}{lrr}',r'\toprule',
           r'Metric & Terminal JetHE & One-layer control\\',r'\midrule']
    for key,label in [('setup','Setup'),('cold','Cold batch'),('warm','Warm batch'),
                      ('setup_plus_cold','Setup + cold'),('peak_rss_MiB','Peak RSS')]:
        values=[]
        for arm in ('native','control'):
            row=summary[arm][key]
            values.append(f"{row['median']:.3f} ({row['minimum']:.3f}--{row['maximum']:.3f})")
        lines.append(label+' & '+' & '.join(values)+r'\\')
    lines += [r'\bottomrule',r'\end{tabular}',r'\end{table}']
    main='\n'.join(lines)+'\n'
    detail=[r'\begin{table}[ht]',r'\centering\small',r'\setlength{\tabcolsep}{3pt}',
            r'\caption{Every setup in the predeclared native/control/control/native/native/control order. Setup, cold, warm and first-use times are seconds; RSS is MiB. No observation is discarded.}',
            r'\label{tab:same-algebra-samples}',r'\begin{tabular}{rlrrrrr}',r'\toprule',
            r'Index & Arm & Setup & Cold & Warm & First use & RSS\\',r'\midrule']
    counts=dict(native=0,control=0)
    for index,arm in enumerate(('native','control','control','native','native','control')):
        j=counts[arm];counts[arm]+=1
        values=[summary[arm][key]['samples'][j] for key in ('setup','cold','warm','setup_plus_cold','peak_rss_MiB')]
        detail.append(f"{index} & {'JetHE' if arm=='native' else 'Control'} & "+' & '.join(f'{v:.3f}' for v in values)+r'\\')
    detail += [r'\bottomrule',r'\end{tabular}',r'\end{table}']
    return {'same-algebra-workflow.tex':main,'same-algebra-samples.tex':'\n'.join(detail)+'\n'}


def main():
    receipt=json.loads((HERE/'verification.json').read_text())
    for name,body in tables(receipt).items():
        (OUT/name).write_text(body,encoding='utf-8')
    print(json.dumps(dict(status='SAME_ALGEBRA_RECORDED_CAMPAIGN_TABLES_GENERATED',
                         new_he_execution=False,files=list(tables(receipt)))))


if __name__=='__main__':main()
