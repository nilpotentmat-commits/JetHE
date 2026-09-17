"""Generate current direct-comparison tables and observed line graph from readback."""
from hashlib import sha256
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent
MAN=HERE.parent/'manuscript'
def digest(p):return sha256(p.read_bytes()).hexdigest()
def generate():
    v=json.loads((HERE/'verification.json').read_text());assert v['status']=='CURRENT_CONTROL_DIRECT_WORKFLOW_READBACK_PASS'
    for name,want in v['files'].items():assert digest(HERE.parents[3]/name)==want['sha256'],name
    s=v['summary']
    text=r'''\begin{table}[ht]
\centering\small
\caption{Current 102-row JetHE and one-prime control using the same current
arithmetic backend. Four fresh setups per arm, two batches each.
Seconds except RSS; medians with observed ranges.}
\label{tab:current-control-workflow}
\begin{tabular}{lrr}
\toprule
Metric & JetHE & One-prime control\\
\midrule
'''
    for k,label in [('setup','Setup'),('warm','Complete warm'),('first_use','Setup + first batch'),('warm_encryption','Warm encryption'),('warm_evaluation','Warm evaluator'),('peak_rss_MiB','Peak RSS (MiB)')]:
        cells=[]
        for a in ('native','control'):
            z=s[a][k];cells.append(f"{z['median']:.3f} [{z['minimum']:.3f}, {z['maximum']:.3f}]")
        text+=label+' & '+' & '.join(cells)+r'\\'+'\n'
    text+=r'\bottomrule\end{tabular}\end{table}'+'\n'
    samples=r'''\begin{table}[ht]
\centering\small
\caption{Every setup in the predeclared current/control order. Complete
batch and setup times in seconds; all outputs pass.}
\label{tab:current-control-samples}
\begin{tabular}{rlrrrr}
\toprule
Index & Arm & Setup & First & Warm & Setup + first\\
\midrule
'''
    campaign=json.loads((HERE/'campaign-v1/summary.json').read_text())
    for i,a in enumerate(campaign['order']):
        r=json.loads((HERE/'campaign-v1'/f'{i:02d}-{a}.json').read_text())['result']
        setup=r['setup_wall_seconds'];cold,warm=[b['batch_wall_seconds'] for b in r['batches']]
        samples+=f"{i} & {'JetHE' if a=='native' else 'Control'} & {setup:.6f} & {cold:.6f} & {warm:.6f} & {setup+cold:.6f}"+r'\\'+'\n'
    samples+=r'\bottomrule\end{tabular}\end{table}'+'\n'
    graph=r'''\begin{tikzpicture}
\begin{axis}[width=11.6cm,height=5.0cm,scale only axis=false,
  xlabel={Fresh setup ordinal within each arm},ylabel={Complete warm batch (s)},
  xmin=0.85,xmax=4.15,ymin=0,ymax=8.5,xtick={1,2,3,4},grid=major,
  major grid style={gray!20},tick label style={font=\small},label style={font=\small},
  legend style={font=\small,at={(0.5,1.04)},anchor=south,legend columns=2,draw=none}]
'''
    for a,color,mark,label in [('native','blue!75!black','*','Current JetHE'),('control','orange!85!black','square*','One-prime control')]:
        coords=' '.join(f'({i},{y:.9f})' for i,y in enumerate(s[a]['warm']['samples'],1))
        graph+=r'\addplot+['+color+',thick,mark='+mark+',mark size=2pt] coordinates {'+coords+'};\n'+r'\addlegendentry{'+label+'}\n'
    graph+=r'\end{axis}\end{tikzpicture}'+'\n'
    plots={'current-control-workflow.tex':text,'current-control-samples.tex':samples,'current-control-lines.tex':graph}
    for name,body in plots.items():(MAN/'generated'/name).write_text(body,encoding='utf-8')
    standalone=r'''\documentclass[border=4pt]{standalone}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\begin{document}
'''+graph+r'\end{document}'+'\n'
    (HERE/'workflow-lines.tex').write_text(standalone,encoding='utf-8')
    result=dict(status='CURRENT_CONTROL_TABLES_AND_OBSERVED_GRAPH_GENERATED',reader_sha256=digest(HERE/'verification.json'),campaign_sha256=digest(HERE/'campaign-v1/summary.json'),generator_sha256=digest(HERE/'report_manuscript.py'),generated={k:digest(MAN/'generated'/k) for k in plots},warm_samples={a:s[a]['warm']['samples'] for a in ('native','control')},new_he_execution=False)
    (HERE/'manuscript-data.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))

if __name__=='__main__':generate()
