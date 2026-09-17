"""Recorded build/public-screen readback. Does not rerun encryption or timings."""
from pathlib import Path
from hashlib import sha256
from statistics import median
import json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
ORDER=('baseline','residue','quotient','quotient','residue','baseline','baseline','residue','quotient')


def binding(p):
    d=p.read_bytes();return dict(bytes=len(d),sha256=sha256(d).hexdigest())


def main():
    build=json.loads((HERE/'build.json').read_text(encoding='utf8'))
    assert build['actual_exit_code']==0 and build['status']=='ISOLATED_CACHED_MATRIX_BUILD_PASS'
    for name,want in build['source_bindings'].items():assert binding(ROOT/name)==want,name
    for name,want in build['artifacts'].items():assert binding(HERE/name)==want,name
    p=json.loads((HERE/'public-check.json').read_text(encoding='utf8'))
    ex=json.loads((HERE/'public-execution.json').read_text(encoding='utf8'))
    assert ex['actual_exit_code']==0 and not ex['new_he_execution']
    for name in ('stdout','stderr'):
        assert binding(HERE/f'public.{name}.txt')['sha256']==ex[f'{name}_sha256']
    warning=(HERE/'public.stderr.txt').read_bytes().decode('utf-16-le').strip()
    assert 'localhost' in warning and 'WSL' in warning and 'NAT' in warning
    for key in ('source_bindings','protected_measured_sources','runtime_bindings','imported_sources'):
        for name,want in p[key].items():assert binding(ROOT/name)==want,(key,name)
    assert tuple(x['arm'] for x in p['samples'])==ORDER
    assert all(x['batches']==16 and x['seconds']>0 for x in p['samples'])
    med={arm:median(x['seconds'] for x in p['samples'] if x['arm']==arm) for arm in set(ORDER)}
    assert med==p['medians']
    eligible=[]
    for arm,mib in (('residue',336),('quotient',672)):
        prep=p['preparation'][arm]
        assert prep['bytes']==mib*(1<<20) and prep['seconds']>0
        ratio=med['baseline']/med[arm];charged=med['baseline']/(med[arm]+prep['seconds'])
        want=dict(evaluator_ratio=ratio,preprocessing_inclusive_ratio=charged,advance=ratio>=1.05 and charged>=1.02)
        assert p['decisions'][arm]==want
        if want['advance']:eligible.append(arm)
    selected=min(eligible,key=lambda a:med[a]+p['preparation'][a]['seconds']) if eligible else None
    assert selected==p['selected_arm'] and p['advance_to_fresh_gate']==bool(eligible)
    c=p['counts']
    assert c['scalar_integer_oracle_words']==3*2*(25000+49) and c['fixture_generator_words']==128
    for arm in ('grouped_baseline','residue','quotient'):assert c[arm+'_trace_words']==16*8323072
    assert c['whole_helper_partial_block_words']==2*2*(1+3+16)*3*65536
    assert c['atomic_rejections']==14 and c['cache_shape_rejections']==4 and c['cache_range_rejections']==2
    assert not p['new_he_execution'] and not p['complete_he_performance_claim'] and p['security_bits'] is None
    assert p['source_gap_factor_for_future_16_batch_HE']==1138
    events=[json.loads(x) for x in (HERE/'progress.jsonl').read_text().splitlines()]
    assert [x['arm'] for x in events if x['event']=='timed_group_complete']==list(ORDER)
    assert events[-1]['event']=='screen_complete' and events[-1]['selected_arm']==selected
    files={q.relative_to(HERE).as_posix():binding(q) for q in HERE.rglob('*') if q.is_file() and q.name!='verification.json'}
    out=dict(status='CACHED_MATRIX_PUBLIC_READBACK_PASS',build_sources=len(build['source_bindings']),
             imported_sources=len(p['imported_sources']),protected_measured_sources=len(p['protected_measured_sources']),
             runtime_libraries=len(p['runtime_bindings']),decisions=p['decisions'],selected_arm=selected,
             no_fresh_he=True,complete_workflow_gain_established=False,files=files)
    (HERE/'verification.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in out.items() if k!='files'},indent=2))


if __name__=='__main__':main()
