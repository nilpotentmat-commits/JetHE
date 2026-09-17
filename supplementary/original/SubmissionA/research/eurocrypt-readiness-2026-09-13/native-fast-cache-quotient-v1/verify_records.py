"""Read the frozen exact-quotient records; never rerun timings or encryption."""
from pathlib import Path
from hashlib import sha256
from statistics import median
import json
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[3]
ORDER=('original','new','new','original','original','new')


def binding(p):
    data=p.read_bytes(); return dict(bytes=len(data),sha256=sha256(data).hexdigest())


def read(name):
    return json.loads((HERE/name).read_text(encoding='utf8'))


def main():
    build=read('build.json'); result=read('preparation-check.json'); ex=read('preparation-execution.json')
    assert build['actual_exit_code']==0 and build['status']=='FAST_CACHE_QUOTIENT_BUILD_PASS'
    assert ex['actual_exit_code']==0 and not ex['new_he_execution']
    assert result['status']=='FAST_QUOTIENT_PREPARATION_SCREEN_COMPLETE'
    assert result['build_receipt']==binding(HERE/'build.json')
    for name in ('stdout','stderr'):
        assert binding(HERE/f'preparation.{name}.txt')['sha256']==ex[f'{name}_sha256']
    warning=(HERE/'preparation.stderr.txt').read_bytes().decode('utf-16-le').strip()
    assert all(x in warning for x in ('localhost','WSL','NAT'))
    for receipt in (build,result):
        for name,want in receipt['source_bindings'].items(): assert binding(ROOT/name)==want,name
        for name,want in receipt['artifacts'].items(): assert binding(HERE/name)==want,name
    for key in ('runtime_bindings','imported_sources'):
        for name,want in result[key].items(): assert binding(ROOT/name)==want,(key,name)
    assert tuple(x['arm'] for x in result['samples'])==ORDER
    assert all(x['block']==i and x['cache_bytes']==704643072 and x['seconds']>0 for i,x in enumerate(result['samples']))
    med={arm:median(x['seconds'] for x in result['samples'] if x['arm']==arm) for arm in ('original','new')}
    ratio=med['original']/med['new']
    assert med==result['medians'] and ratio==result['original_over_new']
    assert result['threshold']==1.25 and result['advance_to_full_public_gate']==(ratio>=1.25)
    assert result['counts']==dict(compiled_quotient_oracle_words=281257,atomic_shape_rejections=3,
        atomic_alias_rejections=1,atomic_range_rejections=1,identical_cache_words=88080384,
        unchanged_matrix_output_words=3*2*3*65536)
    assert result['cache_bytes']==704643072
    assert not result['new_he_execution'] and not result['complete_he_performance_claim'] and result['security_bits'] is None
    events=[json.loads(x) for x in (HERE/'preparation-progress.jsonl').read_text(encoding='utf8').splitlines()]
    recorded=[{k:v for k,v in x.items() if k!='event'} for x in events if x['event']=='preparation_sample']
    assert recorded==result['samples']
    assert events[-1]['event']=='preparation_screen_complete' and events[-1]['advance']==result['advance_to_full_public_gate']
    assert not (HERE/'public-check.json').exists() and not (HERE/'campaign-v1').exists()
    files={p.relative_to(HERE).as_posix():binding(p) for p in HERE.rglob('*') if p.is_file() and p.name not in ('verification.json','postcheck.json') and '__pycache__' not in p.parts}
    out=dict(status='FAST_QUOTIENT_PREPARATION_READBACK_PASS',build_sources=len(build['source_bindings']),
        artifacts=len(build['artifacts']),imported_sources=len(result['imported_sources']),runtime_libraries=len(result['runtime_bindings']),
        medians=med,ratio=ratio,advance=result['advance_to_full_public_gate'],closed=True,
        fresh_he=False,complete_he_performance_claim=False,files=files)
    (HERE/'verification.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in out.items() if k!='files'},indent=2))


if __name__=='__main__': main()
