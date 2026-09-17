"""Portable readback of complete fresh measurements; no new HE or external rehash."""
from datetime import datetime
import json
from math import isclose
from statistics import median
from run import HERE,ROOT,FIXED,ORDER,LIMITS,read,binding,validate

def metrics(rows):
    values=dict(setup=[r['setup_wall_seconds'] for r in rows],cold=[r['batches'][0]['batch_wall_seconds'] for r in rows],warm=[r['batches'][1]['batch_wall_seconds'] for r in rows],first_use=[r['setup_wall_seconds']+r['batches'][0]['batch_wall_seconds'] for r in rows],warm_encryption=[r['batches'][1]['seconds']['encryption'] for r in rows],warm_evaluation=[r['batches'][1]['seconds']['evaluation'] for r in rows],peak_rss_MiB=[r['peak_rss_kib']/1024 for r in rows])
    return {k:dict(samples=v,median=median(v),minimum=min(v),maximum=max(v)) for k,v in values.items()}

def main():
    pre=read(HERE/'preflight.json');gate=read(HERE/'gate-v1/summary.json');campaign=read(HERE/'campaign-v1/summary.json')
    assert pre['status']=='CURRENT_CONTROL_PREFLIGHT_PASS'
    assert gate['status']=='CURRENT_CONTROL_BOTH_FRESH_GATES_PASS'
    assert campaign['status']=='CURRENT_CONTROL_DIRECT_WORKFLOW_PASS'
    assert gate['order']==['native','control'] and campaign['order']==list(ORDER)
    assert pre['source_manifest']==gate['source_manifest']==campaign['source_manifest']
    assert pre['runtime_manifest']==gate['runtime_manifest']==campaign['runtime_manifest']
    for name,want in pre['source_manifest'].items():assert binding(ROOT/name)==want,name
    old=read(FIXED/'verification.json');assert len(old['source_bindings'])==155
    for name,want in old['source_bindings'].items():assert binding(ROOT/name)==want,name
    assert campaign['gate']==binding(HERE/'gate-v1/summary.json')
    measured=[];files=[]
    for dirname,summary,mode in (('gate-v1',gate,'gate'),('campaign-v1',campaign,'measure')):
        d=HERE/dirname
        expected={'frozen.json'}|{f'{i:02d}-{a}{suffix}' for i,a in enumerate(summary['order']) for suffix in ('.json','.stdout.txt','.stderr.txt')}
        assert set(summary['files'])==expected
        for name,want in summary['files'].items():assert binding(d/name)==want,name
        freeze=read(d/'frozen.json')
        assert freeze['order']==summary['order'] and freeze['limits']==LIMITS
        assert freeze['preflight']==binding(HERE/'preflight.json')
        assert freeze['source_manifest']==pre['source_manifest'] and freeze['runtime_manifest']==pre['runtime_manifest']
        for i,arm in enumerate(summary['order']):
            stem=f'{i:02d}-{arm}';record=read(d/(stem+'.json'));r=record['result']
            assert record['status']=='PASS' and record['worker_exit_code']==0
            assert record['error'] is None and record['termination'] is None
            assert record['stdout']==binding(d/(stem+'.stdout.txt'))
            assert record['stderr']==binding(d/(stem+'.stderr.txt')) and record['stderr']['bytes']==0
            raw=[json.loads(line) for line in (d/(stem+'.stdout.txt')).read_text().splitlines()]
            assert [x['result'] for x in raw if x.get('event')=='current_control_result']==[r]
            validate(r,mode,arm,i)
            assert r['source_bindings']==pre['source_manifest'] and r['runtime_bindings']==pre['runtime_manifest']
            assert r['arithmetic_library']==binding(FIXED/'build/fixed_core.so') and r['resource_limits']==LIMITS
            if mode=='measure':measured.append(r)
        files.extend(d.iterdir())
    host=read(HERE/'host-observation-v1.json')
    assert host==read(HERE/'campaign-v1/frozen.json')['host']
    for h in host.values():
        assert h['workers']==[] and h['tool_exit_code']==0
        age=(datetime.fromisoformat(campaign['started_utc'])-datetime.fromisoformat(h['recorded_utc'])).total_seconds()
        assert 0<=age<=300
        assert h['observer']==binding(HERE/'observe.py')
    calculated={a:metrics([r for r in measured if r['arm']==a]) for a in ('native','control')}
    assert calculated==campaign['summary']
    ratios=campaign['control_over_native_median_ratios']
    assert set(ratios)==set(calculated['native'])
    for k,v in ratios.items():assert isclose(v,calculated['control'][k]['median']/calculated['native'][k]['median'],rel_tol=1e-12)
    for phase in ('gate','campaign'):
        receipt=read(HERE/(phase+'-execution.json'));assert receipt['actual_exit_code']==0
        for kind in ('stdout','stderr'):assert receipt[kind]==binding(HERE/(phase+'.'+kind+'.txt'))
    from report_results import render
    assert (HERE/'RESULTS.md').read_text(encoding='utf-8')==render()
    files += [HERE/n for n in ('preflight.json','preflight-execution.json','host-observation-v1.json','observe.py','gate-execution.json','campaign-execution.json','gate.stdout.txt','gate.stderr.txt','campaign.stdout.txt','campaign.stderr.txt','report_results.py','verify_records.py','RESULTS.md','REPRODUCE.md')]
    result=dict(status='CURRENT_CONTROL_DIRECT_WORKFLOW_READBACK_PASS',source_files=len(pre['source_manifest']),recorded_runtime_files=len(pre['runtime_manifest']),source_bindings=pre['source_manifest'],unchanged_native_source_files=155,measured_setups=8,measured_batches=16,fresh_gate_states_by_arm=dict(native=57,control=434),fresh_gate_coefficients=65536*(57+434),summary=calculated,ratios=ratios,files={p.relative_to(ROOT).as_posix():binding(p) for p in files},new_he_execution=False,current_external_runtime_rehashed=False,security_bits=None,scope='Recorded fresh encrypted outputs, complete-cost records and current repository bindings. External Linux runtime bindings are checked for agreement among recorded workers; no current external-library rehash from Windows, cryptographic certification, independent implementation or population confidence claim.')
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('source_bindings','files','summary')}))

if __name__=='__main__':main()
