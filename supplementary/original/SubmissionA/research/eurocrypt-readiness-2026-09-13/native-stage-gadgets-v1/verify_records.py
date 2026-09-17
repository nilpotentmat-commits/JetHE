"""Portable readback of the actual native gates and completed campaign."""
from hashlib import sha256
import json
from math import isclose
from pathlib import Path
from statistics import median

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]

def read(p):return json.loads(p.read_text())
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())

def main():
    gate=read(HERE/'gate-v1/summary.json');campaign=read(HERE/'campaign-v1/summary.json')
    assert gate['status']=='NATIVE_STAGE_GADGET_BOTH_FRESH_GATES_PASS'
    assert campaign['status']=='NATIVE_STAGE_GADGET_CONTROLLED_WORKFLOW_PASS'
    assert gate['source_manifest']==campaign['source_manifest']
    assert gate['runtime_manifest']==campaign['runtime_manifest']
    for name,want in gate['source_manifest'].items():assert binding(ROOT/name)==want,name
    assert campaign['gate']==binding(HERE/'gate-v1/summary.json')
    assert campaign['order']==['baseline','stage','stage','baseline','baseline','stage','stage','baseline']
    measured=[];files=[]
    for directory,summary,mode in ((HERE/'gate-v1',gate,'gate'),(HERE/'campaign-v1',campaign,'measure')):
        for name,want in summary['files'].items():assert binding(directory/name)==want,name
        for index,variant in enumerate(summary['order']):
            stem=f'{index:02d}-{variant}'
            record=read(directory/(stem+'.json'));r=record['result']
            assert record['status']=='PASS' and record['worker_exit_code']==0
            assert record['termination'] is None and record['error'] is None
            assert record['stdout']==binding(directory/(stem+'.stdout.txt'))
            assert record['stderr']==binding(directory/(stem+'.stderr.txt')) and record['stderr']['bytes']==0
            raw=[json.loads(v) for v in (directory/(stem+'.stdout.txt')).read_text().splitlines()]
            assert [v['result'] for v in raw if v.get('event')=='native_stage_gadget_result']==[r]
            assert (r['mode'],r['variant'],r['index'],r['arm'])==(mode,variant,index,'native')
            assert r['status']=='NATIVE_STAGE_GADGET_WORKFLOW_'+('GATE_PASS' if mode=='gate' else 'MEASUREMENT_PASS')
            assert r['source_bindings']==gate['source_manifest'] and r['runtime_bindings']==gate['runtime_manifest']
            assert r['phase_checked_states']==(57 if mode=='gate' else 0)
            assert r['phase_checked_coefficients']==65536*r['phase_checked_states']
            assert len(r['batches'])==(1 if mode=='gate' else 2)
            assert r['material']['public_material_raw_bytes']==(297 if variant=='stage' else 391)<<20
            assert r['worker_threads']==1 and r['affinity']==[0]
            for i,b in enumerate(r['batches']):
                assert b['index']==i and b['output_symbols']==4096
                assert b['output_sha256']=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
                assert b['counts']==dict(fresh_encryptions=35,small_vectors=105,error_vectors=70,ciphertext_products=19)
                assert b['wire']['input_raw_bytes']==103<<20 and b['wire']['output_raw_bytes']==3<<20
                assert b['batch_wall_seconds']>=sum(b['seconds'].values())>0
            if mode=='measure':measured.append(r)
        files.extend(directory.glob('*.json'));files.extend(directory.glob('*.txt'))
    admission=read(HERE/'admission.json');build=read(HERE/'build.json');check=read(HERE/'public-check.json')
    assert admission['status']=='NATIVE_STAGE_GADGETS_CONDITIONAL_ADMISSION_PASS'
    for name,want in admission['bindings'].items():assert binding(ROOT/name)==want,name
    assert build['status']=='NATIVE_STAGE_GADGETS_BUILD_PASS' and build['returncode']==0
    assert check['status']=='NATIVE_STAGE_GADGET_PUBLIC_BOUNDARIES_PASS'
    assert check['build_receipt']==binding(HERE/'build.json') and check['checker']==binding(HERE/'check_public.py')
    for r in measured:
        candidate=r['variant']=='stage'
        assert r['terminal_limbs']==2
        assert [r['material'][k] for k in ('independent_secrets','public_keys','evaluation_rows','setup_error_vectors','setup_small_vectors')]==[9,5,102 if candidate else 134,107 if candidate else 139,116 if candidate else 148]
    host=read(HERE/'campaign-v1/host-observation.json')
    assert set(host)=={'windows','wsl'}
    assert all(r['workers']==[] and r['tool_exit_code']==0 for r in host.values())
    for variant in ('baseline','stage'):
        rows=[r for r in measured if r['variant']==variant]
        values=dict(setup=[r['setup_wall_seconds'] for r in rows],cold=[r['batches'][0]['batch_wall_seconds'] for r in rows],
            warm=[r['batches'][1]['batch_wall_seconds'] for r in rows],
            first_use=[r['setup_wall_seconds']+r['batches'][0]['batch_wall_seconds'] for r in rows],
            warm_encryption=[r['batches'][1]['seconds']['encryption'] for r in rows],
            warm_evaluation=[r['batches'][1]['seconds']['evaluation'] for r in rows],
            peak_rss_MiB=[r['peak_rss_kib']/1024 for r in rows])
        assert campaign['summary'][variant]=={k:dict(samples=v,median=median(v),minimum=min(v),maximum=max(v)) for k,v in values.items()}
    for key,ratio in campaign['baseline_over_stage_median_ratios'].items():
        assert isclose(ratio,campaign['summary']['baseline'][key]['median']/campaign['summary']['stage'][key]['median'],rel_tol=1e-12)
    files += [HERE/n for n in ('verify_records.py','RESULTS.md','REPRODUCE.md','report_campaign.py')]
    result=dict(status='NATIVE_STAGE_GADGET_RECORDED_WORKFLOW_READBACK_PASS',source_files=len(gate['source_manifest']),
        recorded_runtime_files=len(gate['runtime_manifest']),fresh_gate_states_by_arm=dict(baseline=57,stage=57),
        measured_setups=8,measured_batches=16,summary=campaign['summary'],ratios=campaign['baseline_over_stage_median_ratios'],
        source_bindings=gate['source_manifest'],files={p.relative_to(ROOT).as_posix():binding(p) for p in files},
        new_he_execution=False,current_external_runtime_rehashed=False,security_bits=None,
        scope='Recorded fresh gate and campaign consistency, complete output checks and current source bindings; no secret replay, population speedup, source-hardness or cross-campaign ratio.')
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('summary','source_bindings','files')}))

if __name__=='__main__':main()
