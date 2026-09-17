"""Readback of public correspondence and finite ledgers; no HE execution."""
from pathlib import Path
from hashlib import sha256
import json

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]


def binding(p):
    d=p.read_bytes();return dict(bytes=len(d),sha256=sha256(d).hexdigest())


def main():
    a=json.loads((HERE/'public-check.json').read_text(encoding='utf8'))
    ex=json.loads((HERE/'public-execution.json').read_text(encoding='utf8'))
    assert ex['actual_exit_code']==0 and not ex['new_he_execution']
    for name in ('stdout','stderr'):
        assert binding(HERE/f'public.{name}.txt')['sha256']==ex[f'{name}_sha256']
    # The outer WSL launcher warning is preserved, not rewritten as empty stderr.
    warning=(HERE/'public.stderr.txt').read_bytes().decode('utf-16-le').strip()
    assert 'localhost' in warning and 'WSL' in warning and 'NAT' in warning
    for name in ('source_bindings','protected_measured_source_bindings','runtime_bindings'):
        for path,want in a[name].items():assert binding(ROOT/path)==want,path
    assert a['baseline_trace_sha256']==a['candidate_trace_sha256'] and len(a['baseline_trace_sha256'])==22
    assert a['counts']==dict(complete_retained_state_words=8323072,compiled_bank_coordinate_checks=1328,
                              matrix_output_residues=90048,matrix_configurations=576)
    assert not a['new_he_execution'] and not a['performance_benchmark'] and not a['new_arithmetic_binary']
    ledger=json.loads((HERE/'ledger.json').read_text(encoding='utf8'))
    assert len(ledger['stages'])==224 and len(ledger['whole_workflow_configurations'])==70
    for row in ledger['stages']:
        r,a0,g,B,s=row['order'],row['limbs'],row['digits'],row['batches'],row['strassen_levels']
        e=2*r;m=e//(1<<s);v=7**s
        assert row['baseline_products']==a0*g*B*65536*(4*r+1)
        if s==0:
            assert row['matrix_products']==row['matrix_additions']==2*a0*g*65536*e*B
        else:
            blocks=2*g*((B+e-1)//e)*a0*65536//e
            assert row['matrix_products']==blocks*v*m**3
            public=5*(v*m*m-e*e)//3 if row['cached_left_operands'] else 0
            assert row['matrix_additions']==blocks*(v*(m**3-m*m)+6*(v*m*m-e*e)+e*e-public)
    sel=json.loads((HERE/'selection.json').read_text(encoding='utf8'))
    row=next(x for x in ledger['stages'] if (x['order'],x['batches'],x['strassen_levels'],x['cached_left_operands'])==(8,16,1,True))
    assert sel['matrix_products_per_batch']==row['matrix_products']//16==22020096
    assert sel['baseline_and_candidate_runtime_additions_per_batch']==row['matrix_additions']//16==row['baseline_additions']//16
    assert sel['cache_mib']==row['cached_leaf_bytes']//(1<<20)==336
    assert sel['source_gap_factor_at_16_batches']==2*(9+35*16)==1138
    files={p.name:binding(p) for p in HERE.iterdir() if p.is_file() and p.name!='verification.json'}
    result=dict(status='NATIVE_MATRIX_PUBLIC_READBACK_PASS',current_sources=len(a['source_bindings']),
                protected_measured_sources=len(a['protected_measured_source_bindings']),direct_arithmetic_libraries=len(a['runtime_bindings']),
                stage_profiles=224,whole_workflow_profiles=70,public_matrix_cases=576,files=files,
                no_fresh_he=True,practical_speedup_established=False,scientific_readiness='NOT_YET_ESTABLISHED')
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k!='files'},indent=2))


if __name__=='__main__':main()
