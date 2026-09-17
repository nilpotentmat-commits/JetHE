"""Exact operation/storage model; unknown phase costs are retained explicitly."""
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
import json

HERE=Path(__file__).resolve().parent
READY=HERE.parent
N=65536
STAGES=((8,3,4),(4,3,3),(2,2,3),(1,2,2))


def stage(r,a,g,B,s,cache):
    e=2*r;m=e//(1<<s);leaves=7**s
    assert 0<=s<=e.bit_length()-1
    blocks=2*g*((B+e-1)//e)*a*N//e
    multiplies=blocks*leaves*m**3
    recursive=6*(leaves*m*m-e*e)
    public=Fraction(5,3)*(leaves*m*m-e*e)
    assert public.denominator==1
    adds=blocks*(leaves*(m**3-m*m)+recursive+e*e-(int(public) if cache else 0))
    if s==0:
        # Rectangular classical products need no padded batch columns.
        multiplies=adds=2*a*g*N*e*B
    baseline=a*g*B*N*(4*r+1)
    setup_mult=2*a*g*N*(2*r-1)
    setup_add=2*a*g*N*r
    if cache: setup_add+=2*g*a*N//e*int(public)
    virtual_bytes=2*a*g*r*N*8
    matrix_bytes=2*a*g*e*N*8
    leaf_bytes=2*g*a*N//e*leaves*m*m*8 if cache else 0
    saved_m=baseline-multiplies;extra_a=adds-baseline
    threshold=Fraction(extra_a,saved_m) if saved_m>0 else None
    return dict(order=r,limbs=a,digits=g,batches=B,strassen_levels=s,leaf_order=m,
                cached_left_operands=cache,baseline_products=baseline,baseline_additions=baseline,
                matrix_products=multiplies,matrix_additions=adds,
                derived_setup_products=setup_mult,derived_setup_additions=setup_add,
                virtual_only_extra_bytes=virtual_bytes,dense_matrix_bytes=matrix_bytes,
                cached_leaf_bytes=leaf_bytes,
                product_over_add_cost_threshold=str(threshold) if threshold is not None else None,
                strict_lower_product_and_add_counts=(multiplies<baseline and adds<baseline))


def main():
    source=json.loads((READY/'native-prefix-cost-v1/ledger.json').read_text(encoding='utf8'))
    reference=source['current']
    assert reference['resources']['rows']==102
    rows=[stage(r,a,g,B,s,c) for B in (1,2,3,4,8,16,32,64)
          for r,a,g in STAGES for s in range((2*r).bit_length()) for c in (False,True)]
    configurations=[]
    for B in (1,2,4,8,16,32,64):
        for levels in (0,1,2,3,4):
            for cache in (False,True):
                selected=[stage(r,a,g,B,min(levels,(2*r).bit_length()-1),cache) for r,a,g in STAGES]
                baseline=sum(x['baseline_products'] for x in selected)
                ms=sum(x['matrix_products'] for x in selected);ad=sum(x['matrix_additions'] for x in selected)
                config=dict(batches=B,maximum_strassen_levels=levels,cached_left_operands=cache,
                            replaced_baseline_products=baseline,replaced_baseline_additions=baseline,
                            replacement_products=ms,replacement_additions=ad,
                            warm_general_products=B*reference['warm_expanded_products']['general_data_products']-baseline+ms,
                            warm_fixed_products=B*reference['warm_expanded_products']['fixed_products'],
                            additional_setup_products=sum(x['derived_setup_products'] for x in selected),
                            additional_setup_additions=sum(x['derived_setup_additions'] for x in selected),
                            virtual_only_extra_bytes=sum(x['virtual_only_extra_bytes'] for x in selected),
                            dense_matrix_bytes=sum(x['dense_matrix_bytes'] for x in selected),
                            cached_leaf_bytes=sum(x['cached_leaf_bytes'] for x in selected),
                            source_gap_factor=2*(9+35*B),baseline_phase_inventory=reference['phases'])
                if baseline>ms:config['product_over_add_cost_threshold']=str(Fraction(ad-baseline,baseline-ms))
                configurations.append(config)
    baseline_replaced=sum(stage(r,a,g,1,0,False)['baseline_products'] for r,a,g in STAGES)
    assert baseline_replaced==(396+153+54+20)*N
    record=dict(status='FINITE_MATRIX_OPERATION_AND_STORAGE_LEDGER',new_he_execution=False,
                wall_clock_prediction=False,complete_scalar_expansion=False,
                stages=rows,whole_workflow_configurations=configurations,
                untouched_unexpanded_operations=reference['not_scalar_expanded'],
                source_ledger_sha256=sha256((READY/'native-prefix-cost-v1/ledger.json').read_bytes()).hexdigest())
    (HERE/'ledger.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(status=record['status'],stage_profiles=len(rows),whole_workflow_profiles=len(configurations),
                         baseline_replaced_products_per_batch=baseline_replaced,
                         full_cached_extra_mib=max(x['cached_leaf_bytes'] for x in configurations)/(1<<20)),indent=2))


if __name__=='__main__':main()
