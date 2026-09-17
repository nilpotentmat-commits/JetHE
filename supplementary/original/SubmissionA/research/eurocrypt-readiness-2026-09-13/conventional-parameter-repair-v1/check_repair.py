"""Reprice the existing control at smaller moduli and larger gadgets.

Exact selected correctness and geometric signs; heuristic reduction models.
Does not run or import the live encrypted receiver.
"""
import copy
from fractions import Fraction as F
from hashlib import sha256
import importlib.util
import json
from math import gcd, log, log2, pi
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
READY = HERE.parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(READY/'factored-control-v1'))
import verify_control as independent
analysis = independent.trial.analysis
spec = importlib.util.spec_from_file_location('source_interval_screen', READY/'conventional-source-screen-v1/check_screen.py')
cert = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cert)
model = cert.load_model()
N = 32768
DOMAIN = dict(q_bits=list(range(833, 897)), P_bits=list(range(8, 97, 4)),
              ordinary_digits=[2,4,8,16,32,64], diagonal_digits=[2,4,8,16,32,64])


def dual_margin(modulus, beta, copies):
    # copies=1 for root error e; copies=2 for helper residual s+e.
    log_volume = N*log2(modulus)+log2(65537)+(N/2)*log2(copies)
    length = (2*N-1)*model.logdelta(beta)+log_volume/(2*N)
    radius = log2(modulus)+log2(log(2)/(18*pi*pi))/2
    return radius-length


def exact_dual_margin(modulus, beta, copies):
    ln, add, sub, scale = cert.ln, cert.plus, cert.minus, cert.scale
    lnpi = (ln(cert.PI[0])[0], ln(cert.PI[1])[1])
    lnln2 = (ln(cert.LN2[0])[0], ln(cert.LN2[1])[1])
    radius = add(ln(modulus), scale(sub(sub(lnln2, ln(18)), scale(lnpi, 2)), F(1,2)))
    volume = add(add(scale(ln(modulus), N), ln(65537)), scale(ln(copies), F(N,2)))
    length = add(scale(cert.ln_delta(beta), 2*N-1), scale(volume, F(1,2*N)))
    return sub(radius, length)


def all_margins(qb, pb, beta=317):
    q, M = (1 << qb)-1, ((1 << qb)-1)*((1 << pb)-1)
    return dict(root_recovery=model.margin(N,96,96,q,F(1),beta),
                helper_recovery=model.margin(N,96,192,M,F(2),beta),
                root_dual=dual_margin(q,beta,1), helper_dual=dual_margin(M,beta,2))


def beta_dual(modulus, copies):
    lo, hi = 40, 2*N
    assert dual_margin(modulus, lo, copies) < 0 < dual_margin(modulus, hi, copies)
    while hi-lo > 1:
        mid = (hi+lo)//2
        if dual_margin(modulus, mid, copies) > 0:
            hi = mid
        else:
            lo = mid
    return hi


def dual_prices(beta, modulus, copies):
    d, ambient = 2*N, (1+copies)*(N+2)
    height = modulus.bit_length()+17
    poly = log2(ambient)+2*log2(d)+2*log2(height)
    read, score = log2(2*N*height), log2(d*height*height)
    prices = {}
    for name,c in [('classical',.292),('quantum',.265)]:
        reduction = model.logadd(poly,c*beta+16.4+log2(8*d))
        prices[name] = model.logadd(model.logadd(read,score),reduction)
    return dict(core_classical_log2=.292*beta, core_quantum_log2=.265*beta,
                overhead_inclusive_log2=prices, ambient_dimension=ambient,
                lattice_rank=d, input_height_bits=height,
                dense_basis_bytes_upper=d*ambient*((height+7)//8),
                source_factors=1+copies)


def exact_cases(qb, pb):
    cases = []
    for name, modulus, copies in [('root',2**qb-1,1), ('helper',(2**qb-1)*(2**pb-1),2)]:
        residual, gamma = 96*copies, F(copies)
        beta = model.minimum_beta(N,96,residual,modulus,gamma)
        prev = cert.threshold(N,96,residual,modulus,gamma,beta-1)
        after = cert.threshold(N,96,residual,modulus,gamma,beta)
        at317 = cert.threshold(N,96,residual,modulus,gamma,317)
        assert prev[1] < 0 < after[0] and at317[1] < 0 and beta >= 318
        cases.append(dict(row=name, mechanism='nearest-plane', beta=beta,
                          criterion_at_317=cert.rational_record(at317),
                          predecessor=cert.rational_record(prev), passing=cert.rational_record(after),
                          costs=model.prices(beta,2*N,modulus,gamma)))
        beta = beta_dual(modulus,copies)
        prev, after = exact_dual_margin(modulus,beta-1,copies), exact_dual_margin(modulus,beta,copies)
        at317 = exact_dual_margin(modulus,317,copies)
        assert prev[1] < 0 < after[0] and at317[1] < 0 and beta >= 318
        for block,enclosed in [(beta-1,prev),(beta,after),(317,at317)]:
            assert abs(float(sum(enclosed)/sum(cert.LN2))-dual_margin(modulus,block,copies)) < 1e-8
        cases.append(dict(row=name, mechanism='source-metric-dual', beta=beta,
                          criterion_at_317=cert.rational_record(at317),
                          predecessor=cert.rational_record(prev), passing=cert.rational_record(after),
                          costs=dual_prices(beta,modulus,copies)))
    return cases


def example_moduli(qb,pb):
    q = 2**qb-1
    while gcd(q,2*65537) != 1:
        q -= 2
    P = 2**pb-1
    while gcd(P,q*2*65537) != 1:
        P -= 2
    assert 2**(qb-1) <= q < 2**qb and 2**(pb-1) <= P < 2**pb
    return dict(q=str(q),P=str(P),M=str(q*P),odd_coprime=True,primality_claimed=False)


def enrich(source, point):
    row = copy.deepcopy(source)
    point = dict(point)
    values = [point[k] for k in ('q_bits','P_bits','ordinary_digits','diagonal_digits')]
    point.update(analysis.evaluate(source['record'],source['graph'],source['linear_variance_contract'],
                                  source['source_parameters'],*values,keep=True))
    row['search'] = dict(selected=point)
    return dict(selected=point, exact_correctness=independent.rational_bounds(row),
                complete_costs=independent.costs(row), model_cases=exact_cases(*values[:2]),
                example_moduli=example_moduli(*values[:2]))


def inputs():
    paths = {HERE/x for x in ('PLAN.md','check_repair.py','PROOF.md','RESULTS.md','REPRODUCE.md')}
    paths.add(READY/'factored-control-v1/width16.json')
    paths.update(READY/'control-sampler-v1'/x for x in ('PROOF.md','table-receipt.json','sample_vectors.py'))
    paths.add(cert.OLD/'security/WEIGHTED_DUAL_AND_SOURCE_GEOMETRY_V1.md')
    paths.add(cert.OLD/'evidence/attack-cost-v1/sources/reduction.py.txt')
    for module in list(sys.modules.values()):
        name = getattr(module,'__file__',None)
        if name and Path(name).resolve().is_relative_to(ROOT) and Path(name).suffix == '.py':
            paths.add(Path(name).resolve())
    paths.update((Path(cert.__file__),Path(model.__file__)))
    return {p.relative_to(ROOT).as_posix():cert.bind(p) for p in sorted(paths)}


def main():
    before = inputs()
    source = json.loads((READY/'factored-control-v1/width16.json').read_text())
    assert analysis.terminal_floor(source['record'],source['graph'],source['source_parameters']) == source['recurrence_floor']
    inv = source['record']['inventory']
    tested, admitted, accepted = 0,0,[]
    stream = sha256()
    for qb in DOMAIN['q_bits']:
        for pb in DOMAIN['P_bits']:
            margins = all_margins(qb,pb)
            screened = max(margins.values()) < 0
            for g in DOMAIN['ordinary_digits']:
                for gd in DOMAIN['diagonal_digits']:
                    result = analysis.evaluate(source['record'],source['graph'],source['linear_variance_contract'],
                                               source['source_parameters'],qb,pb,g,gd)
                    row = dict(q_bits=qb,P_bits=pb,ordinary_digits=g,diagonal_digits=gd,
                               admitted=result['admitted'],four_model_filter=screened)
                    tested += 1
                    if result['admitted']:
                        admitted += 1
                        if screened:
                            row.update(analysis.row_counts(inv,qb,pb,g,gd))
                            row['evaluation_products_M'] = 2*row['public_row_evaluations']+2*inv['ciphertext_by_plaintext_products']
                            accepted.append(row)
                    else:
                        row['first_failure'] = result['first_failure']
                    stream.update((json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode())
    assert tested == 52992 and accepted
    suffix = ('q_bits','P_bits','ordinary_digits','diagonal_digits')
    storage_score = lambda r:tuple(r[k] for k in ('raw_public_bytes','evaluation_products_M')+suffix)
    product_score = lambda r:tuple(r[k] for k in ('evaluation_products_M','raw_public_bytes')+suffix)
    storage, products = min(accepted,key=storage_score),min(accepted,key=product_score)
    frontier, best_products = [],float('inf')
    for row in sorted(accepted,key=storage_score):
        if row['evaluation_products_M'] < best_products:
            frontier.append(row)
            best_products = row['evaluation_products_M']
    # Certified ideal-character normalization and finite-source loss.
    assert 18*cert.PI[0]**2 > 256*cert.LN2[1]
    gap = (1-F(6*N,2**256-1))/4-F(3,2**228)
    assert gap > F(1,5)
    output = dict(status='EXISTING_CONTROL_MODEL_FILTER_PARAMETER_SCREEN_PASS',domain=DOMAIN,
                  tested=tested,correctness_admitted=admitted,correctness_and_four_model_filter=len(accepted),
                  decision_stream_sha256=stream.hexdigest(),pareto_frontier=frontier,
                  minimum_public_rows=enrich(source,storage),minimum_evaluation_products=enrich(source,products),
                  dual_three_source_boolean_gap_lower=str(gap),
                  old_profile=source['search']['selected'],
                  filter='Four named geometric criteria fail at beta 317 at upper modulus endpoints; not a hardness lower bound.',
                  security_bits=None,new_he_execution=False,lattice_reduction_executed=False,
                  timing_ranking_established=False,full_live_run_assessed=False,
                  bindings_before=before,bindings_after=inputs())
    assert output['bindings_before'] == output['bindings_after']
    (HERE/'verification.json').write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({k:output[k] for k in ('status','tested','correctness_admitted','correctness_and_four_model_filter')}))
    for name in ('minimum_public_rows','minimum_evaluation_products'):
        value = output[name]
        print(json.dumps(dict(selector=name,point={k:value['selected'][k] for k in suffix},
                              raw_public_bytes=value['complete_costs']['raw_public_bytes'],
                              products_M=value['complete_costs']['evaluation']['total_ring_products_M'],
                              model_blocks=[x['beta'] for x in value['model_cases']]),sort_keys=True))


if __name__ == '__main__':
    main()
