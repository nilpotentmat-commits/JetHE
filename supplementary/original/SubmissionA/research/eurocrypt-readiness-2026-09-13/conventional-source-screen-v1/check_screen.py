"""Concrete exposed-row screen; no HE run, lattice reduction or security certificate.

The threshold signs use rational enclosures. Work prices are presentation
approximations checked against a separate Decimal evaluation at two precisions.
Never imports or changes the inputs of the concurrent encrypted receiver.
"""
import ast
from decimal import Decimal, localcontext
from fractions import Fraction as F
from functools import lru_cache
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
READY = HERE.parent
ROOT = HERE.parents[3]
OLD = ROOT/'SubmissionA/research/structured-linear-maps-2026-09-13'


def bind(p):
    raw = p.read_bytes()
    return dict(bytes=len(raw), sha256=sha256(raw).hexdigest())


def load_model():
    p = OLD/'scripts/price_exposed_rows_v1.py'
    spec = importlib.util.spec_from_file_location('previous_exposed_row_model', p)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plus(x, y):
    return x[0]+y[0], x[1]+y[1]


def scale(x, k):
    a, b = x[0]*k, x[1]*k
    return min(a, b), max(a, b)


def minus(x, y):
    return plus(x, scale(y, -1))


def atan_inverse(k, terms=28):
    s = sum((F((-1)**j, (2*j+1)*k**(2*j+1)) for j in range(terms)), F(0))
    next_term = F((-1)**terms, (2*terms+1)*k**(2*terms+1))
    return min(s, s+next_term), max(s, s+next_term)


PI = minus(scale(atan_inverse(5), 16), scale(atan_inverse(239), 4))


@lru_cache(None)
def log_near_one(x):
    """For 1 <= x <= 2, enclose log(x) with 48 positive atanh terms."""
    assert 1 <= x <= 2
    t = (x-1)/(x+1)
    terms = 48
    value = 2*sum((t**(2*j+1)/(2*j+1) for j in range(terms)), F(0))
    tail = 2*t**(2*terms+1)/((2*terms+1)*(1-t*t))
    return value, value+tail


LN2 = log_near_one(F(2))


@lru_cache(None)
def ln(x):
    x = F(x)
    assert x > 0
    k = x.numerator.bit_length()-x.denominator.bit_length()
    y = x/F(2)**k
    if y < 1:
        y *= 2
        k -= 1
    assert 1 <= y < 2
    # A fixed dyadic enclosure prevents huge input moduli from inflating powers.
    unit = 1 << 128
    lower = (y.numerator*unit)//y.denominator
    a = log_near_one(F(lower, unit))[0]
    b = log_near_one(F(lower+1, unit))[1]
    return plus((a, b), scale(LN2, k))


def ln_delta(beta):
    if beta <= 40:
        small = [(2, '1.02190'), (5, '1.01862'), (10, '1.01616'),
                 (15, '1.01485'), (20, '1.01420'), (25, '1.01342'),
                 (28, '1.01331'), (40, '1.01295')]
        return ln(F(next(v for k, v in reversed(small) if k <= beta)))
    numerator = minus(minus(ln(beta), LN2), (F(1), F(1)))
    numerator = plus(numerator, scale((ln(PI[0])[0], ln(PI[1])[1]), F(1, beta)-1))
    numerator = plus(numerator, scale(ln(beta), F(1, beta)))
    return scale(numerator, F(1, 2*(beta-1)))


def threshold(n, a, b, modulus, gamma, beta):
    radius2 = n*(gamma*gamma*a*a+b*b)
    out = scale(ln(gamma*modulus), F(1, 2))
    out = plus(out, scale(ln_delta(beta), 1-2*n))
    return minus(minus(out, LN2), scale(ln(radius2), F(1, 2)))


def rational_record(interval):
    # Outward dyadic rounding keeps the certificate readable and lossless.
    unit = 1 << 96
    lo = (interval[0]*unit).__floor__()
    hi = (interval[1]*unit).__ceil__()
    a, b = F(lo, unit), F(hi, unit)
    assert a <= interval[0] <= interval[1] <= b
    return dict(lower=str(a), upper=str(b), lower_approx=float(a), upper_approx=float(b))


def decimal_prices(beta, dimension, height, precision):
    with localcontext() as ctx:
        ctx.prec = precision
        calls = 8*dimension if beta < dimension else 1
        polynomial = Decimal(dimension**3*height**2)
        answer = {}
        for name, coefficient in [('classical', '0.292'), ('quantum', '0.265')]:
            core = Decimal(coefficient)*beta
            total = polynomial+Decimal(calls)*Decimal(2)**(core+Decimal('16.4'))
            answer[name] = str(total.ln()/Decimal(2).ln())
        return answer


def main():
    model = load_model()
    profile_path = READY/'factored-control-v1/width16.json'
    runner = READY/'compiled-receiver-v1/run_receiver.py'
    profile = json.loads(profile_path.read_text())
    inventory = profile['record']['inventory']
    n, eta = profile['record']['geometry']['N'], profile['record']['geometry']['eta']
    assert (n, eta, inventory['owner_ciphertexts']) == (32768, 96, 31)
    # Check both q/P assignments (plan admission and execution) without importing it.
    tree = ast.parse(runner.read_text())
    assignments = [x for x in ast.walk(tree) if isinstance(x, ast.Assign)
                   and any(isinstance(t, ast.Tuple) and
                           [getattr(v, 'id', '') for v in t.elts] == ['q', 'P'] for t in x.targets)]
    assert len(assignments) == 2
    expected_literal = ast.dump(ast.parse('((1 << 1066)-1, (1 << 533)-3)', mode='eval').body)
    assert all(ast.dump(node.value) == expected_literal for node in assignments)
    q, P = (1 << 1066)-1, (1 << 533)-3
    M = q*P
    witness = inventory['banks'][0]
    assert (witness['source_secret'], witness['helper_secret'], witness['target_secret']) == (0, 1, 4)
    assert witness['mode'] == 'diagonal' and witness['error_divisor'] == 1
    assert [0, 0] in witness['specification']['baby_coordinates']
    assert inventory['main_secret_order']['0'] == 0
    origin = OLD/'evidence/attack-cost-v1/sources/manifest.json'
    manifest = json.loads(origin.read_text())
    assert manifest['commit'] == '53da5982597709ba0fdf94ea37a84d822310fd84'
    for src in manifest['sources']:
        assert bind(OLD/src['file']) == {k: src[k] for k in ('bytes', 'sha256')}
    cases = []
    for label, cap, modulus, receiving_secret in [('owner-root', eta, q, 0),
                                                ('first-baby-digit-zero', 2*eta, M, 1)]:
        gamma = F(cap, eta)
        beta = model.minimum_beta(n, eta, cap, modulus, gamma)
        assert beta > 40
        before = threshold(n, eta, cap, modulus, gamma, beta-1)
        after = threshold(n, eta, cap, modulus, gamma, beta)
        assert before[1] < 0 < after[0]
        for block, enclosed in [(beta-1, before), (beta, after)]:
            independent_log2 = model.margin(n, eta, cap, modulus, gamma, block)
            assert abs(float(sum(enclosed)/sum(LN2))-independent_log2) < 1e-8
        # Exhaustive floating search is cross-checked by exact signs at the boundary.
        assert all(model.margin(n, eta, cap, modulus, gamma, k) <= 0 for k in range(2, beta))
        # For x>=48 the derivative has the sign of
        # 2-log(x/(2*pi))-1/x^2-(2*x-1)*log(pi*x)/x^2, which is negative.
        assert ln(F(48, 2)/PI[1])[0] > 2 and PI[0]*48 > 1
        for k in range(40, 48):
            assert ln_delta(k)[0] > ln_delta(k+1)[1]
        assert threshold(n, eta, cap, modulus, gamma, 40)[1] < 0
        costs = model.prices(beta, 2*n, modulus, gamma)
        lo = decimal_prices(beta, 2*n, costs['input_entry_bits_bound'], 70)
        hi = decimal_prices(beta, 2*n, costs['input_entry_bits_bound'], 100)
        assert all(abs(Decimal(lo[k])-Decimal(hi[k])) < Decimal('1e-60') for k in lo)
        assert abs(float(hi['classical'])-costs['bdgl16_log2_work']) < 1e-9
        assert abs(float(hi['quantum'])-costs['laamospol14_log2_work']) < 1e-9
        cases.append(dict(label=label, N=n, secret_cap=eta, residual_cap=cap,
                          receiving_secret=receiving_secret, modulus=str(modulus),
                          modulus_bits=modulus.bit_length(), gamma=str(gamma), beta=beta,
                          preceding_ln_margin=rational_record(before), ln_margin=rational_record(after),
                          costs=costs, high_precision_log2_model_work=hi))
    # If the helper were recovered, its public baby-0 bank decrypts every root
    # input. This is a deterministic consequence, not a key-recovery algorithm.
    radix = 1 << 800
    assert (radix//2-1)*(radix+1) >= M//2
    kappa = 4*n  # Safe signed period-product bound from symmetric convolution.
    owner_error = 2*kappa*eta**2+eta
    lifted_error = P*owner_error+kappa*radix*eta
    assert 4*lifted_error+2*P < M
    disclosure = dict(baby_exponent=0, digit_count=2, radix=str(radix),
                      coefficient_product_bound=kappa, owner_error_bound=owner_error,
                      lifted_error_bound=str(lifted_error), strict_decode_check=True,
                      root_inputs_accessible=31,
                      condition='Exact helper-secret recovery; not performed or assumed achieved.')
    paths = [Path(__file__), HERE/'PROOF.md', HERE/'RESULTS.md', HERE/'REPRODUCE.md',
             profile_path, runner, READY/'receiver-kernels-v1/check_kernels.py',
             READY/'receiver-kernels-v1/arithmetic.py', READY/'control-sampler-v1/sample_vectors.py',
             READY/'control-sampler-v1/table-receipt.json',
             READY/'compiled-receiver-v1/PROOF.md', Path(model.__file__), origin]
    paths += [OLD/v['file'] for v in manifest['sources']]
    result = dict(status='CONCRETE_EXPOSED_ROW_MODEL_THRESHOLDS_CHECKED',
                  cases=cases, helper_disclosure=disclosure, bank_witness=witness,
                  estimator_commit=manifest['commit'],
                  exact_interval_method='Rational Machin pi and range-reduced positive atanh log with explicit tails.',
                  source_law='Actual capped finite sampler; nearest-plane radius needs no iid coefficient premise.',
                  security_bits=None, attack_executed=False, whole_profile_hardness_established=False,
                  full_receiver_run_assessed=False,
                  scope='Conditional GSA and named reduction-cost witness; not best attack, timing, or security certificate.',
                  bindings={p.relative_to(ROOT).as_posix(): bind(p) for p in paths})
    (HERE/'verification.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(status=result['status'], cases=[dict(label=x['label'], beta=x['beta'],
                    bdgl_log2=x['costs']['bdgl16_log2_work']) for x in cases],
                    helper_disclosure_checked=disclosure['strict_decode_check'], security_bits=None)))


if __name__ == '__main__':
    main()
