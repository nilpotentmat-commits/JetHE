"""Hash-bound source/comparison derivation; not a mathematical proof checker."""
from pathlib import Path
from hashlib import sha256
import json

HERE=Path(__file__).resolve().parent


def binding(p):
    b=p.read_bytes()
    return dict(bytes=len(b),sha256=sha256(b).hexdigest())


def main():
    m=json.loads((HERE/'manifest.json').read_text(encoding='utf-8'))
    for name,want in m['files'].items():
        assert binding(HERE/name)==want,name
    for name,want in m['frozen_context'].items():
        assert name.startswith('checkpoint-v44/')
        assert binding(HERE.parent/name)==want,name
    result=dict(status='RETUNED_RELAY_COMPARISON_CONTEXT_READBACK_PASS',
        context_files=len(m['frozen_context']),same_retuned_modulus_marginal=True,
        polynomial_horizon_charged=True,prefix_computation_charged=True,
        native_input_write_contract_required=True,new_he_execution=False,
        numerical_security_match=False,independent_proof_review=False,
        mathematical_proof_verified_by_program=False,
        files={p.relative_to(HERE).as_posix():binding(p) for p in sorted(HERE.rglob('*'))
               if p.is_file() and '__pycache__' not in p.parts
               and p.name!='verification.json'})
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='files'}))


if __name__=='__main__':main()
