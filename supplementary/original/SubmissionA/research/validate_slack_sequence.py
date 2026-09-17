"""Read-only selection and cross-worker stopping checks, before each V2 sample."""
from hashlib import sha256
from pathlib import Path
import json
import sys
from supervise_conventional_slack import manifest, ROOT, ORDER

EVIDENCE=ROOT/'evidence'


def digest(path):return sha256(path.read_bytes()).hexdigest()


def read(name):return json.loads((EVIDENCE/name).read_text())


def proposal():
    current=manifest(False);public={};bindings={};eligible=[]
    for m in (4369,13107,21845):
        for bits in (20,60):
            name=f'conventional-slack-v2-public-{m}-{bits}.json';r=read(name)
            assert r['status']=='PASS' and r['sources_unchanged'] and r['source_manifest']==current
            p=r['result']['profile'];assert (p['m'],p['requested_bits'])==(m,bits)
            assert r['result']['keys_generated']==0 and len(p['ciphertext_primes'])>0
            public[m,bits]=p;bindings[name]=digest(EVIDENCE/name)
            if p['library_security_estimate_NOT_CERTIFICATION']>=128:
                logn=p['dimension'].bit_length()-1;assert 1<<logn==p['dimension']
                rank=(len(p['ciphertext_primes'])*logn,(len(p['ciphertext_primes'])+len(p['special_primes']))*logn,p['dimension'],bits)
                eligible.append((rank,m,bits))
    eligible.sort();selected={};attempts={}
    for arm in ('column','b16'):
        attempts[arm]=[]
        for rank,m,bits in eligible:
            name=f'conventional-slack-v2-gate-{arm}-{m}-{bits}.json';r=read(name)
            assert r['source_manifest']==current and r['sources_unchanged']
            assert (r['phase'],r['arm'],r['m'],r['requested_bits'])==('gate',arm,m,bits)
            bindings[name]=digest(EVIDENCE/name)
            attempts[arm].append(dict(m=m,requested_bits=bits,status=r['status'],rank=list(rank),receipt=name))
            if r['status']=='PASS':
                assert r['result']['profile']==public[m,bits]
                b=r['result']['batches'];assert len(b)==1 and b[0]['minimum_output_bit_capacity']>=10
                assert b[0]['output_sha256']=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
                selected[arm]=dict(public[m,bits],passing_gate=name)
                break
            assert r['status']=='FAIL' and r['result'] is None
            assert r['stderr']=='Output capacity below predeclared ten-bit margin\n','Unexpected gate failure requires review'
        assert arm in selected,'No selected candidate; control incomplete'
    expected_gates={x['receipt'] for xs in attempts.values() for x in xs}
    assert {p.name for p in EVIDENCE.glob('conventional-slack-v2-gate-*.json')}==expected_gates,'Unaccounted gate'
    return dict(status='SELECTED_BEFORE_TIMING',protocol='CONVENTIONAL_SLACK_V2.md',
        eligible_ranked=[dict(m=m,requested_bits=b,rank=list(rank)) for rank,m,b in eligible],
        rejected_public_profiles=[dict(m=m,requested_bits=b,library_heuristic=p['library_security_estimate_NOT_CERTIFICATION'])
            for (m,b),p in public.items() if p['library_security_estimate_NOT_CERTIFICATION']<128],
        selected=selected,gate_attempts=attempts,receipt_sha256=bindings,source_manifest=current,
        sequence_validator_sha256=digest(Path(__file__)),sample_order=ORDER,
        security_scope='Native unqualified; HElib library heuristic only, not equal-security certification',
        selection_scope='First passing candidate in declared transform/limb proxy ranking, not parameter optimality')


def check(index):
    assert 0<=index<=9
    selection=read('conventional-slack-v2-selection.json');assert selection==proposal(),'Selection or bound evidence changed'
    current=manifest(True);expected_names={f'conventional-slack-v2-sample-{i}-{ORDER[i]}.json' for i in range(index)}
    actual_names={p.name for p in EVIDENCE.glob('conventional-slack-v2-sample-*.json')}
    assert actual_names==expected_names,'Sample skip, duplicate, incomplete predecessor or forbidden post-failure continuation'
    host=None;cpu=None
    for i in range(index):
        r=read(f'conventional-slack-v2-sample-{i}-{ORDER[i]}.json')
        assert r['status']=='PASS' and r['sources_unchanged'] and r['source_manifest']==current
        assert r['sample_index']==i and r['arm']==ORDER[i]
        if host is None:host,cpu=r['host'],r['affinity_cpu']
        assert (r['host'],r['affinity_cpu'])==(host,cpu),'Host or affinity changed'
    return dict(status='SLACK_SEQUENCE_PASS',next_sample_index=index,prior_passing_samples=index,
        selection_sha256=digest(EVIDENCE/'conventional-slack-v2-selection.json'),bound_source_entries=len(current),
        phase='before_each_timed_worker' if index<9 else 'completed_sequence')


if __name__=='__main__':
    assert len(sys.argv)==2
    print(json.dumps(proposal() if sys.argv[1]=='--propose' else check(int(sys.argv[1])),indent=2))
