"""V2 receipt-only synthesis; all samples and failed gates stay visible."""
from hashlib import sha256
from math import prod
from pathlib import Path
import json
from analyze_matched_screen import stats
from validate_slack_sequence import check, read, EVIDENCE, ROOT, ORDER


def main():
    sequence=check(9);selection=read('conventional-slack-v2-selection.json')
    receipts=[read(f'conventional-slack-v2-sample-{i}-{arm}.json') for i,arm in enumerate(ORDER)]
    summaries={}
    for arm in ('native','column','b16'):
        rows=[r['result'] for r in receipts if r['arm']==arm];assert len(rows)==3
        summary=dict(setup_seconds={k:stats([r['setup_seconds'][k] for r in rows]) for k in rows[0]['setup_seconds']},
            peak_rss_kib=stats([r['peak_rss_kib'] for r in rows]),
            setup_bytes=stats([r['public_key_including_hints_bytes_serialized'] for r in rows]),batches={})
        for index,state in enumerate(('cold','warm')):
            batches=[r['batches'][index] for r in rows]
            assert all(b['output_symbols']==4096 and b['output_sha256']=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3' for b in batches)
            summary['batches'][state]=dict(
                seconds={k:stats([b['seconds'][k] for b in batches]) for k in batches[0]['seconds']},
                wall_seconds=stats([b['batch_wall_seconds'] for b in batches]),
                encrypt_eval_seconds=stats([b['seconds']['encryption']+b['seconds']['evaluation'] for b in batches]),
                input_bytes=stats([b['input_bytes_serialized'] for b in batches]),
                output_bytes=stats([b['output_bytes_serialized'] for b in batches]),
                fresh_encryptions=stats([b['fresh_encryptions'] for b in batches]))
        summary['cold_setup_and_batch_phase_subtotal_seconds']=stats([sum(r['setup_seconds'].values())+r['batches'][0]['batch_wall_seconds'] for r in rows])
        if arm!='native':
            profiles=[r['profile'] for r in rows];assert all(p==profiles[0] for p in profiles)
            summary['profile']=profiles[0];ctxt=profiles[0]['ciphertext_primes']
            assert all(b['output_prime_sets']==[ctxt]*8 for r in rows for b in r['batches'])
            q=prod(map(int,ctxt));summary['recorded_output_modulus']=dict(primes=ctxt,q=str(q),bits=q.bit_length())
            summary['remaining_capacity_bits']=stats([b['minimum_output_bit_capacity'] for r in rows for b in r['batches']])
        summaries[arm]=summary
    native=summaries['native'];comparisons={}
    for arm in ('column','b16'):
        base=summaries[arm]
        nsetup=native['setup_bytes']['median'];bsetup=base['setup_bytes']['median']
        ntransfer=sum(native['batches']['cold'][k]['median'] for k in ('input_bytes','output_bytes'))
        btransfer=sum(base['batches']['cold'][k]['median'] for k in ('input_bytes','output_bytes'))
        ntime=native['cold_setup_and_batch_phase_subtotal_seconds']['median'];btime=base['cold_setup_and_batch_phase_subtotal_seconds']['median']
        difference=nsetup+ntransfer-bsetup-btransfer
        comparisons[arm]=dict(warm_batch_wall_ratio=base['batches']['warm']['wall_seconds']['median']/native['batches']['warm']['wall_seconds']['median'],
            warm_encrypt_eval_ratio=base['batches']['warm']['encrypt_eval_seconds']['median']/native['batches']['warm']['encrypt_eval_seconds']['median'],
            cold_phase_subtotal_ratio=btime/ntime,native_minus_baseline_first_transfer_bytes=difference,
            native_minus_baseline_two_batch_transfer_bytes=nsetup+2*ntransfer-bsetup-2*btransfer,
            cold_serial_transfer_model_threshold_bytes_per_second=difference/(btime-ntime) if difference>0 and btime>ntime else None,
            model_scope='Derived serial additive model: one evaluator setup upload plus input/output; no measured network, overlap, latency or extra owner key distribution')
    v1=read('matched-screen-v1-summary.json')
    paths=sorted(EVIDENCE.glob('conventional-slack-v2-*.json'))
    paths=[p for p in paths if p.name!='conventional-slack-v2-summary.json']
    out=dict(status='CONVENTIONAL_SLACK_V2_SUMMARY_PASS',samples=9,batches=18,verified_symbols=18*4096,
        public_profiles=6,gate_attempts=8,gate_margin_rejections=6,gate_successes=2,
        sequence=sequence,host=receipts[0]['host'],affinity_cpu=receipts[0]['affinity_cpu'],arms=summaries,comparisons=comparisons,
        native_adjacent_anchor_warm_median_ratio_to_v1=native['batches']['warm']['wall_seconds']['median']/v1['arms']['native']['batches']['warm']['wall_seconds']['median'],
        selection=selection,receipt_sha256={p.name:sha256(p.read_bytes()).hexdigest() for p in paths},
        script_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        scope='Same synthetic16-job workload; first passing declared candidate; three independent keys/two batches per arm; no128-bit, parameter-optimal, application, universal-SOTA or significance claim',
        rejection_scope='One-prime gates were rejected for reported capacity5/2/0<10, not observed wrong decryption; the threshold is a declared screening policy, not a cryptographic impossibility')
    print(json.dumps(out,indent=2))


if __name__=='__main__':main()
