"""Receipt-only V1 synthesis. No HE, fitting, discarded samples or speed claims."""
from hashlib import sha256
from math import prod
from pathlib import Path
from statistics import median
import json

ROOT=Path(__file__).resolve().parent.parent
ORDER=['native','column','b16','column','b16','native','b16','native','column']


def stats(values):
    return dict(median=median(values),minimum=min(values),maximum=max(values),samples=values)


def main():
    receipts=[];files=[]
    for i,arm in enumerate(ORDER):
        p=ROOT/'evidence'/f'matched-screen-v1-{i}-{arm}.json'
        r=json.loads(p.read_text());files.append(p);receipts.append(r)
        assert r['status']=='PASS' and r['error'] is None and r['worker_exit_code']==0
        assert (r['sample_index'],r['arm'])==(i,arm) and r['sources_unchanged']
        assert r['affinity_cpu']==receipts[0]['affinity_cpu'] and r['host']==receipts[0]['host']
        assert r['source_manifest']==receipts[0]['source_manifest']
        for b in r['result']['batches']:
            assert b['output_symbols']==4096 and b['output_sha256']=='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
    summaries={}
    for arm in ('native','column','b16'):
        rows=[r['result'] for r in receipts if r['arm']==arm];assert len(rows)==3
        summary=dict(setup_seconds={k:stats([r['setup_seconds'][k] for r in rows]) for k in rows[0]['setup_seconds']},
            peak_rss_kib=stats([r['peak_rss_kib'] for r in rows]),
            setup_bytes=stats([r['public_key_including_hints_bytes_serialized'] for r in rows]),batches={})
        for index,state in enumerate(('cold','warm')):
            batch=[r['batches'][index] for r in rows]
            summary['batches'][state]=dict(
                seconds={k:stats([b['seconds'][k] for b in batch]) for k in batch[0]['seconds']},
                wall_seconds=stats([b['batch_wall_seconds'] for b in batch]),
                encrypt_eval_seconds=stats([b['seconds']['encryption']+b['seconds']['evaluation'] for b in batch]),
                input_bytes=stats([b['input_bytes_serialized'] for b in batch]),
                output_bytes=stats([b['output_bytes_serialized'] for b in batch]))
        summary['cold_setup_and_batch_phase_subtotal_seconds']=stats([
            sum(r['setup_seconds'].values())+r['batches'][0]['batch_wall_seconds'] for r in rows])
        if arm!='native':
            profiles=[r['profile'] for r in rows];assert all(p==profiles[0] for p in profiles)
            ctxt=[int(x) for x in profiles[0]['ciphertext_primes']]
            # The executed normalization guarantees a subset. Equal cardinality
            # makes that subset unique; this is derived, not missing-data guessing.
            assert all(all(n==len(ctxt) for n in b['output_prime_counts']) for r in rows for b in r['batches'])
            summary['derived_output_modulus']=dict(primes=[str(p) for p in ctxt],q=str(prod(ctxt)),bits=prod(ctxt).bit_length(),
                reasoning='Each recorded output is a subset of ctxt primes and has equal cardinality; therefore its set is the complete recorded ctxt-prime set')
        summaries[arm]=summary
    native=summaries['native'];comparisons={}
    for arm in ('column','b16'):
        base=summaries[arm]
        nbytes=native['setup_bytes']['median']+sum(native['batches']['cold'][k]['median'] for k in ('input_bytes','output_bytes'))
        bbytes=base['setup_bytes']['median']+sum(base['batches']['cold'][k]['median'] for k in ('input_bytes','output_bytes'))
        ntime=native['cold_setup_and_batch_phase_subtotal_seconds']['median']
        btime=base['cold_setup_and_batch_phase_subtotal_seconds']['median']
        comparisons[arm]=dict(
            warm_batch_wall_ratio=base['batches']['warm']['wall_seconds']['median']/native['batches']['warm']['wall_seconds']['median'],
            warm_encrypt_eval_ratio=base['batches']['warm']['encrypt_eval_seconds']['median']/native['batches']['warm']['encrypt_eval_seconds']['median'],
            cold_phase_subtotal_ratio=btime/ntime,
            native_minus_baseline_first_transfer_bytes=nbytes-bbytes,
            cold_serial_transfer_model_threshold_bytes_per_second=(nbytes-bbytes)/(btime-ntime) if nbytes>bbytes and btime>ntime else None,
            model_scope='Derived additive model only: one evaluator setup upload, one input upload and one output download; no actual network, overlap, additional owner key distribution or latency model')
    out=dict(status='MATCHED_SCREEN_V1_SUMMARY_PASS',samples=9,batches=18,verified_symbols=18*4096,
        host=receipts[0]['host'],affinity_cpu=receipts[0]['affinity_cpu'],arms=summaries,comparisons=comparisons,
        sources={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in files},
        script_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        scope='Three cold/warm process samples per arm at fixed provisional profiles; no128-bit, optimality, universal SOTA, application speedup or statistical-significance claim')
    print(json.dumps(out,indent=2))


if __name__=='__main__':main()
