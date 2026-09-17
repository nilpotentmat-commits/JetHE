"""Fresh complete native workflows, with separate keys for every setup.

Each setup runs in a new process. These results are local reproductions,
not replacements for the paper's recorded medians or security estimates.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import json
import os
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
THREADS = ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'NUMEXPR_NUM_THREADS')
EXPECTED = 'd22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'


def child(args):
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
    os.sched_setaffinity(0, {args.cpu})
    if sys.byteorder != 'little' or sys.flags.optimize:
        raise RuntimeError('Use little-endian Linux and Python without -O; correctness assertions must be enabled.')
    sys.path.insert(0, str(ROOT / 'src'))
    if args.profile == 'jethe149':
        from workflow149 import run_worker
        result = run_worker('measurement' if args.mode == 'measure' else 'gate', 'paid', args.index, {})
    else:
        from fixed_worker import FixedWorker
        from adapter import CurrentControlWorker
        worker = FixedWorker(args.mode, 'fixed', args.index) if args.profile == 'jethe102' else CurrentControlWorker(args.mode, 'control', args.index)
        try:
            result = worker.run()
        finally:
            if worker.ring:
                worker.ring.close()
    assert result['encrypted_execution'] and result['security_bits'] is None
    assert len(result['batches']) == (2 if args.mode == 'measure' else 1)
    for batch in result['batches']:
        assert batch['output_symbols'] == 4096 and batch['output_sha256'] == EXPECTED
    result.update(release_profile=args.profile, standalone_reproduction=True,
                  published_median=False, cpu=args.cpu,
                  python_version=platform.python_version())
    print(json.dumps({'event': 'standalone_result', 'result': result}), flush=True)


def main():
    if sys.flags.optimize:
        raise SystemExit('Python -O/-OO is unsupported; correctness assertions must be enabled.')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, choices=('jethe102', 'jethe149', 'control'))
    parser.add_argument('--setups', type=int, default=1)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--mode', choices=('measure', 'gate'), default='measure', help='gate adds private phase checks and is not a performance measurement')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--index', type=int, default=0, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux' or not hasattr(os, 'sched_getaffinity'):
        parser.error('This release supports Linux/WSL2 with a little-endian 64-bit process.')
    available = os.sched_getaffinity(0)
    if args.cpu is None:
        args.cpu = min(available)
    if args.cpu not in available:
        parser.error(f'CPU {args.cpu} is outside this process affinity set.')
    for name in THREADS:
        os.environ[name] = '1'
    if args.child:
        child(args)
        return
    if args.setups < 1 or args.setups > 100:
        parser.error('--setups must be between 1 and 100.')
    if args.output is None:
        parser.error('--output is required and must name a new directory.')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for index in range(args.setups):
        command = [sys.executable, '-B', '-u', str(Path(__file__).resolve()), '--child', '--profile', args.profile,
                   '--mode', args.mode, '--index', str(index), '--cpu', str(args.cpu)]
        start = time.perf_counter()
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=960)
        (output / f'{index:03d}.stdout.jsonl').write_text(proc.stdout)
        (output / f'{index:03d}.stderr.txt').write_text(proc.stderr)
        if proc.returncode:
            raise RuntimeError(f'Setup {index} failed (exit {proc.returncode}); see {output / f"{index:03d}.stderr.txt"}')
        values = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        results = [value['result'] for value in values if value.get('event') == 'standalone_result']
        assert len(results) == 1
        record = {'index': index, 'elapsed_seconds': time.perf_counter() - start, 'result': results[0]}
        (output / f'{index:03d}.json').write_text(json.dumps(record, indent=2) + '\n')
        records.append(record)
        print(json.dumps({'setup': index, 'profile': args.profile, 'status': 'PASS'}), flush=True)
    result = {'status': 'PASS', 'profile': args.profile, 'mode': args.mode, 'setups': args.setups,
              'batches_per_setup': 2 if args.mode == 'measure' else 1, 'cpu': args.cpu,
              'platform': platform.platform(), 'python_version': platform.python_version(),
              'source_manifest_sha256': sha256((ROOT / 'provenance.json').read_bytes()).hexdigest(),
              'fresh_he_execution': True, 'published_median': False, 'security_bits': None,
              'records': records}
    (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
