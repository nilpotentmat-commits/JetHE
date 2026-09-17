"""Build the native libraries from this directory; no downloads or prebuilt code."""
from pathlib import Path
from hashlib import sha256
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main():
    if sys.flags.optimize:
        raise SystemExit('Python -O/-OO is unsupported; use the same assertion-enabled interpreter for build and validation.')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx', default=os.environ.get('CXX', 'g++'))
    args = parser.parse_args()
    compiler = shlex.split(args.cxx)
    if not compiler or shutil.which(compiler[0]) is None:
        parser.error('A C++17 compiler is required; install g++ or set CXX.')
    target = ROOT / 'build'
    target.mkdir(exist_ok=True)
    units = {
        'fixed_core.so': 'backend/fixed/fast_core_v1.cpp',
        'terminal_kernel_v1.so': 'backend/terminal_kernel_v1.cpp',
        'interpolation.so': 'backend/interpolation.cpp',
        'paid_hasse_core_v1.so': 'backend/paid149/paid_hasse_core_v1.cpp',
    }
    records = []
    for output, source in units.items():
        command = compiler + ['-std=c++17', '-O3', '-DNDEBUG', '-fPIC', '-shared',
                              str(ROOT / source), '-o', str(target / output)]
        subprocess.run(command, check=True, timeout=180)
        records.append({'source': source, 'output': 'build/' + output,
                        'sha256': sha256((target / output).read_bytes()).hexdigest()})
    result = {'status': 'PASS', 'compiler': subprocess.check_output(compiler + ['--version'], text=True).splitlines()[0],
              'flags': ['-std=c++17', '-O3', '-DNDEBUG', '-fPIC', '-shared'],
              'libraries': records, 'fresh_he_execution': False}
    (target / 'build.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
