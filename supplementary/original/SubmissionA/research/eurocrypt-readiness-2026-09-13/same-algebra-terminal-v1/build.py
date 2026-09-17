"""Build the isolated public interpolation kernel; no encryption execution."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import shutil

HERE=Path(__file__).resolve().parent
(HERE/'build').mkdir(exist_ok=True)
compiler=shutil.which('g++') or '/var/tmp/helib-full-field-Sc2fBv/env/bin/x86_64-conda-linux-gnu-g++'
command=[compiler,'-O3','-std=c++17','-shared','-fPIC',str(HERE/'interpolation.cpp'),'-o',str(HERE/'build/interpolation.so')]
subprocess.run(command,check=True)
receipt=dict(command=command,compiler=subprocess.check_output([compiler,'--version'],text=True).splitlines()[0],
             compiler_sha256=sha256(Path(compiler).read_bytes()).hexdigest(),
             source_sha256=sha256((HERE/'interpolation.cpp').read_bytes()).hexdigest(),
             binary_sha256=sha256((HERE/'build/interpolation.so').read_bytes()).hexdigest())
(HERE/'build/receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
