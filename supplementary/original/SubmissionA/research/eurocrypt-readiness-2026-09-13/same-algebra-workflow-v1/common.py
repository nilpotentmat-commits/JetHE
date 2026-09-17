"""Common native-algebra workflow bindings and immutable-input manifest."""
from array import array
import ast
import importlib.util
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys

HERE=Path(__file__).resolve().parent
READY=HERE.parent
RESEARCH=HERE.parents[1]
ROOT=HERE.parents[3]
FAST=RESEARCH/'jethe-throughput-redesign-2026-09-13'
OLD=RESEARCH/'existing-results-revision-2026-09-13'
LIGHT=RESEARCH/'lightweight-jethe-2026-09-13'
SAME=READY/'same-algebra-terminal-v1'
PAIRED=READY/'paired-terminal-receiver-v1'
sys.path[:0]=[str(HERE),str(SAME),str(FAST),str(OLD),str(LIGHT),str(RESEARCH),str(PAIRED)]

import slim_public_v2 as native
from slim_crypto_v2 import SlimRing
from slim_ring_base_v2 import SlimRingBase
from fast_crypto_v1 import encrypt
from composition_full_run import Secret,Cipher,Bundle,Coins,keygen,encode_lanes,codec_setup,decode
from measure_composition_native import owner_inputs,FastField,fixture_inputs
from paid_hasse_experiment_v1 import expected_states,check_phase
from analysis.slim_bounds_v2 import FRESH as NATIVE_FRESH
sys.path.insert(0,str(SAME))
import admission as control_admission
assert Path(control_admission.__file__).resolve()==SAME/'admission.py'
from admission import Q,F,BRAW,N,bindings as control_admission_bindings
from interpolation import Interpolation
from prepare import outer_prepare,inner_prepare,records,record_digest
from composition_wire import send

# Several preserved experiments have a module named run_receiver. Resolve this
# actual dependency explicitly; imported codecs may prepend their own paths.
_spec=importlib.util.spec_from_file_location('native_algebra_control_receiver',SAME/'run_receiver.py')
_control=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_control)
public_product=_control.public_product

ORDER=('native','control','control','native','native','control')
THREAD_VARIABLES=('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS')
EXPECTED_SHA='d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3'
LIMITS=dict(address_space_bytes=2<<30,cpu_seconds=900,wall_seconds=960,core_bytes=0,cpu=0)


class SharedField(FastField):
    def __init__(self):
        super().__init__()
        # Public adapter only; inherited multiplication has no diagnostic counter.
        self.log,self.exp=self.logs,self.exponents


def binding(path):
    return dict(bytes=path.stat().st_size,sha256=sha256(path.read_bytes()).hexdigest())


def source_manifest():
    dirs=(HERE,SAME,FAST,OLD,LIGHT,RESEARCH,PAIRED)
    paths={HERE/name for name in ('PLAN.md','common.py','worker.py','supervise.py')}
    paths.update(ROOT/name for name in control_admission_bindings())
    paths.update((READY/'exact-admission.json',READY/'source-scope.json',SAME/'admission.json',
                  SAME/'run_receiver.py',READY/'compiled-receiver-v1/expected.bin',FAST/'PROOF_V2.md'))
    paths.update((FAST/'backend-v2').glob('*.cpp'))
    paths.update((RESEARCH/'composition_native_core.cpp',RESEARCH/'composition_optimized_core.cpp',
                  OLD/'paid_hasse_core_v1.cpp',LIGHT/'terminal_kernel_v1.cpp',
                  LIGHT/'build/terminal_kernel_v1.so'))
    pending=list(paths)
    found={}
    while pending:
        path=pending.pop().resolve()
        if path in found:continue
        found[path]=binding(path)
        if path.suffix=='.py':
            for node in ast.walk(ast.parse(path.read_bytes())):
                names=[node.module or ''] if isinstance(node,ast.ImportFrom) else [n.name for n in node.names] if isinstance(node,ast.Import) else []
                for name in names:
                    for directory in dirs:
                        candidate=directory/Path(*name.split('.')).with_suffix('.py')
                        if candidate.is_file():
                            pending.append(candidate)
                            break
    return {p.relative_to(ROOT).as_posix():v for p,v in sorted(found.items())}


def runtime_manifest():
    libraries=(FAST/'build/fast_core_v2.so',LIGHT/'build/terminal_kernel_v1.so',SAME/'build/interpolation.so')
    paths=set(libraries)
    for library in libraries:
        value=subprocess.check_output(['ldd',str(library)],text=True)
        assert 'not found' not in value
        for match in re.finditer(r'(/[^\s()]+)',value):
            p=Path(match.group(1)).resolve()
            if p.is_file():paths.add(p)
    return {str(p):binding(p) for p in sorted(paths)}


def verify_admission():
    value=json.loads((SAME/'admission.json').read_text())
    assert value['status']=='SAME_ALGEBRA_TERMINAL_ADMISSION_CHECKS_PASS'
    assert value['bindings_before']==value['bindings_after']==control_admission_bindings()
    exact=json.loads((READY/'exact-admission.json').read_text())
    assert exact['status']=='EXACT_ARITHMETIC_AUDIT_PASS' and exact['fresh']==NATIVE_FRESH
    trace=native.spec(None)
    assert len(trace)==22
    for actual,(name,key,limbs,arity,bound) in zip(exact['trace'],trace):
        assert (actual['state'],actual['key'],actual['limbs'],actual['components'],int(actual['error_bound_decimal']))==(name,key,limbs,arity,bound)


def decrypt(ring,ct,secret,square,rows,diagnostic=False):
    assert ct.key==secret.key and ct.limbs==2 and len(ct.components) in (2,3)
    phase=ring.add(ct.components[0],ring.point(ct.components[1],secret.spectra,2),2)
    if len(ct.components)==3:phase=ring.add(phase,ring.point(ct.components[2],square,2),2)
    residues=[ring.transform(phase[j*N:(j+1)*N],j,True) for j in range(2)]
    p0,p1=ring.primes[:2]
    inv=pow(p0,-1,p1)
    bits=bytearray(N)
    for i,(a,b) in enumerate(zip(*residues)):
        value=a+p0*((b-a)*inv%p1)
        bits[i]=(value-Q if value>Q//2 else value)&1
    words=[sum(bits[i*256+e]<<e for e in range(256)) for i in range(256)]
    values=decode(words,rows)
    lanes=array('H',((values[j]>>(16*lane))&65535 for lane in range(16) for j in range(256)))
    return (lanes,phase,bits) if diagnostic else lanes


class CountSink:
    def __init__(self):self.bytes=0
    def write(self,data):self.bytes+=len(data);return len(data)
    def flush(self):pass


def serialize(kind,records):
    arrays=[]
    frames=[]
    for name,components in records:
        for part,value in enumerate(components):
            arrays.append(value)
            frames.append(dict(record=name,part=part,words=len(value)))
    sink=CountSink()
    receipt=send(sink,b'JETSW001',dict(version=1,profile='same-algebra-workflow-v1',kind=kind,frames=frames),arrays)
    assert sink.bytes==receipt['wire_bytes']
    return dict(raw_bytes=receipt['payload_bytes'],wire_bytes=receipt['wire_bytes'],polynomials=len(arrays),ciphertexts=len(records))
