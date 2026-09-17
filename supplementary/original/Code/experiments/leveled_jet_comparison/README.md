# Matched leveled jet evaluation in OpenFHE

This experiment compares ordinary BGV and BFV, each using two representations
of the **same terminal binary polynomial product**. It supplies measured leveled
library costs, not an ExactJet implementation, a bootstrap benchmark, a
certification of Phi_8224, or a universal advantage for native jet encoding.

## Workload and the stronger baseline

For each job, the client supplies `d+1` binary polynomials of length `e` and
receives the first `e` binary coefficients of their product. Timed fixtures
are independently generated binary units: the constant is 1 and all higher
coefficients are independent pseudorandom bits. Independent factors avoid a
repeated-squaring workload and units avoid trivial nilpotent annihilation.

- **Native:** use plaintext modulus 2 and `u=X+1` in the standard power-of-two
  ring. One ciphertext holds one job. Projection modulo `u^e` commutes with
  the encrypted product. This is one ramified lane, not the multi-lane
  arbitrary-cyclotomic construction.
- **Packed terminal:** evaluate each input at `K=(d+1)(e-1)+1` distinct points
  over F_65537 and pack `floor(N/K)` jobs per ciphertext. Retain evaluation
  form during the entire encrypted product. The input owner decrypts,
  interpolates, and parity-decodes the low coefficients at the end.

The latter output is exact, not a comparison of different fields' answers.
The full product has degree below K. Its low integer coefficient of degree
`j<e` is at most `binomial(j+d,d)`, which is at most 3876 on the declared
`e=4,8,16; d=1,2,4` grid. This is below 65537, so canonical lifting after
interpolation recovers that coefficient before taking parity. Higher
coefficients may wrap; they do not invalidate the low-coefficient argument.
The executable checks the bound, actual scalar-slot capacity, and batching
root condition. The manuscript contains a formal proposition.

The comparator is appropriate for a **terminal input-owner** service. It does
not return coefficient ciphertexts ready for arbitrary binary continuation,
nor does it claim equal leakage to a restricted-output third party. The owner
already supplies the inputs and is permitted to decode the returned object.
Client transforms and all serialized output objects are charged explicitly.

Both sequential and balanced product schedules use `d` multiplications per
ciphertext batch. Their multiplicative depths are `d` and
`ceil(log2(d+1))`. Neither equals the jet length in general. Every EvalMult
includes the backend's ordinary relinearization and modulus-alignment work.
All calls execute serially, including independent branches of the balanced
tree. The schedule control therefore measures operand shape and backend
handling on one thread; it does not measure parallel critical-path latency.

## Parameters and measurements

Both schemes request `HEStd_128_classic`; OpenFHE chooses the ring dimension
and moduli independently for each plaintext modulus and requested workload
horizon. The final policy requests `parameter_multiplicative_depth=d` for
both schedules and both representations, while recording the actual circuit
depth separately as `ctct_depth`. Thus sequential and balanced controls use
the same parameter-generation policy for a fixed scheme, representation,
and number of factors. This measures scheduling under a common provisioned
horizon; it does not claim a minimum-modulus implementation of either graph.
Each
record contains actual Q primes, Q/P/QP bit lengths, special primes, secret
distribution, key-switching and multiplication methods, backend version,
compiler version, input/output/key serialization sizes, and process peak RSS.
The standard library preset is not an independent attack estimate or a new
proof for the evaluation-key transcript. Actual conventional relinearization
keys must not be described as the manuscript's independent-key graph.

One whole pipeline trial warms each process and is excluded from statistics.
Each subsequent trial uses fresh library encryptions of the same deterministic
fixture; the fixture seed is never given to the cryptographic sampler. Each
configuration has a freshly generated library key pair. All jobs and all
output coefficients are checked against clear multiplication. The independent
Python verifier uses integer bit strings and carryless XOR multiplication.
Finite successful trials are not a decryption-failure probability estimate.

The harness serializes timed processes and sets `OMP_NUM_THREADS=1` and
`OMP_DYNAMIC=FALSE`. Configuration order is shuffled using a recorded seed.
The raw records preserve every trial's encoding, encryption, evaluation,
decryption, and decoding time. The end-to-end statistic is the median of
the **per-trial sums**, not the sum of five medians. Setup and public matrix
precomputation are separate; the latter timing also includes deterministic
fixture generation and the clear reference computation. Decoding time includes
output-vector bookkeeping, the output comparison, and the packed
representation's integer-bound check.
End-to-end here excludes network transfer and
object serialization time; their byte volumes are reported separately.
RSS is the process peak, including setup, transforms, and measurement support,
not a ciphertext-only allocation measurement.

Comparisons use the same job count, factors, schedule, and input fixture.
Single-job latency and packed throughput must be read separately. A table of
HMul counts alone cannot establish speed, and equal requested security does
not mean equal ring dimension, modulus, capacity, or ciphertext size.

## Build and run

Dependencies: C++17 compiler, CMake, installed OpenFHE 1.5.1, Python 3.
No optional Python package is required for running or checking observations.
Build outside this source/evidence directory:

```powershell
cmake -S Code/experiments/leveled_jet_comparison -B Code/build-leveled-jet-comparison -G Ninja -DCMAKE_BUILD_TYPE=Release -DOpenFHE_DIR="C:/Program Files/OpenFHE/CMake"
cmake --build Code/build-leveled-jet-comparison
ctest --test-dir Code/build-leveled-jet-comparison --output-on-failure
python -m unittest discover -s Code/experiments/leveled_jet_comparison -p "test_verify_results.py"
python Code/experiments/leveled_jet_comparison/run_benchmarks.py --binary Code/build-leveled-jet-comparison/leveled_jet_comparison.exe --output Code/experiments/leveled_jet_comparison/results/NEW-RUN-ID --balanced
```

On Windows the compiler must match the installed OpenFHE build. If it is not
already configured on PATH, pass `-DCMAKE_CXX_COMPILER=.../g++.exe` and
`-DCMAKE_MAKE_PROGRAM=.../ninja.exe` for that MinGW installation. The CMake
target copies the required OpenFHE and MinGW runtime DLLs beside the executable.
On other platforms the executable has no `.exe` suffix.

The default sweep has 80 configurations: the 72-way cross product of two
schemes, two representations, three jet lengths, three sequential depths,
and job counts 1/16, plus eight length-16 balanced controls with five factors.
Default repetitions are seven, plus one excluded warm-up. Smaller smoke
runs can restrict `--lengths`, `--mults`, `--jobs`, `--schemes`, and `--layouts`.
Run additional full-occupancy pairs using the actual packed capacity reported
by a single-job case, with that same job count for both representations.

Every run directory, record, and source snapshot is created exclusively;
existing runs are never overwritten. `plan.json` records the intended sweep
before execution. A failed case leaves a failure record and does not produce
a completed manifest. `manifest.json` binds the source snapshots, executable,
DLLs, environment, order, and each successful observation. Preserve failed
runs as diagnostics, not as completed evidence.

`results/leveled-main-v1` preserves a preliminary run that stopped at its
54th requested configuration, BFV/native with length 16, four multiplications,
16 jobs, and the balanced schedule. That earlier producer requested the
balanced graph's depth 3; an output disagreed with the exact oracle. The
failure record and its source snapshot are retained without modification,
and the incomplete run is excluded from completed comparison evidence. The
record lacks sufficient diagnostics to attribute the failure to a specific
library defect or to estimate its probability.

The policy above subsequently provisions both schedules for the same
sequential horizon. One targeted depth-4-provisioned balanced diagnostic passed
its warm-up and three measured trials; its separate record is
`results/bfv-balanced-common-depth-diagnostic-v1.json`. That diagnostic does
not replace the full sweep. The completed final-policy sweep is
`results/leveled-main-v2`; its 80 cases pass the independent verifier.
`results/leveled-capacity-v1` adds four matched 215-job cases, and
`results/leveled-seed-control-v1` adds eight length-16/five-factor/16-job
controls with fixture seed 29 and new keys. Together the completed runs contain
92 cases, 644 retained trials, and 158,256 independently checked output
coefficients. The 92 warmup trials are checked by the producer but not
included in those independently checked counts.
A plan file or partial collection of cases alone is not a completed result.

```powershell
python Code/experiments/leveled_jet_comparison/verify_results.py Code/experiments/leveled_jet_comparison/results/RUN-ID/manifest.json --repo-root .
```

The verifier checks recorded outputs, algebraic bounds, schedules, operation
counts, parameter metadata, timing statistics, and hashes. It does not
independently rerun the stopwatch or establish security. Its negative tests
demonstrate rejection of selected malformed records; they do not turn a
measurement into a cryptographic theorem.

## Complete results and reproducibility

[Read the measured report](results/leveled-report-v1/report.md) or use
[all-cases.csv](results/leveled-report-v1/all-cases.csv) for every phase,
parameter, byte count, memory observation and sample range. The paper inputs
the report's generated LaTeX directly, so the numerical tables have one source.

For length 16 and five factors, native single-job pipeline medians are
54.60 versus 89.92 ms for BGV and 53.53 versus 123.48 ms for BFV (native versus
packed). At 16 jobs, packed batch pipeline time is instead lower by factors
9.49 and 6.61. These are workload/layout-specific measured tradeoffs, not an
all-FHE ranking, a proof of optimal encoding, or an ExactJet speedup.

```powershell
python Code/experiments/leveled_jet_comparison/summarize_results.py Code/experiments/leveled_jet_comparison/results/leveled-main-v2/manifest.json Code/experiments/leveled_jet_comparison/results/leveled-capacity-v1/manifest.json Code/experiments/leveled_jet_comparison/results/leveled-seed-control-v1/manifest.json --output Code/experiments/leveled_jet_comparison/results/leveled-report-v1 --check
```

Without `--check`, use a new output directory: reports are exclusively created,
never overwritten. The summary binds all parent manifests and the generator
and verifier source hashes. The check recomputes plaintext outcomes, medians,
ranges and every report byte; it does not independently remeasure time.
The measured build used GCC 16.1.0 with `-O3 -DNDEBUG`, OpenFHE 1.5.1,
and Windows 11 build 26200. Hardware/thread details are in each manifest.

## Relation to the earlier benchmark

`Code/tests/cpp/bench_jet_openfhe.cpp` is retained as historical diagnostic
code. It compares F2 native arithmetic with F65537 arithmetic without the
terminal parity proof, disables security parameter selection, uses unequal
depth provisioning, and reuses a multiplier. Its timings are not incorporated
in this experiment. This new benchmark is independent of all frozen ExactJet
and selected57 receipts and changes none of their authority fields.
