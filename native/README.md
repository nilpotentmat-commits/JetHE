# Native JetHE implementations

This directory contains executable code for the paper's JetHE-102 construction, its same-backend one-prime control, and the separate JetHE-149 configuration measured alongside OpenFHE. It builds without the development research tree, HElib, OpenFHE, or a precompiled JetHE library.

## Requirements

- Little-endian, 64-bit Linux or WSL2.
- Python 3.10 or later, with its standard library; do not use `python -O`.
- A C++17 compiler supporting `unsigned __int128` and shared libraries, such as GCC or Clang.
- Each execution is limited to one selected CPU, 2 GiB address space, 900 CPU seconds and 960 wall seconds. Use a machine with enough available memory for the chosen profile.

The standalone release was checked on x86-64 WSL2 with Python 3.14.4 and GCC 16.2.0. Other platforms and Python/compiler versions have not been independently tested here.

## Build and run

From the directory containing `native/`:

```bash
python3 native/tools/verify_sources.py
python3 native/build.py
python3 native/run.py --profile jethe102 --setups 1 --output results/native102
python3 native/run.py --profile control --setups 1 --output results/one-prime-control
python3 native/run.py --profile jethe149 --setups 1 --output results/native149
```

Run these commands sequentially when collecting timings. Every output directory must be new. The compiler is selected by `CXX`, or explicitly with `python3 native/build.py --cxx clang++`. Libraries are built into the ignored `native/build/` directory. No compiled binary is required in the source release.

Each setup runs in a new process, samples fresh independent secret keys and evaluation-key randomness from the operating system, and executes one cold and one warm batch with fresh encryption coins. The default CPU is the first CPU allowed by the current process; `--cpu N` chooses another available CPU. The public synthetic input fixture is deterministic; it is never used as cryptographic randomness.

Use `--setups N` for additional independent setups. The launcher retains every observation and does not manufacture or replace the paper's recorded medians. `--mode gate` is an optional instrumented correctness mode with private phase checks and one batch; its timings are not complete-workflow benchmark samples. The release smoke verification exercised the default cold-plus-warm mode.

## Configurations

All three programs compute sixteen exact length-256 compositions over the binary extension field defined by `0x1100b`, returning all 4096 coefficients. The native carrier has dimension 65536.

| CLI profile | Arithmetic and interface | Inputs | Encrypted products | Hint rows | Terminal output |
| --- | --- | ---: | ---: | ---: | --- |
| `jethe102` | Three-prime start, stage-dependent gadgets, fixed-multiplier backend | 35 | 19 | 102 | One three-component ciphertext |
| `control` | Same fixed-multiplier arithmetic, one-prime, one product layer, recipient interpolation | 346 | 86 | 0 | 86 raw products and two owner corrections |
| `jethe149` | Separate original four-prime backend, width-48 paid-identity transport | 35 | 19 | 149 | One two-component ciphertext |

The two native configurations must remain distinct when comparing to the recorded OpenFHE observations. JetHE-149 uses its own original arithmetic library, ordinary encryption routine, key graph, modulus chain and serialization schema. `config/profiles.json` records the fixed parameters, source laws and profile identifiers.

Raw public/input/output payloads are respectively 297/103/3 MiB for JetHE-102, 1/346/131 MiB for the control, and 559/137/2 MiB for JetHE-149. Serialized frames add headers and digests. Peak process RSS includes retained keys, owner data, temporary allocations, and recipient work.

## Timing and correctness scope

Batch times include owner preparation, encoding, fresh encryption, evaluator computation, counting-sink serialization, decryption and recipient reconstruction. Public fixture/reference preparation, imports, process startup, post-batch teardown, and physical network/disk transfer are outside the batch interval. Final output comparisons are outside that interval. Setup is reported separately. JetHE-102/control record setup wall time; JetHE-149 retains its original setup phase subtotals. Summing phase medians across experiments is not a new observation.

The expected fixture is the original 8192-byte, little-endian reference output. Every batch checks all 4096 coefficients and the fixed SHA-256 digest. JetHE-149 additionally computes the independent plaintext Horner reference using its original arithmetic routine outside the batch timer. A matching result establishes this finite execution's correctness, not a proof for arbitrary inputs.

All configurations use the measured ternary/CBD20 source laws. They are not numerical security certifications, and they do not implement the manuscript's growing Gaussian theorem. The public evaluator functions accept public ciphertexts and evaluation material; this local benchmark runs owner, evaluator and recipient roles in one process and does not provide a network protocol or recipient-privacy theorem.

`VALIDATION.json` and `validation/` retain the public records of one successful fresh cold/warm setup for each profile, plus the initial packaging failure and its resolution. They contain timings, counts and output digests, without secret keys or random coins. The original execution directories under ignored `results/` are not bundled; their relative paths and hashes are retained for provenance. No HE run was repeated to prepare these public records. All three entry points reject Python `-O` and `-OO` so validation assertions cannot be disabled.

## Source layout and provenance

- `backend/fixed/`: measured optimized ring arithmetic for JetHE-102 and the control.
- `backend/paid149/`: original arithmetic for JetHE-149.
- `backend/terminal_kernel_v1.cpp` and `backend/interpolation.cpp`: terminal multiplier and recipient/owner interpolation kernels.
- `src/`: the computational Python definitions extracted from the measured implementation, with local imports and paths.
- `fixtures/expected.bin`: public reference output, not an executable or secret material.
- `provenance.json`: original relative source paths and hashes, checks against the recorded benchmark bindings, extracted definitions, and package hashes.

Unchanged computational definitions retain their original bodies. The packaging changes reconstruct import contexts, make library/fixture paths relative, omit unused historical variants and supervisors, and add the portable build/run interface. `tools/verify_sources.py` checks the supplied source and fixture bytes against this provenance. It does not rerun a benchmark or certify the security of the construction.
