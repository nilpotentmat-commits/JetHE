# JetHE: code and reproducibility artifact

Code accompanying **JetHE: Prepared Composition on Ramified Homomorphic Ciphertexts**. The matching [paper](paper/JetHE.pdf) and [LaTeX source](paper/JetHE-source.zip) are included. This snapshot has 28 main pages, 3 reference pages, and 158 supplementary pages. The supplement is organized into ten thematic appendices (A–J). The correspondence below uses this snapshot; [paper/labels.json](paper/labels.json) provides stable source labels and printed numbers.

The artifact provides executable implementations of all five configurations in the main performance tables, finite mathematical checks, original measurement receipts, and selected supplementary code. It is a research implementation, with the timing and security scope described below.

## Start here

From this directory, using Python 3.10 or later:

```sh
python tools/verify_manifest.py
python tools/verify_recorded.py
python -B theory/run_checks.py --output results-theory.json
```

These commands require only the Python standard library and work without an HE library. The first verifies the supplied files. The second checks the 40 recorded measurement rows, their 20 original receipt hashes, main-table aggregates, and the paper's unchanged evidence checker. The third executes ten finite mathematical check groups. **None of these three commands runs encrypted benchmarks.** Do not use Python optimization flags `-O` or `-OO` for assertion-based checks.

For a fresh full-workload JetHE execution on 64-bit little-endian Linux or WSL2:

```sh
python3 native/tools/verify_sources.py
python3 native/build.py
python3 native/run.py --profile jethe102 --setups 1 --output results/native102
```

This compiles the packaged C++17 sources and runs one fresh setup with a cold and a warm encrypted batch. Every batch checks all 4096 output coefficients. There is no dependency on the original development directory, OpenFHE, or HElib. See [native/README.md](native/README.md) for compiler selection and resource limits.

## Correspondence with the paper

| Paper location | Implementation or data | Reviewer action |
| --- | --- | --- |
| Section 3, tensor representation | `theory/lib/`; native codec modules | `python -B theory/run_checks.py --check codec` |
| Sections 4–5, leveled evaluation, prepared recursion, Hasse transport | `native/src/`, `native/backend/`; finite worked examples and Hasse checks | Native execution; theory selectors `worked-example` and `hasse` |
| Section 6, Table 2, selected 102-row profile | `native/config/profiles.json`, `recorded/admission.json` | Native profile `jethe102`; theory selector `admission` |
| Section 7, Gaussian family and source-law distinctions | Written proofs; exact parameter and finite sampler-law arithmetic in `theory/` | Theory selector `gaussian`; this is not an executable Gaussian HE implementation |
| Section 8, complete-work bounds and joint evaluation | `theory/`, including finite rank, encoding, arithmetic and matrix checks | Selectors `fixed-field`, `encoding`, `arithmetic`, `rational-matrix`, `batched-hasse`; asymptotic claims remain mathematical proofs |
| Section 9, Tables 4–5: JetHE-102 and one-prime control | `native/`; `recorded/` | Native profiles `jethe102` and `control` |
| Section 9.1, Tables 4–5: JetHE-149 and the two OpenFHE BGV adapters | `native/`, `openfhe/`; `recorded/` | Native profile `jethe149`; OpenFHE profiles `summed` and `terminal` in **benchmark** mode |
| Table 6, complete workflow phase costs | Preserved worker timers and `recorded/measurements.csv` | Recorded verifier; inspect phase fields in fresh run JSON |
| Supplement, HElib implementation profiles and core controls, Table 22 and Tables 38–42 | `helib/` | Build and select a profile using [HElib instructions](helib/README.md) |
| Supplement, optimization campaigns, alternative controls and source screens | `supplementary/original/` | Inspect original sources/data using the [coverage inventory](docs/SUPPLEMENTARY_COVERAGE.md); historical entry points are not all portable |

The [detailed paper-to-code map](docs/PAPER_CODE_MAP.md) gives source labels, expected measurements and the distinction between runnable checks and archived evidence. The [theory README](theory/README.md) lists the exact finite scope of each check.

## Reproduce the five main configurations

Build the native code as above, then run sequentially:

```sh
python3 native/run.py --profile jethe102 --setups 4 --output results/native102-four
python3 native/run.py --profile control --setups 4 --output results/control-four
python3 native/run.py --profile jethe149 --setups 3 --output results/native149-three
```

Build the pinned OpenFHE dependency and adapter using [openfhe/README.md](openfhe/README.md), then:

```sh
python3 openfhe/run.py --build-dir openfhe/build --profile all --mode benchmark --setups 3 --output results/openfhe-three
```

The OpenFHE build instructions run from `openfhe/` and create `openfhe/build/`. If another build directory is used, pass that directory instead. `all` selects the two BGV adapters. The runner's default **smoke** mode uses four length-16 jobs and must not be compared with the paper; the command above explicitly selects the full sixteen length-256 jobs. One setup per profile is sufficient for an initial functional check. Every result directory must be new; failures and earlier observations are retained.

The setup counts above match the selected sample counts in the paper. The commands group profiles separately; they do not recreate the original interleaved campaign order or machine conditions. For a new timing comparison, retain the complete command/environment receipts, use a quiet machine, keep one thread and the same CPU across profiles, and document execution order. Report fresh measurements separately from the published data.

The workload computes sixteen exact truncated-series compositions of length 256 over the field defined by `0x1100b`. The public synthetic fixture is deterministic. Keys, errors and encryption coins are freshly sampled; the fixture seed is not a randomness source for cryptography. Each full batch returns 4096 field coefficients, serialized as 8192 little-endian bytes, with expected SHA-256:

```text
d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3
```

The original complete warm medians, in seconds, are:

| Configuration | Independent warm observations | Recorded median |
| --- | ---: | ---: |
| JetHE-102 | 4 | 1.730384 |
| Same-backend one-prime control | 4 | 7.710294 |
| JetHE-149 | 3 | 4.733799 |
| OpenFHE summed BGV | 3 | 15.795136 |
| OpenFHE terminal BGV | 3 | 12.884548 |

These are observations from distinct selected parameter profiles. They are not predictions for another machine or a claim of equal security levels. The OpenFHE adapters use exact encoding over plaintext prime 65537 to implement the binary-field task; “packed” denotes an encoding/evaluation layout, not a separate encryption scheme. JetHE-149 uses its own original four-prime implementation and must not be substituted for JetHE-102 in the historical OpenFHE comparison.

## Timing, validation and scope

A cold batch is the first batch after a fresh setup; a warm batch is the second batch reusing that setup. Each performs fresh encryption. Native complete batch timers charge owner preparation, encoding, encryption, evaluation, counting-sink serialization, decryption and recipient reconstruction. Setup, process startup, public reference preparation, final correctness comparisons and physical network transfer are separate. The individual component READMEs describe their preserved timers. These programs simulate the roles locally; they do not deploy a distributed protocol.

Release validation ran a full cold/warm setup for each of the five main profiles: ten batches and 40,960 recovered coefficients checked. These fresh functional checks do not replace the original medians. Component `VALIDATION.json` files and [docs/VALIDATION.md](docs/VALIDATION.md) record exactly what was exercised, including supplementary checks and packaging failures that were corrected.

The measured native profiles use ternary/CBD20 laws. Their execution does not instantiate the separate growing Gaussian security theorem, establish a 128-bit security certificate, prove recipient privacy, or establish a general FHE speedup. Finite algebra checks support inspection of the proofs; they are not machine-checked proofs of the universal or asymptotic statements. Historical adverse controls and failed parameter choices remain available in the supplementary archive.

## Directory guide and provenance

| Directory | Contents |
| --- | --- |
| `native/` | JetHE-102, JetHE-149, and same-backend control; portable build/run scripts |
| `openfhe/` | Exact BGV adapters, optional BFV relay, pinned dependency instructions |
| `helib/` | Supplementary conventional controls and selected profile arguments |
| `theory/` | Ten independent finite mathematical/numerical check groups |
| `recorded/` | Original selected CSV, receipt JSON files, admission data and reference output |
| `supplementary/` | Selected historical source/data archive and provenance hashes |
| `paper/` | Exact accompanying manuscript PDF/source and label map |
| `docs/` | Detailed correspondence, coverage and release validation |
| `tools/` | Manifest and recorded-evidence verification |

Per-component provenance records original relative paths, source hashes and packaging adaptations. Those paths identify origins; portable runners resolve dependencies within this artifact. Original receipts and archival scripts retain historical machine/path metadata, so this directory is not an anonymization of the development record. `release-manifest.json` lists the distributed files and their SHA-256 hashes.

Build products, downloaded libraries and newly generated result directories are ignored. Original archived result data remain included. `.gitattributes` preserves exact file bytes across Git checkouts so line-ending conversion does not invalidate the provenance hashes. OpenFHE, HElib, NTL and GMP are external dependencies; their source trees and compiled libraries are not bundled. The supplied nlohmann JSON header retains its MIT notice. No new license is assigned to the project's own code by this packaging step.
