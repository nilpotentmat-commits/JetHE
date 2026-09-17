# JetHE finite mathematical checks

This directory runs finite public algebra and exact numerical checks associated
with the current JetHE manuscript. It needs Python 3.10 or later and the Python
standard library. It has no HE-library, network, research-workspace, stored-key,
or external-fixture dependency. Run with assertions enabled; `-O` and `-OO` are
rejected.

From the `JetHE-Code` directory:

```console
python -B theory/run_checks.py --list
python -B theory/run_checks.py --output theory-results.json
python -B theory/run_checks.py --check admission --check rational-matrix --output selected-results.json
```

An output path must be new: the runner preserves earlier result files. Each
command also works from another current directory when the script is addressed
by its full path. Omitting `--output` performs the checks and prints a summary;
using it retains the complete finite configurations and results as JSON.

The default runs all ten groups below. The runner verifies the packaged source
hashes before executing them. `validation/standalone-checks.json` records the
release validation from a separate copy of this directory and an unrelated
temporary working directory. This is a fresh finite-check result, separate from
archived paper measurements and from any new benchmark.

## Mapping to the current manuscript

Paths in this table are relative to the manuscript root, supplied separately in
the release's `paper/` directory. Labels identify statements even if page or
theorem numbers change. The consolidated supplement places representation and
Hasse transport in Appendix A, correctness in B, public-view and Gaussian
constructions in C, source-law boundaries in D, complete-work and lower-bound
arguments in E, and joint evaluation in F. The remaining appendices organize
controls, implementations, measurements and reproducibility.
See `paper/labels.json` for the exact subsection and page of each statement.

| Command selector | Finite execution | Current manuscript and labels |
|---|---|---|
| `--check codec` | Constructs/inverts the actual 256-bit CRT matrices over the fixed degree-16 field; Taylor basis checks, tensor/univariate round trips, direct sparse Hasse oracles and small full-lane multiplication checks. Also checks both length-512 conversion branches. | `sections/representation.tex`: `sec:representation`, `thm:tensor-owner-codec`; `appendices/representation-details.tex`. |
| `--check worked-example` | Exhausts 32,768 binary length-eight composition pairs and 256 Hasse inputs; checks 128 deterministic full-field fixtures, intermediate interleaved states and the prepared-prefix identity. | `sections/prepared-composition.tex`: `thm:native-composition-recurrence`, `thm:owner-product-prefix`; the current length-eight worked example. |
| `--check hasse` | 72 public affine transport fixtures in small rings with odd conductor 5; 210 count ledgers; 64 selected unit-minor checks for the actual length-256 residue modulus, over eight dyadic orders, four sign patterns and paid/free variants. | `sections/hasse-minimum.tex`: `thm:hasse-paid-identity-minimum`, `eq:hasse-paid-layer-attainer`; `sections/prepared-composition.tex`: `lem:native-hasse-transport`; `appendices/hasse-map-layer-comparison.tex`: `prop:paid-hasse-current-phase`; `appendices/conventional-compiler-transfer.tex`. |
| `--check admission` | Recomputes all 22 complete-state bounds for the selected 102-row profile, stage digits, incoming-row inventory and strict margins. An exact rational bound checks the stated 59-event, 1024-fixed-batch union. | `sections/primary-profile.tex`: `thm:primary-terminal`; `appendices/three-prime-proof.tex`: `eq:terminal-switch-caps`, `eq:terminal-product-caps`, `eq:terminal-probabilistic-product`; `appendices/native-stage-gadgets.tex`. |
| `--check fixed-field` | Symbolic coefficient witnesses and ranks at lengths 8, 16 and 32; an independent full length-eight truth table; bounded point checks through length 64; exact dimension/count formulas for logarithmic lengths 8 through 64. | `sections/resources.tex`: `cor:main-depth-work-separation`; `appendices/fixed-field-carrier-bound.tex`: `lem:fixed-field-coefficient-space`, `cor:fixed-field-carrier-counts`. |
| `--check encoding` | Seven finite counterexamples illustrate why privacy and full-domain correctness are separate hypotheses; checks 87,376 toy message/key assignments. | `sections/resources.tex`: lower-bound Step 3; `appendices/fixed-field-carrier-bound.tex`: `lem:secure-encoding-length`, `cor:explicit-prepared-bit-work`. |
| `--check gaussian` | 285 exact reference-parameter cases, 1719 admitted states, inventory and sufficient failure-budget arithmetic; 4077 rounded-CDF weight laws and 375,084 enumerated uniform inputs. The selected table size is counted, not allocated. | `sections/security.tex`: `cor:main-gaussian-security`; `sections/resources.tex`: `cor:gaussian-complete-resources`; `appendices/gaussian-security-family.tex`: `lem:gaussian-shared-tables`, `prop:gaussian-prepared-workflow`, `eq:gaussian-batch-failure`. |
| `--check arithmetic` | Packed integer-ring multiplication versus a separate power-basis oracle, field/jet products through length 256, and finite Carlitz rescaling identities. | `appendices/fast-prepared-work.tex`: `lem:fast-physical-products`; `appendices/fixed-field-carrier-bound.tex`: coefficient witness. |
| `--check rational-matrix` | Twenty signed integer matrix cases and 23 quotient-ring matrix fixtures, including even moduli where the denominator is noninvertible; exact fractions for the exponents and 249 prefix-rounding cases. | `sections/resources.tex`: `thm:joint-work-main`; `appendices/rational-joint-work.tex`: `lem:rational-matrix-integer-transfer`, `prop:rational-joint-work`, `cor:rational-joint-gap`. |
| `--check batched-hasse` | Direct versus joint public Hasse matrix arithmetic, 6720 compared algebra coefficients, and two following-state traces on known public ciphertext-shaped arrays. | `appendices/joint-hasse-work.tex`: `prop:joint-hasse-identity`, `eq:joint-hasse-counts`; `sections/resources.tex`: joint-evaluation construction. |

## What these executions establish

Passing means the stated finite assertions hold for the executed fixtures.
The source law, acyclic reduction, universal payload minimum, asymptotic
independence argument and complexity theorems remain written mathematical
arguments. In particular:

- The Hasse unit-minor checks use selected sign patterns; they do not exhaust
  every norm-one lift or prove the universal payload lower bound.
- The admission program checks arithmetic conditional on the paper's
  fixed-input concentration premises. It does not establish those premises,
  adaptive-input correctness, or an observed decryption-failure rate.
- Gaussian checks construct neither sampler tables nor Gaussian samples,
  certified primes, HE keys or a hardness estimate. Their profile is distinct
  from the measured ternary/CBD20 construction.
- Encoding counterexamples are finite toys, not reusable public-key encryption
  or a machine proof of the secure-length lemma.
- Rational arithmetic uses a rescaled Strassen kernel to exercise clearing
  denominators and exact division. It does not implement the cited modern
  matrix exponent or provide its practical constants.
- The fixed-field and rational-matrix executions are explicitly bounded subsets
  of the original research campaigns. Their results are not rank or runtime
  extrapolations.

This directory does not reproduce all experiments or all proofs in the
supplement. HElib/OpenFHE experiments, native optimization campaigns, receiver
measurements and other source-law screens belong to separate release components
where supplied. `supplementary-inventory.json` records 61 entries from the
paper's source-provenance map to help locate those components; source existence
alone does not mean inclusion or successful reproduction.

## Provenance and implementation layout

`provenance.json` gives original workspace-relative paths, SHA-256 hashes,
retained function/constant line ranges, adaptations and packaged hashes.
Original paths are provenance only and are never opened by the runner.

`lib/` contains selected original mathematical functions and constants with
portable imports. Historical entry points, workspace-file bindings, unused
experimental drivers and source-document retrieval routines were omitted.
`run_checks.py` supplies the portable entry point, bounded fixture selection and
current manuscript references. The extracted codec and worked-example `main`
functions only produce in-memory/public-arithmetic results and are called by
the runner; no historical filesystem-dependent main routine is invoked.

No cryptographic keys, binaries, third-party library trees or unrelated refresh
experiments are included in this theory directory.
