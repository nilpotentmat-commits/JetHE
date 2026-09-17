# Paper-to-code map

All labels and numbers below refer to the bundled `paper/JetHE.pdf`. Source file paths refer to the root of `paper/JetHE-source.zip`. Use `paper/labels.json` if looking up a theorem whose numbering differs from another draft.

## Main performance evidence

| Result | Paper source / labels | Fresh executable | Original data |
| --- | --- | --- | --- |
| Selected 102-row implementation | `sections/primary-profile.tex`, `tab:primary-profile` (Table 2), `thm:primary-terminal` | `native/run.py --profile jethe102` | `recorded/admission.json`; four native cold/warm pairs from `shared_backend_composition` |
| Complete time and memory | `sections/evaluation.tex`, `tab:workflow` (Table 4) | The five main profiles in the root README | `recorded/measurements.csv`: `seconds`, memory and phase fields; `benchmark-verification.json` gives median/min/max statistics |
| Public, input and output material | `tab:material` (Table 5) | Preserved serialization and payload counters in native/OpenFHE workers | Same CSV and raw receipts; distinguish raw payload from framed serialization |
| Native phase costs | `tab:phase-costs` (Table 6) | Native workers' complete workflow timers | Original per-phase fields; do not sum independently selected phase medians into a new observed total |
| Joint JetHE-149/OpenFHE campaign | `app:openfhe-comparison` (Appendix I.3), `tab:joint-w0-results` (Table 46) | Native `jethe149`; OpenFHE `summed`, `terminal`; optional `relay-bfv` | Three setups per arm from `openfhe_composition`; the optional relay is recorded but is outside the five-profile main validation |
| Current native/control comparison | `sec:current-control-evidence` (Section G.3.9), `tab:current-control-samples` (Table 20), `tab:current-control-workflow` (Table 21) | Native `jethe102` and `control` | Four setups per arm; preserve the distinct modulus, key, memory and output profiles |

`tools/verify_recorded.py` verifies all 20 supplied receipt hashes and their membership in the 40-row CSV, recomputes all recorded statistics for the five main configurations, and runs the paper's original evidence checker in a separate extraction. It does not independently reconstruct every CSV field from the semantic contents of every raw receipt or rerun HE. The portable encrypted runners independently check the recovered output for fresh executions.

## Main technical arguments

The executable-to-statement map is in [theory/README.md](../theory/README.md). The most direct review sequence is:

1. `codec`: the tensor representation and the actual length-256 codec.
2. `worked-example` and `hasse`: the interleaved recursion, prepared prefix, sparse Hasse oracle and finite payload-count/minor checks.
3. `admission`: the selected implementation's 22 complete states and exact conditional failure-budget arithmetic.
4. `gaussian`: bounded parameter and sampler-law calculations for the separate Gaussian family.
5. `fixed-field` and `encoding`: finite coefficient-rank witnesses and counterexamples clarifying the lower-bound hypotheses.
6. `arithmetic`, `rational-matrix`, `batched-hasse`: exact arithmetic supporting the complete-work and joint-evaluation derivations.

The source-law reductions, IND-CPA theorem, universal Hasse minimum and asymptotic bounds are written proofs. No program here establishes those theorems by testing. In particular, the rational-matrix check does not implement a state-of-the-art matrix multiplication exponent, and the Gaussian check does not generate Gaussian HE keys.

## Supplementary implementation evidence

| Paper material | Supplied code | Reproduction status |
| --- | --- | --- |
| `app:baseline-profiles`, `app:core-matched-measurements`; Tables 38–42 | `helib/src/core/`, `helib/src/leveled/`, 34 selected conventional profiles | Portable build/launcher; release validation covers the explicit subset in `helib/VALIDATION.json`, not all profiles |
| Historical paid Hasse and terminal comparisons; Tables 34–37, 44 | `supplementary/original/SubmissionA/research/`; current native and HElib workers where the configuration matches | Original source/data supplied; historical campaign drivers may need their original layout |
| Five-factor leveled controls; Table 25 and related diagnostics | `supplementary/original/Code/experiments/leveled_jet_comparison/` | Original C++ sources and selected outcome JSON; not newly executed in this release |
| Same-algebra and one-prime workflows (Tables 16–21); stage-gadget, axis and multiplier campaigns (Tables 26–33) | `supplementary/original/SubmissionA/research/eurocrypt-readiness-2026-09-13/` | Original selected campaign sources/data; the final 102-row and one-prime profiles additionally have portable native runners |
| Source-law screens, receiver studies and joint-work alternatives | Supplementary archive; bounded checks in `theory/` where explicitly mapped | Inspectable historical sources/data; availability is separate from a portable or newly validated execution |

[SUPPLEMENTARY_COVERAGE.md](SUPPLEMENTARY_COVERAGE.md) resolves the paper's 61 provenance-map entries into this artifact, external dependency sources, generated build material or an explicit unresolved status. It is the detailed coverage ledger; the archive is not a claim that every experiment in the 158-page supplement has a turnkey rerun.
