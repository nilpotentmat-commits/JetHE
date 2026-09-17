# Release validation

Date: 2026-09-16. The source package was assembled from the implementations bound to the paper's selected measurements. This document describes validation of the released code; the published measurements remain in `recorded/`.

| Component | Executed during release preparation | Result and evidence |
| --- | --- | --- |
| Native JetHE-102 | Freshly built local libraries; one fresh setup, cold and warm full batches | PASS; 8192 recovered coefficients checked; `native/VALIDATION.json`, `native/validation/jethe102.json` |
| Same-backend one-prime control | One fresh setup, cold and warm full batches | PASS; 8192 coefficients; `native/validation/control.json` |
| Native JetHE-149 | Its separate original arithmetic backend, freshly compiled; one fresh setup, cold and warm full batches | PASS; 8192 coefficients; `native/validation/jethe149.json` |
| OpenFHE summed BGV | Fresh adapter build against the pinned installed library; one selected full setup, cold and warm batches | PASS; 8192 coefficients, parameter and operation inventories; `openfhe/VALIDATION.json`, `openfhe/validation/` |
| OpenFHE terminal BGV | Same validation with its selected full profile | PASS; 8192 coefficients, parameter and operation inventories; same evidence directory |
| HElib core control | Fresh adapter build; `crt-w1-l16-j1-m4369-b20-raw`, cold and warm | PASS; 32 logical output symbols and 512 terminal slots checked across two batches; `helib/VALIDATION.json`, `helib/validation/core.json` |
| HElib composition | Selected `composition-b16`, conductor 13107, requested bits 60, cold and warm | PASS; 8192 coefficients; `helib/validation/composition.json` |
| Finite theory checks | All ten groups from a separate copy and unrelated working directory | PASS; exact executed scopes in `theory/README.md` and `theory/validation/standalone-checks.json` |
| Recorded evidence | Original receipt hashes, 40 selected rows, five main-profile aggregates and unchanged paper checker | PASS; independently repeat with `python tools/verify_recorded.py` |

The five main configurations account for ten full batches and 40,960 checked field coefficients. These fresh checks use newly generated keys and encryption coins; their observed timings are functional validation records rather than replacement statistical estimates. Each full batch matched the fixed 8192-byte expected output. The OpenFHE C++ and Python generators also produced identical full public input bytes.

Native and HE-adapter builds were checked under x86-64 WSL2 with Python 3.14.4 and GCC 16.2.0. OpenFHE, HElib, NTL and GMP dependencies were the existing pinned installations; their linked library hashes were checked against the recorded build evidence. They were not independently rebuilt from scratch during this release. The supplied instructions allow reviewers to build them.

## Packaging corrections retained in the evidence

The first native JetHE-102 run exposed a missing `sys` import in an extracted module. Restoring the import allowed the complete run to pass. The failure traceback is included under `native/validation/`, with machine-prefix normalization documented in the validation manifest.

The first supplementary HElib composition run used an incorrect packaging parameter of 20 requested bits. It failed the unchanged ten-bit output-capacity gate. The original selection receipt specified 60 bits for both composition profiles; the package was corrected to that value and the BSGS profile passed. The original failed record is included as `helib/validation/initial-composition-profile-failure.json`.

Subsequent launcher changes added explicit rejection of Python optimization modes where assertions are used. These guards were checked without rerunning HE, and do not change normal execution. Native computational source provenance remained unchanged. The final OpenFHE and HElib wrappers also rechecked their retained outputs after packaging adjustments.

## Reproduction boundaries

The optional OpenFHE relay, HElib column composition, the other 31 HElib core profiles and the historical supplementary campaigns were not freshly executed in this release. Their availability and binding checks are described separately. The archival sources do not all have portable launchers.

Passing these checks is not a proof of a security assumption, arbitrary-input correctness, an asymptotic lower bound or a numerical security level. The accompanying paper snapshot and its scientific claims were not changed during code packaging. The manifest verifies the listed artifact bytes; it does not authenticate authorship or check newly generated result directories.

## Appendix consolidation

The accompanying paper snapshot and navigation were synchronized after its
supplement was grouped into ten thematic appendices. Computational sources,
parameters, original measurement receipts and the existing fresh-execution
records are unchanged. This editorial synchronization did not rerun HE; the
recorded-evidence and release-manifest checks were repeated for the new bundle.
