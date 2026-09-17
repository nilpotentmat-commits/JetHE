# HElib supplementary controls

These are the original composition and terminal product/circuit implementations used in the supplement. They are separate from the main OpenFHE comparison. All six project C++/header files are unchanged; `provenance.json` records their original hashes. The bundled nlohmann JSON 3.9.1 single header retains its full MIT notice.

Use HElib 2.3.0 at commit `3e337a66a91a92d49de6a9505340826b0eb71081`. Its [pinned installation instructions](https://github.com/homenc/HElib/blob/3e337a66a91a92d49de6a9505340826b0eb71081/INSTALL.md) describe package builds with GMP/NTL and builds against existing dependencies. Install into a user-owned prefix, then from the artifact root:

The pinned commit's `VERSION` file and installed CMake package report `2.2.0`; use the commit as the exact source identity. `VALIDATION.json` also records the installed library hash and its match to the original measurement receipt.

```sh
cmake -S helib -B build/helib -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/path/to/helib/prefix
cmake --build build/helib --parallel 2
python3 helib/run.py --build-dir build/helib --profile composition-b16 --output results/helib-b16
python3 helib/run.py --build-dir build/helib --profile composition-column --output results/helib-column
```

`python3 helib/run.py --list` lists all 34 supplied conventional profiles: 32 terminal product/circuit profiles and two composition profiles. Each run generates fresh keys and performs a cold and a warm batch. Core profiles check their full cell-specific outputs; composition recovers all 4096 field coefficients. The original binary checks fail on mismatch. Runtimes differ across hosts and builds.

Both composition profiles use the originally selected `m=13107`, requested `bits=60` configuration with two ciphertext primes. The initial package incorrectly specified 20 bits; validation rejected that configuration at the original ten-bit output-capacity gate. The corrected profiles follow the recorded selection, and the failed validation is retained in the internal release evidence. Run without Python `-O` or `-OO`; the launcher rejects those modes to keep output assertions active.

Correspondence: supplementary implementation profiles in Appendix H.1 (`app:baseline-profiles`, `tab:leveled-profile-manifest`, Table 22) and core measurements in Appendix I.1 (`app:core-matched-measurements`, Tables 38–42, including `tab:core-phase-breakdown`, `tab:core-setup-throughput`, and `tab:core-nested-timers`). Use `paper/labels.json` for current printed numbering. `profiles.json` preserves the selected command arguments and the original measurement status. Historical native core implementations and campaign selection code are retained separately under `supplementary/original`.

These drivers require Linux or WSL for POSIX resource accounting and `/dev/urandom`. HElib, NTL and GMP are external dependencies, not vendored libraries. The original host-specific supervisors are not used by this portable launcher. Complete in-process timing boundaries remain those implemented in the unchanged C++ workers; the launcher does not count its own process startup as a paper measurement.
