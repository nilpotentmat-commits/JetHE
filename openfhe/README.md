# OpenFHE exact-composition adapters

This directory builds the actual OpenFHE programs behind the paper's **Summed BGV** and **Terminal BGV** rows. Both compute all coefficients of sixteen length-256 compositions over `GF(2)[x]/(x^16+x^12+x^3+x+1)`. The measured C++ evaluator is byte-identical to the recorded source. Its companion header has only an include-path relocation; the public fixture generator is unchanged. `PROVENANCE.json` binds these files to the recorded experiment's source hashes.

These are OpenFHE BGV programs with an exact extension-field adapter, not a native JetHE implementation. Their inputs, recovery work, key material and memory differ from JetHE. The paper does not claim numerical security matching. The optional BFV relay already present in the evaluator is a secondary work-placement control: it discloses both original operands to the recipient and is excluded from `--profile all`.

## Build on Linux or WSL

Use a C++17 compiler, CMake 3.20 or newer, Git, Python 3, and **OpenFHE 1.5.1 at commit `1306d14f8c26bb6150d3e6ad54f28dfe1007689e`**. The adapter uses Linux affinity and resource APIs; run these commands inside Linux or WSL, not Windows Python. Compiler and operating-system versions affect measurements. The recorded experiments used GCC 16.2.0, Release, native integer size 64, math backend 4, OpenMP disabled and native-CPU tuning disabled.

From this directory, the following commands obtain and build the pinned external library. OpenFHE sources and compiled libraries are not bundled in this release.

```sh
git clone --no-checkout https://github.com/openfheorg/openfhe-development.git _deps/openfhe-src
git -C _deps/openfhe-src checkout --detach 1306d14f8c26bb6150d3e6ad54f28dfe1007689e
git -C _deps/openfhe-src submodule update --init --recursive
git -C _deps/openfhe-src rev-parse HEAD
cmake -S _deps/openfhe-src -B _deps/openfhe-build \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PWD/_deps/openfhe-install" \
  -DBUILD_SHARED=ON -DBUILD_STATIC=OFF -DBUILD_UNITTESTS=OFF \
  -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF -DBUILD_EXTRAS=OFF \
  -DGIT_SUBMOD_AUTO=OFF -DWITH_OPENMP=OFF -DWITH_NATIVEOPT=OFF \
  -DWITH_NOISE_DEBUG=OFF -DWITH_REDUCED_NOISE=OFF -DWITH_NTL=OFF \
  -DWITH_TCM=OFF -DNATIVE_SIZE=64 -DMATHBACKEND=4
cmake --build _deps/openfhe-build --parallel 2
cmake --install _deps/openfhe-build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOpenFHE_DIR="$PWD/_deps/openfhe-install/lib/OpenFHE"
cmake --build build --parallel 2
```

`lib64/OpenFHE` may replace `lib/OpenFHE` on installations using that layout. To reuse an existing pinned installation, run only the final two commands with its `OpenFHE_DIR`. Use a compatible compiler/runtime for both builds; a nonstandard compiler runtime can be supplied through `CMAKE_BUILD_RPATH`. The CMake file checks version 1.5.1, but a version string alone does not attest to a Git commit. The C++ receipt's commit field is a source annotation, not a measurement of the linked library. Verify the checkout and retain the actual library/build hashes.

The official [Linux installation guide](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/linux.html) describes the external dependency's CMake installation. The pinned commit and the configuration above, rather than the moving default branch, define this artifact's dependency.

## Verify and run

Every command creates a **new** output directory. Failed output is retained; choose a different directory for a subsequent run.

```sh
# Fast encrypted functional check: four length-16 jobs, one batch per arm.
# This is a smaller workload with correspondingly different parameter sizing.
python3 run.py --build-dir build --profile all --mode smoke --output results/smoke-001

# Full 16 x 256 clear-arithmetic adapter checks; no HE context is created.
python3 run.py --build-dir build --profile all --mode clear --output results/clear-001

# Full selected paper configurations: each setup performs a cold and a warm
# batch with fresh encryption. Three setups match each paper row's sample count.
python3 run.py --build-dir build --profile all --mode benchmark --setups 3 --output results/full-001
```

`--profile summed` and `--profile terminal` select individual primary arms; aliases `summed-bgv` and `terminal-bgv` are accepted. `--profile relay-bfv` explicitly selects the secondary raw-input relay. `--binary PATH` can replace `--build-dir DIR`. `--cpu N` selects a permitted logical CPU; the default is the lowest permitted CPU. The original experiments used CPU zero. Each subprocess is pinned to exactly one CPU, and thread-count environment variables are set to one. `--timeout` defaults to 900 seconds per subprocess.

| Selected profile | Ring dimension | Baby width | Actual switching | Main full-workload inventory |
| --- | ---: | ---: | --- | --- |
| Summed BGV | 16384 | 16 | HYBRID, FLEXIBLEAUTOEXT scaling | 2168 encryptions, 2040 products, 128 relinearizations, 120 rotations, 8 outputs |
| Terminal BGV | 32768 | 32 | HYBRID, FLEXIBLEAUTOEXT scaling; no executed relinearization or rotation | 1021 encryptions, 510 products, 511 outputs |

Both request `HEStd_128_classic` and use plaintext modulus 65537 with a 32-point exact bit-polynomial adapter. The inert `--bfv-key-switch BV` argument in historical BGV commands does **not** mean that BGV uses BV switching. `profiles/*.json` records the actual selected parameters, ciphertext and auxiliary primes, inventory, source receipt identity and expected outputs. Full benchmark mode checks these profile fields against the fresh result, permitting a different compiler version. It stops on drift rather than silently calling another parameter set the paper configuration.

## Inputs and output verification

`src/composition_fixture.h` is the original public C++ generator. `fixtures/composition_fixture.py` is its unchanged Python counterpart. The seed constructs test data only; it is never used as encryption randomness. The first two jobs contain zero and identity inner polynomials, and later jobs include nontrivial valuation and general coefficients.

```sh
python3 fixtures/composition_fixture.py
build/export_fixture results/new-fixture.bin
```

The binary input format is job-major `f_j` then `g_j`, 256 unsigned 16-bit little-endian symbols each. The output vector in `fixtures/expected-output.bin` is 4096 job-major symbols with SHA-256 `d22a60188ba884b10626ae52a2902f003cc2535294053979c417c39be68fbda3`. The runner checks every recovered coefficient against this preserved vector, in addition to the evaluator's independent Horner reference. Smoke-mode expected values are the corresponding truncations of that full vector, not newly selected inputs.

The evaluator records owner preparation, codec, encryption, evaluation, serialization and recipient phases. Complete times exclude fixture/reference generation, correctness validation, process startup and physical network transfer. Serialization writes to a counting sink; it measures encoded sizes and serialization computation, not network delivery. Warm work is the second fresh batch under the same setup. First-use summaries add the declared setup-phase subtotal to the first batch, matching the recorded OpenFHE convention. Phase medians need not add to a complete-work median.

This standalone runner executes the selected OpenFHE arms serially, reversing their order on alternate setups. It does not replay the original four-arm campaign or promise its latency values. Fresh validation results are separate from the preserved paper observations. A passing result establishes exact output agreement for its executed batches, not numerical security certification.

## Source and notices

The evaluator retains its original diagnostic schema and comments for source equivalence. The portable CMake file, runner and fixture exporter are release tooling. No operational command depends on the original research workspace. Original source paths in `PROVENANCE.json` are historical attribution only.

OpenFHE is an external BSD-2-Clause dependency; its [license at the pinned commit](https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/LICENSE) and submodule notices remain in the fetched checkout. No OpenFHE implementation source or linked binary is redistributed here. Existing notices in the copied project sources are preserved.
