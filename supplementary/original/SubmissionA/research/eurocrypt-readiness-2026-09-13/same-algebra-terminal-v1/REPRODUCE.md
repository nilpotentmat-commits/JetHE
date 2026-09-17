# Reproduce the native-algebra terminal control

Run from the repository root. Use native Python for recorded readback:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/same-algebra-terminal-v1/verify_receiver.py
```

Fresh execution requires Linux/WSL and the unchanged `jethe-throughput-redesign-2026-09-13/build/fast_core_v2.so` plus its recorded shared-library dependencies. The isolated interpolation kernel is built by `build.py` using `-O3 -std=c++17 -shared -fPIC`; the receipt binds compiler, source and binary hashes. It first uses `g++` on PATH, with the recorded local conda GCC path as fallback. Rebuilding can change the binary receipt and invalidate recorded run bindings; preserve the existing tree and perform rebuild/re-execution in a copied checkout when retaining these exact records matters.

In that copied Linux checkout, build the interpolation kernel and run `admission.py`. The latter verifies the two existing exact prime certificates, deterministic source/modulus inequality, all 16384 columns/point checks of the full interpolation map, smaller cases, and 16 independent polynomial-product cases. It generates no HE ciphertext.

```text
python3 -B same-algebra-terminal-v1/build.py
python3 -B same-algebra-terminal-v1/admission.py
python3 -B same-algebra-terminal-v1/run_receiver.py --mode preflight --output same-algebra-terminal-v1/preflight-fresh
python3 -B same-algebra-terminal-v1/run_receiver.py --mode full --output same-algebra-terminal-v1/full-fresh
```

The example paths are relative to `SubmissionA/research/eurocrypt-readiness-2026-09-13`; use absolute paths if invoking WSL from Windows. Output directories must be new direct children of the experiment directory. Existing results are never overwritten. The runner installs a 2 GiB address-space limit, 900 s CPU limit, zero core dumps and CPU-0 affinity before execution; a timeout or incomplete record is not a functional pass. `verify_receiver.py` currently validates the pinned `preflight-v1` and `full-v1` receipts; a new independent reproduction should retain its own input bindings and report its own outputs, rather than replacing these evidence files.

The native public tensor codec, two-prime cryptography, source law, fixture, paired owner preparation and Horner oracle are imported unchanged and bound in each run. Owner-local maps receive only that owner's input. The public evaluator function receives four ciphertexts and public context. All 346 input phases and 88 terminal phases are checked in the full diagnostic run. Raw three-component outputs are decrypted without relinearization. The recipient's private square is generated and charged once.

No measured ratio, 128-bit qualification, publication authority or recipient privacy follows from these commands. The diagnostic worker is not the eventual warm-workflow benchmark driver.
