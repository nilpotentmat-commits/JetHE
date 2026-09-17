# Receiver-kernel validation

Run from the repository root in Windows PowerShell. GMP is already installed in the Ubuntu WSL environment; the runner binds the actual loaded library. Python code requires only the standard library plus that system library.

```powershell
wsl -e python3 -B /mnt/d/Users/scanf/OneDrive/Paper/NilCrypto/Submissions/NilHEoverRing/SubmissionA/research/eurocrypt-readiness-2026-09-13/receiver-kernels-v1/check_kernels.py --output /mnt/d/Users/scanf/OneDrive/Paper/NilCrypto/Submissions/NilHEoverRing/SubmissionA/research/eurocrypt-readiness-2026-09-13/receiver-kernels-v1/local-replay.json
```

Use a new output name: the runner refuses to replace an existing receipt. Each complete execution samples new secrets, errors and masks. Digests and observed error maxima therefore need not equal the saved run. Secrets, plaintext-independent OS tapes and key material are not saved. The two coefficient/slot fixtures and the public diagonal mask are deterministic public test data, identified in the source.

`execution-v2.json` is the authoritative source-bound execution. It adds exact original-slot-order checks and a missing-identity negative case to the earlier `execution-v1.json`. The old `small-v1.json` and `execution-v1.json` are preserved as historical runs against earlier script bytes; they are not asserted to match the current source. `verify_receipt.py` checks the authoritative receipt and its current source bindings without executing encryption:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/receiver-kernels-v1/verify_receipt.py
```

The root revision verifier invokes that **recorded-execution readback**, not a fresh HE run. No controlled timing campaign is provided. Public-key setup, complete compiled maps, mask caching, six-output recovery and a matched security/performance comparison must still be implemented and assessed before claiming a complete-control benchmark.
