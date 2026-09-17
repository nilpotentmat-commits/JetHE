# Reproduce the exact-law projection audit

From the workspace root:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/source-projections-v1/check_projections.py
```

Only Python's standard library is needed. The script reads the current source-scope receipt and frozen prime/sampler declarations. It verifies exact prime certificates and root orders, certifies the TV exponents with integer powers and rational constants, checks small-ring norms using Bareiss determinants, validates public spectral-support fixtures, and computes the adverse rank-four distribution by exact integer convolution. It writes only this directory's `verification.json`.

The public fixture PRNG has a fixed seed and never supplies cryptographic coins. The source implementation is read and hashed; it is not executed. The small fixture tests and full-size spectral checks are corroborating evidence for the separate universal proof, not exhaustive enumeration of production characters. The manuscript must retain the exact observation restrictions from [PROOF.md](PROOF.md).
