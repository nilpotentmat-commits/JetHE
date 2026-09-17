# Reproduce the prepared-contraction audit

Run from the repository root:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/prepared-contraction-audit-v1/check_contraction.py
```

The checker expands small formal power coefficients, computes exact finite-field function ranks, checks the production Frobenius marker minor through all inverse-Frobenius candidates, and executes the paired contraction on the declared clear fixtures. It checks adverse small-field and omitted-correction cases. It uses no cryptographic coins, encryption, HE library or lattice estimator. A passing receipt corroborates the written model-specific proof; it is not a formal proof certificate or runtime/security evidence.

The terminal component ledger is algebraic. No concrete modulus or honest-noise admission is supplied in this checkpoint. In particular, the existing two-digit scaled-BFV receiver's correctness or timings must not be transferred to this proposed direct terminal route. Its live inputs remain untouched.
