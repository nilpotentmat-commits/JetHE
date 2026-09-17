# Reproduce the bilinear carrier checks

From the repository root:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/bilinear-carrier-audit-v1/check_carriers.py
```

The checker imports the existing finite-field rank checker unchanged, reads no private HE material, and writes `verification.json`. The written mixed-difference and Boolean-generator/Frobenius arguments are in `PROOF.md`. Scope is exact one-layer bilinear functional computation with fixed linear recovery and the explicit finite-field size conditions. The test is not a proof assistant, HE execution, timing benchmark or security estimate.
