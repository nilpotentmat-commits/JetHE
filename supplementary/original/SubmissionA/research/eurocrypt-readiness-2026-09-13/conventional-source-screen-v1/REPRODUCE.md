# Reproduce the concrete source-model screen

From the repository root with standard Python:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/conventional-source-screen-v1/check_screen.py
```

The script recomputes two exact-parameter model points, rational threshold enclosures, independent high-precision cost values and the conditional helper-disclosure cap. It writes `verification.json` in this directory. It reads and hashes the listed inputs without executing the compiled receiver, sampling new keys, importing Sage, constructing a lattice basis or changing any input of the live full-graph process.

The pinned historical pricing module is imported only for its pure numerical formulas. Downloaded estimator files are hash-checked and never executed. A passing receipt validates these scoped calculations, not an attack, source hardness, matching security or EUROCRYPT readiness. The live receiver outcome must be read from its own process and final receipt.
