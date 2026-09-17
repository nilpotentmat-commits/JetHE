# Reproduce the existing-control parameter screen

Run with standard Python from the repository root:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/conventional-parameter-repair-v1/check_repair.py
```

This reruns all 52,992 declared arithmetic policies. It evaluates the saved graph's sufficient recurrence, applies the four explicit geometric-model filters, records a canonical decision-stream hash, and independently recomputes selected state envelopes and complete costs. Exact rational threshold signs and the three-source character bound are checked. The output is `verification.json` in this directory.

The command runs no HE, lattice reduction, random-source sampling, timing campaign or new native compilation. It imports existing pure graph/analysis routines and reads the source-metric model; it does not import or alter the concurrently running encrypted receiver. Keep that receiver's original process and bound files intact. A passing screen supplies conditional parameter/cost witnesses, not security bits or a performance ordering.
