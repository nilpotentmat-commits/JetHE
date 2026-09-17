# Reproduce the conditional one-prime admission

From the repository root:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/same-algebra-one-prime-v1/check_admission.py
```

The script uses integer/rational arithmetic, reads the existing certificate without importing cryptographic runtime modules, checks the prime/root and noise/centering/failure bounds, and writes admission.json. It retains the old deterministic one-prime failure and accounts for the projected source game and logical stopped-source budget. No private source words, encryption, benchmark or attack runs. PROOF.md identifies the existing tensor-row and raw-phase arguments used.

A one-prime receiver and timing campaign are not yet implemented here. Use a separate driver, complete fresh gates and new output directories; do not modify the executed two-prime sources or reinterpret their measurements.
