# Reproduce the ciphertext-length boundary checks

From the workspace root:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/ciphertext-length-audit-v1/verify_records.py
```

This verifies the original child exit, frozen proof/checker/runner hashes, captured outputs and downloaded primary source hashes. It recomputes the finite examples in memory and writes only verification.json. It does not execute HE, regenerate keys, measure timing, call an estimator or download sources.

The original run_check.py execution exits zero, chunk 404de1. Its three executed inputs are frozen; a correction to them requires preservation and a new run/version. The finite tests guard the hypotheses of the written proof and do not establish a general complexity or cryptographic-security theorem by enumeration. The projected-pad example is one-time only.

retrieval.json binds the successful source retrieval, exit zero 8e777c. The author's PDF versions and SEAL source snapshot are the inspected files; published metadata is linked in RESULTS.md. No independently executed FLS implementation or compressed JetHE candidate is claimed.
