# Reproduce the public fixed-field audit

From the repository root:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/fixed-field-count-audit-v1/verify_records.py
```

This recomputes finite public polynomial-function ranks, diagnostic failures, additive witnesses, point evaluations and all 57 schedule points. It rewrites only verification.json. It binds the preserved raw records and source files; it does not run encryption or a source estimator, establish a security level, or independently certify a universal proof.

To perform a separately named fresh public witness run, select an output path that does not exist:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/fixed-field-count-audit-v1/check_additive_witness.py --output SubmissionA/research/eurocrypt-readiness-2026-09-13/fixed-field-count-audit-v1/additive-witness-check-repeat.json
```

Do not overwrite the original diagnostic or execution records. The primary witness run binds its three source inputs before execution. The original Boolean screen is separately preserved and refuses to overwrite its output. The inline degree/pivot diagnostic outputs are reconstructed by the later reader; that reader is not retroactively described as their original executed source. See execution.json for actual observed return codes.
