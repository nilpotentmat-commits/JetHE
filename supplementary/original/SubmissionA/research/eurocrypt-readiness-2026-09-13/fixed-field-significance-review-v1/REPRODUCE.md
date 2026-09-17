# Reproduce the public arithmetic checks

From the workspace root, run:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/fixed-field-significance-review-v1/verify_records.py
```

The reader verifies the captured child exit, frozen proof/checker source hashes, output hashes, and reruns exact arithmetic in memory. It writes only verification.json. It does not run HE, regenerate manuscript tables, call a security estimator, download papers, or measure a fast backend.

The original command was run_check.py; its actual outer exit was zero, chunk 567bfd. It generated execution.json, arithmetic-check.json and captured stdout/stderr. Do not rerun it merely to refresh the receipt. The original proof, checker and runner are frozen after this execution. If their executed inputs need correction, preserve this run and use a new version.

The proof cites exact integer multiplication; Python's integer multiplication is used only to verify finite algebraic identities. Its implementation/runtime is not evidence for the asymptotic theorem. Byte-aligned digits in the checker are conservative supersets of the proof's widths.

retrieval.json records successful primary PDF downloads and SHA-256 hashes. Full downloaded texts, along with the two visually inspected Conrad first-page PNGs, support the source review. The other primary sources are linked directly in RESULTS.md and FAST_WORK_PROOF.md; only the actually downloaded documents have local retrieval records.
