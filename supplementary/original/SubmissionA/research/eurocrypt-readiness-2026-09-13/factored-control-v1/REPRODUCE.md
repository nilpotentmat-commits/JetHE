# Reproduce the padded-CRT trial

Run from the workspace root with Python and the existing native public coefficient-Horner library. Windows uses `composition_native_core.dll`; Linux uses the existing optimized public library. These are plaintext oracles. No HE library, cryptographic key generation or encryption is invoked.

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/factored-control-v1/verify_control.py
```

This regenerates all field matrices and five complete public graphs, checks physical routes and fixture outputs, reconstructs the BSGS/dependency contracts, and independently evaluates the selected sufficient bounds using rational arithmetic. It rewrites only this trial's `verification.json`. It validates the source-bound recorded grid decisions; it does not repeat the exhaustive grid.

To rerun one full graph and finite parameter screen, choose a fresh output name in this directory. Existing files are rejected rather than overwritten:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/factored-control-v1/compile_control.py --width 16 --search --output SubmissionA/research/eurocrypt-readiness-2026-09-13/factored-control-v1/width16-fresh.json
```

Repeat for widths 1,2,4,8 for the other four recorded policies. Each screen contains 51,300 policies; source hashes and the exact decision-stream digest bind it. The verifier reads the original `width1.json` through `width16.json` names; compare a fresh record explicitly before changing any authoritative record. Earlier project manuscripts and evidence are read-only.

The source imports frozen field/graph/noise helpers without invoking their main functions. Receipts bind every imported workspace Python module and the public Horner library. Field inputs are the public fixed correctness fixture, never crypto coins. The code initially exposed and repaired a missing field-Frobenius helper before writing any receipt. The first verifier attempt also repaired JSON key-order normalization; it did not change a mathematical or numerical result.
