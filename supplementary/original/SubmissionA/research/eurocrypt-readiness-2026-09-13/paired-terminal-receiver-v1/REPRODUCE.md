# Reproduce the direct paired terminal receiver

Run from the repository root. Preserve existing output directories and source-bound inputs. The completed runs' 30 exact dependencies, including their proof checkpoint, are preserved at `SubmissionA/research/paired-src-v1`. The current manuscript's receiver-status text has since changed. Use the snapshot for exact fresh reexecution; its manifest is `source-snapshot.json`.

Read back the completed preflight and full records, without new encryption:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/paired-terminal-receiver-v1/verify_receiver.py
```

The integer admission and prefix-table checks are reproducible with native Python from the snapshot:

```powershell
python -B SubmissionA/research/paired-src-v1/SubmissionA/research/eurocrypt-readiness-2026-09-13/paired-terminal-receiver-v1/admission.py
python -B SubmissionA/research/paired-src-v1/SubmissionA/research/eurocrypt-readiness-2026-09-13/paired-terminal-receiver-v1/build_prefix.py
```

The latter regenerates the exact 33,685,524-byte lookup and its mass-check receipt; it does not draw cryptographic vectors. Do not regenerate or edit any bound input during an actual receiver invocation.

For **new encryption**, use WSL with Python and installed GMP. The scripts use `os.urandom`; the deterministic public fixture never supplies encryption coins. Choose new direct-child output names, since existing directories are refused:

```powershell
$pairedArchive = '/mnt/d/Users/scanf/OneDrive/Paper/NilCrypto/Submissions/NilHEoverRing/SubmissionA/research/paired-src-v1/SubmissionA/research/eurocrypt-readiness-2026-09-13/paired-terminal-receiver-v1'
wsl -e python3 -B "$pairedArchive/run_receiver.py" --mode preflight --output "$pairedArchive/preflight-v2"
wsl -e python3 -B "$pairedArchive/run_receiver.py" --mode full --output "$pairedArchive/full-v2"
```

Run the full workload after the new preflight succeeds. Each invocation enforces a 2 GiB address-space limit, hashes its actual local dependencies before and after, and writes progress, recovered public fixture words and a final record. A failure produces `failure.json` and a nonzero process exit. Completion requires both the actual exit and final result; elapsed time is not evidence of success. Secret keys, source coins and serialized ciphertext bodies are not retained. Counting hash sinks do perform serialization, but do not implement network transport.

To check different completed names:

```powershell
$pairedArchiveWindows = (Resolve-Path 'SubmissionA/research/paired-src-v1/SubmissionA/research/eurocrypt-readiness-2026-09-13/paired-terminal-receiver-v1').Path
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/paired-terminal-receiver-v1/verify_receiver.py --preflight "$pairedArchiveWindows/preflight-v2" --run "$pairedArchiveWindows/full-v2"
```

This writes the local verification receipt for those records. Changing this selection changes the aggregate evidence binding; keep the v1 record set for reproducing the current manuscript. The verifier pins the recorded GMP version and binary digest; another backend requires explicit revalidation rather than silently accepting it as the same implementation.

The proof and arithmetic admit the exact finite source conditionally; neither successful invocation nor checker supplies security bits, recipient privacy or a matched-performance campaign. Read [RESULTS.md](RESULTS.md) for included phases, excluded preprocessing and concurrency limits. The longer `compiled-receiver-v1` job is a distinct construction and process; do not restart it to run this script.
