# Reproduce the complete-record audit

From the repository root, prepare the public contract with WSL Python and the same installed GMP used by the receiver:

```powershell
wsl -e python3 -B /mnt/d/Users/scanf/OneDrive/Paper/NilCrypto/Submissions/NilHEoverRing/SubmissionA/research/eurocrypt-readiness-2026-09-13/complete-receiver-audit-v1/check_complete.py --prepare
```

This encodes public expected states, derives operation/source counts and writes `contract.json`. It draws no cryptographic source words. The successful isolated-map record supplies a cross-check of six public carrier hashes. This is preparation of acceptance conditions, not a successful full execution.

After the existing complete process exits successfully, audit its actual final record:

```powershell
wsl -e python3 -B /mnt/d/Users/scanf/OneDrive/Paper/NilCrypto/Submissions/NilHEoverRing/SubmissionA/research/eurocrypt-readiness-2026-09-13/complete-receiver-audit-v1/check_complete.py --verify complete-v1
```

A missing `execution.json` produces `FINAL_EXECUTION_RECORD_UNAVAILABLE` and exit code 2, without writing a verification receipt or asserting process liveness. A `failure.json`, a preflight result or inconsistent final data is rejected. The existing session handle remains the authority for polling the active invocation. Do not restart a live run because this readback is pending.

An accepted final record writes `verification.json` here. The checker does not decrypt ciphertexts anew: the functional runner checked secrets and ciphertexts in memory and did not retain them. It verifies the recorded checks against independently reconstructed public expectations and current source/library bindings. No synthetic successful HE record is generated. This remains a diagnostic functional audit, with no warm-workflow or security ranking.
