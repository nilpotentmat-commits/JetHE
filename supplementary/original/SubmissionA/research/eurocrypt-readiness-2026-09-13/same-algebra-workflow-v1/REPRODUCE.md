# Reproduce the shared workflow gates and campaign

From the repository root, recorded gate readback is portable:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/same-algebra-workflow-v1/verify_workflow.py
```

The completed six-setup campaign and generated manuscript tables use:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/same-algebra-workflow-v1/verify_workflow.py --campaign SubmissionA/research/eurocrypt-readiness-2026-09-13/same-algebra-workflow-v1/campaign-v1
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/same-algebra-workflow-v1/report_campaign.py
```

Both commands are recorded-data processing, not fresh encryption. The campaign supervisor actually exited zero in tool session 25232. The supplemental Windows/WSL pre-launch observations are retained in `host-observation-v1.json`; `check_host_workers.py` reproduces the WSL observation, including native workspace executables. It is a point-in-time check, not a guarantee that the host remains idle.

Fresh execution uses Linux/WSL with the preserved arithmetic libraries and dependencies. From `SubmissionA/research/eurocrypt-readiness-2026-09-13`:

```text
python3 -B same-algebra-workflow-v1/supervise.py --mode gate --out same-algebra-workflow-v1/gate-fresh
python3 -B same-algebra-workflow-v1/supervise.py --mode campaign --gate same-algebra-workflow-v1/gate-fresh --out same-algebra-workflow-v1/campaign-fresh
```

Directories must be new direct children of the harness directory. Do not invoke workers directly. The supervisor installs CPU-0 affinity, single-thread environment variables, 2 GiB address-space and 900 s CPU limits; its declared wall/output limits can terminate a worker and preserve a failure receipt. A tool observation timeout alone is not an execution failure and never authorizes a duplicate run.

Campaign mode requires successful gates for the exact same 63-file source manifest and runtime binaries. It also checks that no other Linux research worker is live and requires the existing complete receiver's actual audited final record. Check Windows research processes and host load separately before starting the campaign; routine OS background activity is not claimed absent. The environment file records the CPU, load, limits and prerequisite evidence. All samples use exclusive receipts, explicit exit codes and complete stdout/stderr bindings.

After a completed campaign, run:

```text
python -B same-algebra-workflow-v1/verify_workflow.py --gate same-algebra-workflow-v1/gate-fresh --campaign same-algebra-workflow-v1/campaign-fresh
```

The checker recomputes every sample count, median, range and reported ratio. The default command verifies the pinned gates only and cannot promote them to a timing result. Any change to the plan, driver, imported cryptographic source, admission or binary invalidates the old gates; preserve them and create a new versioned gate/campaign if changes are needed. Editing presentation-only files or the standalone readback checker does not change the executed driver, but their latest versions are separately bound by the readback receipt.
