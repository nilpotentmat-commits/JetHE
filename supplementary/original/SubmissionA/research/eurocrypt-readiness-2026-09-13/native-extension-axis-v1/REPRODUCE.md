# Reproducing the extension-axis experiment

This experiment compares the current 102-row tensor-axis baseline with an isolated implementation that batches the extension-axis transforms. It changes no source law, gadget schedule, ciphertext interface or encryption equation. It is not an OpenFHE comparison or a security-matched comparison with the older conventional control.

The exact compiler, command and input hashes are in `build.json`. The build uses C++17, `-O3`, `-DNDEBUG`, `-fPIC` and `-shared`, with no architecture target. The baseline files remain frozen. `prepare.py` copies those files into this directory and replaces only the extension transform lambda, then derives the corresponding bindings and worker. Do not rerun it over the completed build.

`check_candidate.py` checks canonical arithmetic against integer and baseline oracles, all relative lengths, sparse direct evaluations, the affected exported operations and deterministic public-coin encryption. Its kernel samples are a descriptive screen; they are not fresh secret encryptions or complete-workflow measurements. The threshold and workload order were declared in PLAN.md and WORKFLOW_PLAN.md before execution.

Fresh runs use WSL Ubuntu, CPU 0, one thread, 2 GiB address space, 180 CPU seconds and a 210-second wall limit per worker. The launcher uses the following environment and arguments, with absolute paths:

```text
env PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1 python3 -B <directory>/run.py --mode gate --out <directory>/gate-v1
env PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1 python3 -B <directory>/run.py --mode measure --gate <directory>/gate-v1 --host-observation <directory>/host-observation-v1.json --out <directory>/campaign-v1
```

The supervisor rejects existing output directories and host observations older than five minutes. Windows and WSL observations omit command-line contents and cannot guarantee exclusive host use. The inherited WSL launcher warning concerns its localhost/proxy environment; child stderr is checked separately. A justified replication needs a new evidence directory and its own fresh gates and observations. Do not overwrite the recorded campaign or alter its source bindings.

Run the portable reader from the repository root after the campaign has completed:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/native-extension-axis-v1/verify_records.py
```

The reader checks the 140 executed workspace bindings, equality of thirteen recorded runtime bindings, actual child exits, stdout/result agreement, all phase and output counts, every sample and the descriptive medians. It does not rerun HE, recover secret randomness or rehash external Linux libraries from Windows. Its result has `new_he_execution=false`, even though the original gates and campaign execute fresh encryption. Actual outer tool exits are retained separately in execution.json.

All local setup and batch costs listed in WORKFLOW_PLAN.md are charged. Process imports/startup, public fixture/oracle construction, diagnostics and physical network transport have the same exclusions in both arms. Keep complete warm time, first-use time, individual phases and RSS distinct. No ratio is multiplied into an earlier campaign, and no global optimum or scientific-readiness conclusion is inferred.
