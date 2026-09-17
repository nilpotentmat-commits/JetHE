# Reproduce the direct current/control evidence

The recorded preflight and campaign are immutable. From this directory, `python -B verify_records.py` checks current repository bytes and rederives every reported statistic from the complete worker records. It does not rerun encryption or rehash external Linux system libraries from Windows.

The completed execution commands, actual return codes and launcher stdout/stderr are retained in gate-execution.json and campaign-execution.json. Each child has its own separate stdout, empty stderr and actual zero exit code; the WSL launcher warning is retained separately. See PLAN.md for the frozen order, costs, limits and interpretation.

To perform a new encrypted reproduction, use a separate versioned directory and update the explicit driver path assertion and source bindings before a new preflight. Preserve the recorded directory. Under WSL, use `/usr/bin/python3 -B -u preflight.py`, then `run.py --mode gate --out <new-dir>/gate-v1`. Capture fresh Windows/WSL process observations with observe.py and run `run.py --mode measure --out <new-dir>/campaign-v1 --gate <new-dir>/gate-v1 --host-observation <new-dir>/host-observation-v1.json`. All commands use the workspace working directory or equivalent absolute paths. The scripts refuse to overwrite the preflight or campaign directories.

The implementation depends on the exact repository source catalogue and pre-existing shared libraries identified by the manifests. `native-fixed-multipliers-v1/prepare.py` and its immutable build.json record the compiler and build command. The campaign uses the same fixed_core.so arithmetic binary for both arms, with independent keys and encryption coins. Startup and source-manifest processing are outside algorithm timing; key/context construction, sampling, conversion, serialization, owners, evaluator and recipient remain charged as specified. A new environment can yield different times.

No execution of this package supplies a numerical security certificate, a proof assistant check, or an independent optimized conventional implementation. The Gaussian asymptotic theorem is a separate profile.
