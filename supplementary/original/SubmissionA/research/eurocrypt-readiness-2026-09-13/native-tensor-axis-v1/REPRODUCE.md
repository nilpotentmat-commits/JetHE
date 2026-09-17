# Reproducing the tensor-axis evidence

This directory freezes the completed native implementation experiment. The comparator is the previous 102-row stage-gadget implementation; both arms use the same widths, source laws, randomness accounting and workflow. It is not an OpenFHE campaign or a new comparison with the older 134-row conventional control.

Run the portable record reader from the repository root:

```powershell
python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/native-tensor-axis-v1/verify_records.py
```

The reader checks all 124 current execution source bindings, the equality of twelve recorded runtime bindings across the gates and campaign, stdout/result agreement, child exits, phase counts, all output checks and every descriptive statistic. It does not replay unretained secret randomness or rehash external Linux libraries from Windows. Its `new_he_execution` field is false.

The actual build used the compiler and exact arguments in `build.json`. `prepare.py` makes an isolated copy of the stage backend and changes only the native first-axis transform. The public arithmetic screen in `public-check.json` covers all relative transform lengths, independent sparse evaluation, the exported arithmetic operations and deterministic public encryption inputs. Its six kernel blocks are a screen, not fresh secret encryption evidence.

`gate-v1` contains two fresh encrypted phase checks; `campaign-v1` contains eight fresh setups and sixteen measured batches in the order declared before execution in `WORKFLOW_PLAN.md`. Each worker records its command, actual exit, complete stdout, stderr and source/runtime bindings. `execution.json` records the outer tool evidence separately. The gate's completed summary and both child exit records survive, although the outer gate handle was no longer available after context recovery; no outer gate exit is invented.

The fresh invocations ran under WSL Ubuntu with these settings:

```text
env PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1 python3 -B <absolute-path>/run.py --mode gate --out <absolute-path>/gate-v1
env PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1 python3 -B <absolute-path>/run.py --mode measure --gate <absolute-path>/gate-v1 --host-observation <absolute-path>/host-observation-v1.json --out <absolute-path>/campaign-v1
```

Those exact output directories already exist and must not be overwritten. To conduct a justified independent replication, use a new evidence directory, repeat the public checks and fresh gates, and retain current Windows/WSL observations before launching the balanced campaign. The supervisor rejects existing output directories and observations older than five minutes. Do not change the frozen sources or rebuild the frozen library in place; a changed implementation requires a new version and bindings.

Each serial worker uses CPU 0, one thread, a 2 GiB address-space cap, 180 CPU seconds and a 210-second supervisor wall limit. The outer WSL launcher emitted its existing localhost/proxy warning; child stderr files must remain empty. Host observations are snapshots and do not establish exclusive host use.

The charged boundary includes setup context/codecs, key and hint generation, recipient preparation and public serialization. Each batch includes owner preparation, encoding, fresh encryption, serialization to the common counting sink, evaluation and recipient recovery. Process startup/import, public fixture/oracle generation and checking, post-batch teardown and physical network transport are excluded in both arms. All measured samples remain in `RESULTS.md`; no cross-campaign ratio or security certification is inferred.
