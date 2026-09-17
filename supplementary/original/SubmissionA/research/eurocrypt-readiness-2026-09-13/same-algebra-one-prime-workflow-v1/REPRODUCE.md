# One-prime driver validation and controlled workflow

The archived preflight, both fresh gates and the six-setup campaign have completed successfully. To read back the existing evidence without new encryption, run `python -B verify_workflow.py --campaign campaign-v1`; generate manuscript tables with `python -B report_campaign.py`.

For a fresh reproduction, use Linux/WSL with the already installed libraries. From this directory, first run the public preflight once, then fresh gates in a new output directory:

```text
python3 -B check_driver.py
python3 -B supervise.py --mode gate --out gate-v2
```

The preflight writes exclusively to preflight.json and draws no private source. Gate mode executes fresh encryption and verifies every state. Preserve failures; a correction requires a distinct version/directory and new gates. Do not invoke worker.py directly.

After gates pass, record fresh Windows and WSL workspace-worker observations. check_host_workers.py emits the WSL record, including native workspace executables. Store both records under keys windows and wsl in a new host-observation JSON, each with workers=[], tool_exit_code=0 and its actual recorded_utc. Do not manufacture those observations. The supervisor requires their timestamps to precede launch by at most five minutes, checks its Python-worker prerequisite, and copies the supplied observations into the new campaign directory.

```text
python3 -B supervise.py --mode campaign --gate gate-v2 --host-observation host-observation-v2.json --out campaign-v2
python3 -B verify_workflow.py --gate gate-v2 --campaign campaign-v2
```

The same commands with new direct-child gate/campaign directories and a fresh host observation reproduce another campaign. All six setups, cold/warm batches and failures are retained. CPU-0/single-thread affinity, address-space and CPU/wall/output limits are installed by the supervisor. Observation timeouts are not process termination. Readback checks actual records and repository bindings without fresh encryption or rehashing current external runtime libraries. No cross-campaign ratio, source-hardness or scientific-readiness conclusion follows.
