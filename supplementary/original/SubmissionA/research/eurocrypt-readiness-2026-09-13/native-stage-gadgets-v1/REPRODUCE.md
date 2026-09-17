# Reproduce stage-gadget evidence

From the workspace root, `python -B SubmissionA/research/eurocrypt-readiness-2026-09-13/native-stage-gadgets-v1/verify_records.py` checks completed gate/campaign records, all output checks and current source bindings. It does not replay secrets, rerun HE or rehash current external system libraries. Actual workers checked runtime libraries before and after their runs.

Fresh Linux/WSL execution from this directory uses new direct-child directories:

```text
python3 -B run.py --mode gate --out gate-v2
python3 -B run.py --mode measure --gate gate-v2 --host-observation host-observation-v2.json --out campaign-v2
```

The host file must contain actual Windows and WSL observations with workers=[], tool_exit_code=0 and recorded_utc no more than five minutes old. Preserve all observations/failures and their scope; do not fabricate or reuse stale timestamps. The measurement supervisor requires both gates and identical source/runtime manifests. WORKFLOW_PLAN.md specifies order, limits and charged costs.

The independent stage implementation consists of stage_binding.py, stage_crypto.py, stage_public.py, bounds.py and build/stage_core.so. Its admission and public-boundary receipts precede the fresh gates. Do not alter these files or rerun prepare.py over bound outputs; a changed implementation needs a separate version and fresh gates. The single initial wrapper import failure occurred before encrypted execution and is preserved in PREFLIGHT_FAILURES.md.
