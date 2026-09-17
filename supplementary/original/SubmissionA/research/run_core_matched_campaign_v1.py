"""Execute the predeclared matched order; preserve every sample and stop on ERROR."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import supervise_core_matched_v1 as supervisor


if __name__ == "__main__":
    assert __debug__ and len(sys.argv) == 1
    current, rows = supervisor.manifest(), []
    destination = supervisor.PAPER / "evidence/core-matched-campaign-v1.json"
    assert not destination.exists(), "Never replace the completed campaign"
    for item in supervisor.schedule():
        path = supervisor.receipt_path(item)
        if not path.exists():
            result = subprocess.run([sys.executable,"-B",str(supervisor.HERE / "supervise_core_matched_v1.py"),
                                     str(item["index"])],check=False)
            if result.returncode:
                raise RuntimeError(f"Retained timing error at {path}; no automatic replay")
        record = json.loads(path.read_text())
        assert record["source_manifest"] == current and record["sources_unchanged"]
        assert record["schedule_item"] == item and record["status"] != "ERROR"
        rows.append(dict(item=item,status=record["status"],receipt=path.relative_to(supervisor.ROOT).as_posix(),
                         sha256=sha256(path.read_bytes()).hexdigest()))
    result = dict(schema="core-matched-campaign-v1", status="COMPLETE" if all(r["status"] == "PASS" for r in rows)
                  else "COMPLETE_WITH_FAILED_SAMPLES", samples=rows, source_manifest=current,
                  scheduler_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
                  benchmark=True, security_128_qualified=False, manuscript_complete=False)
    with destination.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2)
        stream.write("\n")
    print(json.dumps(dict(status=result["status"],samples=len(rows),path=destination.relative_to(supervisor.ROOT).as_posix(),
                         sha256=sha256(destination.read_bytes()).hexdigest())),flush=True)
