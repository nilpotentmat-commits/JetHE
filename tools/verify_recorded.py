"""Recompute the paper's recorded tables; does not run homomorphic encryption."""
from pathlib import Path
import csv, hashlib, json, statistics, subprocess, sys, tempfile, zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    if not __debug__:
        raise RuntimeError("Run with assertions enabled; Python -O/-OO is not supported")
    rows = list(csv.DictReader((ROOT / "recorded/measurements.csv").open(encoding="utf-8")))
    evidence = json.loads((ROOT / "recorded/benchmark-verification.json").read_text(encoding="utf-8"))
    index = json.loads((ROOT / "recorded/receipt-index.json").read_text(encoding="utf-8"))
    assert len(rows) == 40 and len(index) == 20
    expected = (ROOT / "recorded/expected-output.bin").read_bytes()
    digest = hashlib.sha256(expected).hexdigest()
    assert len(expected) == 8192 and all(r["output_sha256"] == digest for r in rows)
    for item in index:
        assert hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest() == item["sha256"]
    assert {r["receipt_sha256"] for r in rows} == {i["sha256"] for i in index}
    names = {
        ("shared_backend_composition", "native"): "JetHE-102",
        ("shared_backend_composition", "control"): "One-prime control",
        ("openfhe_composition", "native"): "JetHE-149",
        ("openfhe_composition", "summed-bsgs"): "OpenFHE summed BGV",
        ("openfhe_composition", "terminal-products"): "OpenFHE terminal BGV",
    }
    summaries = {}
    for (campaign, arm), name in names.items():
        warm = [r for r in rows if r["campaign"] == campaign and r["arm"] == arm and r["state"] == "warm"]
        measured = evidence["statistics"][name]
        assert len(warm) == measured["n"]
        summary = {}
        for field, archived in measured.items():
            if field == "n": continue
            values = [float(r[field]) for r in warm]
            actual = {"median": statistics.median(values), "min": min(values), "max": max(values)}
            for statistic, value in actual.items():
                assert abs(value - archived[statistic]) <= max(1e-12, 1e-12 * abs(value)), (name, field, statistic)
            summary[field] = actual
        summaries[name] = summary
    # Exercise the unchanged paper checker in a temporary standalone extraction.
    with tempfile.TemporaryDirectory(prefix="jethe-paper-check-") as temp:
        extracted = Path(temp)
        with zipfile.ZipFile(ROOT / "paper/JetHE-source.zip") as archive:
            assert all((extracted / n).resolve().is_relative_to(extracted.resolve()) for n in archive.namelist())
            archive.extractall(extracted)
        for name in ["measurements.csv", "admission.json", "expected-output.bin", "benchmark-verification.json"]:
            assert (extracted / "evidence" / name).read_bytes() == (ROOT / "recorded" / name).read_bytes()
        check = subprocess.run([sys.executable, "evidence/verify_artifact.py"], cwd=extracted, capture_output=True, text=True)
        assert check.returncode == 0, check.stdout + check.stderr
        paper_check = json.loads(check.stdout)
    print(json.dumps({"status": "PASS", "recorded_rows": len(rows), "verified_receipts": len(index),
        "output_sha256": digest, "table_4_warm_medians": {n: x["seconds"]["median"] for n,x in summaries.items()},
        "paper_check": paper_check, "fresh_HE_execution": False}, indent=2))

if __name__ == "__main__":
    main()
