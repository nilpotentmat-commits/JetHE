"""Verify every file listed in the release manifest; does not run experiments."""
from pathlib import Path, PurePosixPath
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def main():
    manifest = json.loads((ROOT / "release-manifest.json").read_text(encoding="utf-8"))
    seen = set()
    total = 0
    for entry in manifest["files"]:
        rel = PurePosixPath(entry["path"])
        if rel.is_absolute() or ".." in rel.parts or "\\" in entry["path"] or str(rel) in seen:
            raise ValueError(f"Invalid or duplicate manifest path: {rel}")
        seen.add(str(rel))
        path = (ROOT / Path(*rel.parts)).resolve()
        if not path.is_relative_to(ROOT.resolve()):
            raise ValueError(f"Manifest path escapes artifact: {rel}")
        data = path.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"Release file mismatch: {rel}")
        total += len(data)
    print(json.dumps({"status": "PASS", "files": len(seen), "bytes": total,
        "scope": "Listed release files; manifest itself and newly generated files are not checked",
        "fresh_HE_execution": False}, indent=2))


if __name__ == "__main__":
    main()
