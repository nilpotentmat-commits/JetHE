"""Verify packaged source/fixture hashes without the development checkout."""
from pathlib import Path
from hashlib import sha256
import json
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if sys.flags.optimize:
        raise SystemExit('Python -O/-OO is unsupported; integrity assertions must be enabled.')
    provenance = json.loads((ROOT / 'provenance.json').read_text())
    verified = []
    for record in provenance['records']:
        path = (ROOT / record['release_file']).resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError('Source record escapes the package directory')
        assert path.stat().st_size == record['bytes'], record['release_file']
        assert sha256(path.read_bytes()).hexdigest() == record['sha256'], record['release_file']
        verified.append(record['release_file'])
    print(json.dumps({'status': 'PASS', 'source_and_fixture_records': len(verified),
                      'scope': 'package integrity against provenance; no HE run or security estimate'}, indent=2))


if __name__ == '__main__':
    main()
