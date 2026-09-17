"""Record a minimal WSL process observation before a controlled campaign."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    workers = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit() or int(directory.name) == os.getpid():
            continue
        try:
            words = [os.fsdecode(x) for x in (directory/'cmdline').read_bytes().split(b'\0') if x]
            if not words:
                continue
            executable = (directory/'exe').resolve(strict=True)
            cwd = (directory/'cwd').resolve(strict=True)
            in_workspace = executable.is_relative_to(ROOT) or any(str(ROOT) in x for x in words)
            computation = ('python' in executable.name or executable.is_relative_to(ROOT)) and cwd.is_relative_to(ROOT)
            if in_workspace or computation:
                workers.append(dict(pid=int(directory.name), executable=executable.name,
                                    workspace_executable=executable.is_relative_to(ROOT),
                                    workspace_cwd=cwd.is_relative_to(ROOT),
                                    scripts=[Path(x).name for x in words[1:] if x.endswith('.py')]))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    record = dict(recorded_utc=datetime.now(timezone.utc).isoformat(), observer_pid=os.getpid(),
                  workspace=str(ROOT), workers=workers,
                  scope='One WSL process-table observation, excluding this observer; includes native executables whose path or arguments identify this workspace. This is not a guarantee of exclusive host use.')
    print(json.dumps(record, indent=2))
    return bool(workers)


if __name__ == '__main__':
    raise SystemExit(main())
