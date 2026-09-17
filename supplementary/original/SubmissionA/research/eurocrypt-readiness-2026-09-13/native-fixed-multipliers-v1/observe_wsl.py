"""Read-only process snapshot before the serial campaign; emits no command lines."""
from datetime import datetime,timezone
import json,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
workers=[]
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit() or int(entry.name)==os.getpid():continue
    try:
        argv=(entry/'cmdline').read_bytes().split(b'\0')
        executable=Path(argv[0].decode(errors='replace')).name if argv else ''
        if any(k in executable.lower() for k in ('python','sage','g++','clang','pdflatex','latexmk')) and str(ROOT).encode() in b' '.join(argv):
            workers.append(dict(pid=int(entry.name),executable=executable))
    except (FileNotFoundError,ProcessLookupError,PermissionError):pass
record=dict(recorded_utc=datetime.now(timezone.utc).isoformat(),observer_pid=os.getpid(),workspace=str(ROOT),workers=workers,scope='Single WSL process-table snapshot of computing commands identifying this workspace; command arguments are not exported. Relative paths can be missed; this is not an exclusive-host guarantee.')
out=Path(__file__).resolve().parent/'host-wsl-v1.json'
with out.open('x') as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(record))
