"""Process observations before the serial campaign; never exports arguments."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
def binding(p):return dict(bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest())
def stamp():return datetime.now(timezone.utc).isoformat()

if '--wsl-child' in sys.argv:
    workers=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name)==os.getpid():continue
        try:
            argv=(p/'cmdline').read_bytes().split(b'\0')
            executable=Path(argv[0].decode(errors='replace')).name if argv else ''
            if any(k in executable.lower() for k in ('python','sage','g++','clang','pdflatex','latexmk')) and str(ROOT).encode() in b' '.join(argv):
                workers.append(dict(pid=int(p.name),executable=executable))
        except (FileNotFoundError,ProcessLookupError,PermissionError):pass
    print(json.dumps(dict(recorded_utc=stamp(),observer_pid=os.getpid(),workers=workers,tool_exit_code=0,observer=binding(Path(__file__)),scope='WSL process-table observation; absolute workspace references only, relative paths can be missed. Not an exclusive-host guarantee.')))
else:
    script="$r=(Get-Location).Path; $items=@(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(python|sage|g\+\+|clang|pdflatex|latexmk)' -and $_.ProcessId -ne "+str(os.getpid())+" -and $_.CommandLine -like ('*'+$r+'*') } | Select-Object @{n='pid';e={$_.ProcessId}},@{n='executable';e={$_.Name}}); ConvertTo-Json -InputObject $items -Compress"
    a=subprocess.run(['powershell','-NoProfile','-Command',script],capture_output=True)
    assert a.returncode==0 and not a.stderr
    windows=dict(recorded_utc=stamp(),observer_pid=os.getpid(),workers=json.loads(a.stdout.decode('utf-8')),tool_exit_code=a.returncode,observer=binding(Path(__file__)),scope='Windows process-table observation of computing executables mentioning absolute workspace; relative paths can be missed. Not an exclusive-host guarantee.')
    relative=Path(__file__).resolve().relative_to(ROOT).as_posix()
    cmd=['wsl','--cd','/mnt/d/Users/scanf/OneDrive/Paper/NilCrypto/Submissions/NilHEoverRing','/usr/bin/python3','-B',relative,'--wsl-child']
    a=subprocess.run(cmd,capture_output=True)
    assert a.returncode==0
    wsl=json.loads(a.stdout.decode('utf-8'));wsl['launcher_stderr_bytes']=len(a.stderr)
    assert not windows['workers'] and not wsl['workers']
    with (HERE/'host-observation-v1.json').open('x') as f:json.dump(dict(windows=windows,wsl=wsl),f,indent=2);f.write('\n')
    print(json.dumps(dict(windows=windows,wsl=wsl)))
