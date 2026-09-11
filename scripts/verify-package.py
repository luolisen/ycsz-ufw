#!/usr/bin/env python3
"""Verify the NSIS payload against this build, then assemble an offline handoff zip."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import tempfile
import zipfile

root = Path(__file__).resolve().parent.parent
artifacts = root / 'artifacts'
installer = artifacts / 'Ycsz-Setup-1.0.1-x64.exe'
sevenzip = shutil.which('7zz') or shutil.which('7z')
if not sevenzip:
    raise SystemExit('Install 7-Zip to verify NSIS contents.')
logs = []
def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, check=True)
    logs.append(result.stdout)
    return result
run(sevenzip, 't', str(installer))
expected = {
    'Ycsz-Client-Setup.exe': artifacts/'Ycsz-Client-Setup.exe',
    'Ycsz-Client-Setup-NoRuntime.exe': artifacts/'Ycsz-Client-Setup-NoRuntime.exe',
    'Ycsz.exe': artifacts/'app/Ycsz.exe',
    'Ycsz.Core.dll': artifacts/'app/Ycsz.Core.dll',
    'Ycsz.exe.config': artifacts/'app/Ycsz.exe.config',
    'System.ps1': root/'scripts/System.ps1',
    'README.md': root/'README.md',
    'TASK.md': root/'TASK.md',
    'PLAN.md': root/'PLAN.md',
    'docs/ARCHITECTURE.md': root/'docs/ARCHITECTURE.md',
    'docs/SECURITY-VALIDATION.md': root/'docs/SECURITY-VALIDATION.md',
}
with tempfile.TemporaryDirectory(prefix='ycsz-package-') as folder:
    run(sevenzip, 'x', str(installer), '-o'+folder, '-y')
    runtime=Path(folder)/'$PLUGINSDIR/net48-offline.exe'
    if hashlib.sha256(runtime.read_bytes()).hexdigest() != '0a3a390c47e639d0f7fc65b21195fee6b7f65b066f80f70c60fab191d14b7e40':
        raise SystemExit('Embedded .NET runtime mismatch')
    for name, source in expected.items():
        actual = Path(folder)/name
        left,right=actual.read_bytes(),source.read_bytes()
        if source.suffix.lower() in {'.md','.ps1','.config'}:
            left,right=left.replace(b'\r\n',b'\n'),right.replace(b'\r\n',b'\n')
        if left != right:
            raise SystemExit('Payload mismatch: '+name)
        logs.append('PASS payload matches build: '+name+'\n')
    if any((Path(folder)/name).exists() for name in ['SecurityProbe.exe','Ycsz.Tests.exe','TlsProbe.exe']):
        raise SystemExit('Test probe leaked into installer')
    if not (Path(folder)/'Uninstall.exe').exists():
        raise SystemExit('Uninstaller missing')
client=artifacts/'Ycsz-Client-Setup.exe'
run(sevenzip, 't', str(client))
with tempfile.TemporaryDirectory(prefix='ycsz-client-package-') as folder:
    run(sevenzip, 'x', str(client), '-o'+folder, '-y')
    runtime=Path(folder)/'$PLUGINSDIR/net48-offline.exe'
    if hashlib.sha256(runtime.read_bytes()).hexdigest() != '0a3a390c47e639d0f7fc65b21195fee6b7f65b066f80f70c60fab191d14b7e40':
        raise SystemExit('Client embedded .NET runtime mismatch')
    for name in ['Ycsz.exe','Ycsz.Core.dll','Ycsz.exe.config','System.ps1']:
        if (Path(folder)/name).read_bytes() != (artifacts/'app'/name).read_bytes():
            raise SystemExit('Client payload mismatch: '+name)
    if any((Path(folder)/name).exists() for name in ['SecurityProbe.exe','Ycsz.Tests.exe','TlsProbe.exe','Ycsz-Client-Setup.exe']):
        raise SystemExit('Unexpected nested installer/test fixture')
small_installers=[artifacts/'Ycsz-Setup-1.0.1-NoRuntime-x64.exe',artifacts/'Ycsz-Client-Setup-NoRuntime.exe']
for small in small_installers:
    run(sevenzip,'t',str(small))
    with tempfile.TemporaryDirectory(prefix='ycsz-no-runtime-') as folder:
        run(sevenzip,'x',str(small),'-o'+folder,'-y')
        base=Path(folder)
        if (base/'$PLUGINSDIR/net48-offline.exe').exists() or (base/'Ycsz-Client-Setup.exe').exists():
            raise SystemExit('Runtime leaked into runtime-free package')
        for name in ['Ycsz.exe','Ycsz.Core.dll','Ycsz.exe.config','System.ps1']:
            if (base/name).read_bytes() != (artifacts/'app'/name).read_bytes():
                raise SystemExit('Runtime-free application mismatch: '+name)
        if 'NoRuntime-x64' in small.name and (base/'Ycsz-Client-Setup-NoRuntime.exe').read_bytes() != small_installers[1].read_bytes():
            raise SystemExit('Runtime-free nested client mismatch')
logs.append('RESULT four NSIS packages verified; bundled and runtime-free payload comparisons passed (text CRLF/LF normalized). Windows execution evidence is recorded separately.\n')
(artifacts/'package-results.txt').write_text(''.join(logs), encoding='utf-8')

files = []
for directory in ['src', 'scripts', 'installer', 'docs', '.github']:
    files.extend(p for p in (root/directory).rglob('*') if p.is_file())
files.extend(root/name for name in ['README.md','TASK.md','PLAN.md','.gitignore'])
files.extend([installer,client]+small_installers)
files.extend(p for p in artifacts.iterdir() if p.is_file() and (p.suffix == '.txt' or p.name == 'SHA256SUMS'))
archive = artifacts/'Ycsz-1.0.1-delivery.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as out:
    for path in sorted(set(files)):
        out.write(path, str(Path('Ycsz-1.0.1')/path.relative_to(root)))
checks = ''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in [installer,client]+small_installers+[archive])
(artifacts/'DELIVERY-SHA256SUMS').write_text(checks,encoding='ascii')
print(logs[-1].strip())
print(checks,end='')
