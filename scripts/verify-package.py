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
installer = artifacts / 'Ycsz-Setup-0.2.0-x64.exe'
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
    for name, source in expected.items():
        actual = Path(folder)/name
        if actual.read_bytes() != source.read_bytes():
            raise SystemExit('Payload mismatch: '+name)
        logs.append('PASS payload matches build: '+name+'\n')
    if not (Path(folder)/'Uninstall.exe').exists():
        raise SystemExit('Uninstaller missing')
logs.append('RESULT NSIS CRC/decompression and 10 payload comparisons passed; installer was NOT executed on Windows.\n')
(artifacts/'package-results.txt').write_text(''.join(logs), encoding='utf-8')

files = []
for directory in ['src', 'scripts', 'installer', 'docs', '.github']:
    files.extend(p for p in (root/directory).rglob('*') if p.is_file())
files.extend(root/name for name in ['README.md','TASK.md','PLAN.md','.gitignore'])
files.append(installer)
files.extend(p for p in artifacts.iterdir() if p.is_file() and (p.suffix == '.txt' or p.name == 'SHA256SUMS'))
archive = artifacts/'Ycsz-0.2.0-delivery.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as out:
    for path in sorted(set(files)):
        out.write(path, str(Path('Ycsz-0.2.0')/path.relative_to(root)))
checks = ''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in [installer,archive])
(artifacts/'DELIVERY-SHA256SUMS').write_text(checks,encoding='ascii')
print(logs[-1].strip())
print(checks,end='')
