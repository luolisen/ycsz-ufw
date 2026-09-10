#!/usr/bin/env python3
"""Fetch the pinned Microsoft offline redistributable at build time only."""
import hashlib
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
NAME = 'NDP48-x86-x64-AllOS-ENU.exe'
URL = 'https://download.microsoft.com/download/f/3/a/f3a6af84-da23-40a5-8d1c-49cc10c8e76f/' + NAME
SHA256 = '0a3a390c47e639d0f7fc65b21195fee6b7f65b066f80f70c60fab191d14b7e40'

def verify(path):
    with path.open('rb') as stream:
        sha = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
        digest = sha.hexdigest()
    if digest != SHA256:
        raise RuntimeError('Microsoft .NET 4.8 SHA-256 mismatch: ' + str(path))

def main():
    path = ROOT / 'artifacts' / 'redist' / NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        temp = path.with_suffix('.tmp')
        try:
            with urllib.request.urlopen(URL, timeout=120) as response, temp.open('wb') as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
            verify(temp)
            temp.replace(path)
        finally:
            temp.unlink(missing_ok=True)
    verify(path)
    print('PASS pinned Microsoft .NET Framework 4.8: ' + SHA256)

if __name__ == '__main__':
    main()
