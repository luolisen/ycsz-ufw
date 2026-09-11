#!/usr/bin/env python3
"""Compile extracted production lifecycle functions against portable test shims.
No driver compilation, installation or Windows integration is performed.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
driver = repo / 'drivers/YcszProtection'
source = (driver / 'ycsz_protection.c').read_text()
filter_source = (driver / 'ycsz_minifilter.c').read_text()

def extract(name):
    marker = '\n' + name + '('
    start = source.index(marker) + 1
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    # The first occurrence may be a forward declaration. Select the definition.
    if ';' in source[start:opening]:
        start = source.index(marker, start) + 1
        opening = source.index('{', start)
        depth, end = 1, opening + 1
        while depth:
            depth += (source[end] == '{') - (source[end] == '}')
            end += 1
    return 'static NTSTATUS\n' + source[start:end] + '\n'

def extract_filter_boolean(name):
    marker = '\n' + name + '('
    start = filter_source.index(marker) + 1
    opening = filter_source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        if filter_source[end] == '{':
            depth += 1
        elif filter_source[end] == '}':
            depth -= 1
        end += 1
    return 'static BOOLEAN\n' + filter_source[start:end] + '\n'

with tempfile.TemporaryDirectory(prefix='ycsz-control-test-') as tmp:
    work = Path(tmp)
    (work / 'control_lifecycle_extracted.inc').write_text(
        extract('YcpCreateClose') + extract('YcpFilterUnloadAuthorized'))
    shutil.copy2(driver / 'tests/control_lifecycle.c', work)
    (work / 'stream_context_extracted.inc').write_text(
        extract_filter_boolean('YcpAttachProtectedStreamContext'))
    shutil.copy2(driver / 'tests/stream_context_lifecycle.c', work)
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror',
                              str(work / 'control_lifecycle.c'), '-o', str(work / 'test')], check=True)
    subprocess.run([str(work / 'test')], check=True)
    subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror',
                              str(work / 'stream_context_lifecycle.c'), '-o', str(work / 'stream-test')], check=True)
    subprocess.run([str(work / 'stream-test')], check=True)
