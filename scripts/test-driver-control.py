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

def extract(name, return_type="NTSTATUS"):
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
    return 'static '+return_type+'\n' + source[start:end] + '\n'

def extract_filter_boolean(name, return_type="BOOLEAN"):
    marker = '\n' + name + '('
    start = filter_source.index(marker) + 1
    opening = filter_source.index('{', start)
    while ';' in filter_source[start:opening]:
        start = filter_source.index(marker, start) + 1
        opening = filter_source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        if filter_source[end] == '{':
            depth += 1
        elif filter_source[end] == '}':
            depth -= 1
        end += 1
    return 'static '+return_type+'\n' + filter_source[start:end] + '\n'

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

    (work / 'precreate_extracted.inc').write_text(
        extract_filter_boolean('YcpCreateChangesNamespace') +
        extract_filter_boolean('YcpTrustedNamespaceMutationAllowed') +
        extract_filter_boolean('YcpPreOperationFile','FLT_PREOP_CALLBACK_STATUS'))
    shutil.copy2(driver / 'tests/precreate_dispatch.c', work)
    subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror',
                              str(work / 'precreate_dispatch.c'), '-o', str(work / 'precreate-test')], check=True)
    subprocess.run([str(work / 'precreate-test')], check=True)

    (work / 'namespace_extracted.inc').write_text(
        extract('YcpPathHasBoundaryPrefix','BOOLEAN') + extract('YcpPathIsStrictAncestor','BOOLEAN'))
    shutil.copy2(driver / 'tests/namespace_boundary.c', work)
    subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror',
                              str(work / 'namespace_boundary.c'), '-o', str(work / 'namespace-test')], check=True)
    subprocess.run([str(work / 'namespace-test')], check=True)

    shutil.copy2(driver / 'tests/initialization_lifecycle.c', work)
    shutil.copy2(driver / 'ycsz_initialization_coverage.c', work)
    shutil.copy2(driver / 'ycsz_initialization_coverage.h', work)
    subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror',
                              str(work / 'initialization_lifecycle.c'), '-o', str(work / 'initialization-test')], check=True)
    subprocess.run([str(work / 'initialization-test')], check=True)

    (work / 'initialization_round_extracted.inc').write_text(
        extract('YcpTargetMatchesLocked', 'BOOLEAN') +
        extract('YcpInitializationValidLocked', 'BOOLEAN') +
        extract('YcpCaptureInitializationSnapshot', 'BOOLEAN') +
        extract('YcpReleaseInitializationSnapshot', 'VOID') +
        extract('YcpRecordInitializationStream', 'VOID'))
    shutil.copy2(driver / 'tests/initialization_round_binding.c', work)
    subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror',
                              str(work / 'initialization_round_binding.c'), '-o', str(work / 'initialization-round-test')], check=True)
    subprocess.run([str(work / 'initialization-round-test')], check=True)
