#!/usr/bin/env python3
"""Offline preview must stop before any installer operation, even with bad inputs."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='tunnex-ui-preview-') as temp:
    scratch = Path(temp)
    marker = scratch / 'unexpected-operation'
    for command in ('curl', 'docker', 'sudo', 'uname', 'openssl', 'brew'):
        stub = scratch / command
        stub.write_text(f'#!/bin/sh\nprintf invoked > "{marker}"\nexit 99\n')
        stub.chmod(0o755)
    env = dict(os.environ, PATH=f'{scratch}:' + os.environ['PATH'],
               TUNNEX_DIR=str(scratch / 'must-not-exist'),
               TUNNEX_PUBLIC_BASE_URL='invalid', TUNNEX_COLOR='always')
    for controls in ({'NO_COLOR': '1'}, {'TERM': 'dumb'}):
        result = subprocess.run(['sh', str(root / 'install.sh'), '--ui-preview'],
                                env=dict(env, **controls), capture_output=True,
                                text=True, timeout=15, check=True)
        assert 'This was a simulation' in result.stdout, result.stdout
        assert '\x1b' not in result.stdout + result.stderr
        assert not marker.exists(), 'preview called a host operation'
        assert not (scratch / 'must-not-exist').exists()
    if shutil.which('pwsh'):
        result = subprocess.run(['pwsh', '-NoProfile', '-File', str(root / 'install.ps1'), '-UiPreview'],
                                env=dict(env, NO_COLOR='1'), capture_output=True,
                                text=True, timeout=15, check=True)
        assert 'PREVIEW COMPLETE' in result.stdout, result.stdout
        # Both entrypoints must show the approved complete flow, not just the
        # Windows prerequisite prelude. Ignore CRLF, preserve content and spacing.
        shell_preview = subprocess.run(
            ['sh', str(root / 'install.sh'), '--ui-preview'], env=dict(env, NO_COLOR='1'),
            capture_output=True, text=True, timeout=15, check=True)
        assert result.stdout.splitlines() == shell_preview.stdout.splitlines(), (
            'Windows and shared installer previews differ', result.stdout, shell_preview.stdout)
        assert '\x1b' not in result.stdout + result.stderr
        assert not marker.exists(), 'Windows preview called a host operation'
print('installer UI preview isolation: PASS')
