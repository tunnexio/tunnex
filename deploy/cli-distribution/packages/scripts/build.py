#!/usr/bin/env python3
"""Package exact upstream bytes. No enrollment, services or install scripts."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from upstream import resolve, download, gh

info = resolve()
Path('work').mkdir(exist_ok=True)
Path('dist').mkdir(exist_ok=True)
Path('work/release.json').write_text(json.dumps(info, indent=2) + '\n')
# Only a real 404 permits creation; authentication/network/server errors fail closed.
probe = subprocess.run(['gh', 'api', f"repos/{os.environ['GITHUB_REPOSITORY']}/releases/tags/{info['tag']}"], capture_output=True, text=True)
if probe.returncode == 0:
    release = json.loads(probe.stdout)
    if release['draft'] or release['prerelease']:
        raise SystemExit('Unexpected draft/prerelease package release; inspect before retry')
    subprocess.run(['gh', 'release', 'download', info['tag'], '--dir', 'dist'], check=True)
    recorded = json.loads(Path('dist/provenance.json').read_text())
    if recorded['source_sha'] != info['source_sha']:
        raise SystemExit('Refusing source reuse')
    Path('work/existing').touch()
    raise SystemExit(0)
if 'HTTP 404' not in probe.stderr:
    raise SystemExit(probe.stderr)
download(info, 'work/upstream')
for arch in ['amd64', 'arm64']:
    config = {
        'name': 'tunnex-cli', 'arch': arch, 'platform': 'linux',
        'version': info['version'], 'release': '1', 'section': 'net', 'priority': 'optional',
        'maintainer': 'Tunnex <iotunnex@gmail.com>', 'description': 'Tunnex Zero Trust command-line client',
        'vendor': 'Tunnex', 'homepage': 'https://tunnex.io', 'license': 'Apache-2.0',
        'contents': [{'src': f'work/upstream/tnx-linux-{arch}', 'dst': '/usr/bin/tunnex',
                      'file_info': {'mode': 493}}],
        'rpm': {'signature': {'key_file': os.environ['PACKAGE_GPG_KEY'],
                              'key_id': os.environ['PACKAGE_KEY_ID'][-16:]}},
        'apk': {'signature': {'key_file': os.environ['PACKAGE_APK_KEY'], 'key_name': 'tunnex'}},
    }
    Path('work/nfpm.json').write_text(json.dumps(config))
    for fmt in ['deb', 'rpm', 'apk', 'archlinux']:
        subprocess.run(['nfpm', 'package', '--config', 'work/nfpm.json', '--packager', fmt, '--target', 'dist/'], check=True)
    # Universal static fallback, including systems without a supported package manager.
    archive = f"dist/tunnex-cli_{info['version']}_linux_{arch}.tar.gz"
    subprocess.run(['tar', '-czf', archive, '-C', 'work/upstream', '--transform', f's/tnx-linux-{arch}/tunnex/', f'tnx-linux-{arch}'], check=True)
Path('dist/provenance.json').write_text(json.dumps(info, indent=2) + '\n')
for path in sorted(Path('dist').glob('*.pkg.tar.zst')):
    subprocess.run(['gpg', '--batch', '--yes', '--local-user', os.environ['PACKAGE_KEY_ID'], '--detach-sign', str(path)], check=True)
checksums = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(Path('dist').iterdir()) if p.is_file())
Path('dist/SHA256SUMS').write_text(checksums)
subprocess.run(['gpg', '--batch', '--yes', '--armor', '--local-user', os.environ['PACKAGE_KEY_ID'], '--detach-sign', 'dist/SHA256SUMS'], check=True)
