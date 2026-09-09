#!/usr/bin/env python3
"""Resolve a public stable release and verify its immutable source contract."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

REPO = 'tunnexio/tunnex'

def gh(*args):
    return subprocess.check_output(['gh', *args], text=True)

def api(path):
    return json.loads(gh('api', path))

def resolve():
    release = api(f'repos/{REPO}/releases/latest')
    tag = release['tag_name']
    if release['draft'] or release['prerelease'] or not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
        raise ValueError('Only public stable semantic releases are eligible')
    source = json.loads(gh('release', 'download', tag, '--repo', REPO,
                           '--pattern', 'Tunnex-release-source.json', '--output', '-'))
    sha = source['source_sha']
    if source['schema_version'] != 1 or source['tag'] != tag or not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('Invalid source marker')
    if api(f'repos/{REPO}/commits/{tag}')['sha'] != sha:
        raise ValueError('Source tag moved')
    runs = api(f'repos/{REPO}/actions/workflows/ci.yml/runs?head_sha={sha}&status=success&per_page=100')['workflow_runs']
    if not any(r['head_sha'] == sha and r['event'] == 'push' and r['head_branch'] == tag for r in runs):
        raise ValueError('No successful tag CI on the exact source SHA')
    return {'version': tag[1:], 'tag': tag, 'source_sha': sha, 'upstream_release': release['html_url']}

def download(info, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name in ['tnx-linux-amd64', 'tnx-linux-arm64', 'Tunnex-CLI-SHA256SUMS']:
        subprocess.run(['gh', 'release', 'download', info['tag'], '--repo', REPO,
                        '--pattern', name, '--dir', str(output), '--clobber'], check=True)
    expected = {}
    for line in (output / 'Tunnex-CLI-SHA256SUMS').read_text().splitlines():
        digest, name = line.split()
        name = Path(name).name
        if not re.fullmatch('[0-9a-f]{64}', digest) or name in expected:
            raise ValueError('Malformed or duplicate checksum')
        expected[name] = digest
    for arch in ['amd64', 'arm64']:
        path = output / f'tnx-linux-{arch}'
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected[path.name]:
            raise ValueError(f'Checksum mismatch: {path.name}')
        path.chmod(0o755)
    info['binary_sha256'] = expected

if __name__ == '__main__':
    print(json.dumps(resolve(), indent=2))
