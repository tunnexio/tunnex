#!/usr/bin/env python3
"""Rebuild repository storage from immutable, signed package releases."""
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import subprocess
from upstream import gh

keyring = str(Path('keys/tunnex.asc').resolve())
def verify(folder):
    subprocess.run(['gpg', '--batch', '--verify', 'SHA256SUMS.asc', 'SHA256SUMS'], cwd=folder, check=True)
    names = set()
    for line in (folder / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split()
        if not re.fullmatch('[0-9a-f]{64}', digest) or Path(name).name != name or name.startswith('.') or name in names:
            raise ValueError('Invalid signed checksum entry')
        names.add(name)
    actual = {p.name for p in folder.iterdir()}
    if actual != names | {'SHA256SUMS', 'SHA256SUMS.asc'}:
        raise ValueError('Release assets differ from the signed manifest')
    if any(not p.is_file() or p.is_symlink() for p in folder.iterdir()):
        raise ValueError('Only regular release files are accepted')
    subprocess.run(['sha256sum', '--strict', '--check', 'SHA256SUMS'], cwd=folder, check=True)
    return [folder / name for name in sorted(names)]

def apk_destination(path):
    # APK v2 is concatenated gzip/tar streams; tarfile handles the gzip stream
    # and ignore_zeros traverses from signature to control/data members.
    with tarfile.open(path, 'r:gz', ignore_zeros=True) as archive:
        member = archive.extractfile('.PKGINFO')
        if member is None:
            raise ValueError('APK lacks package metadata')
        fields = dict(line.split(' = ', 1) for line in member.read().decode().splitlines()
                      if ' = ' in line)
    if fields.get('pkgname') != 'tunnex-cli' or fields.get('arch') not in {'x86_64', 'aarch64'}:
        raise ValueError('Unexpected APK identity or architecture')
    version = fields['pkgver']
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-r[0-9]+', version):
        raise ValueError('Unexpected APK version')
    return Path('alpine') / fields['arch'] / f'tunnex-cli-{version}.apk'

def main():
    site = Path('site')
    site.mkdir(exist_ok=True)
    for name in ['tunnex.asc', 'tunnex.rsa.pub']:
        shutil.copyfile(Path('keys') / name, site / name)
    info = json.loads(Path('work/release.json').read_text())
    releases = json.loads(gh('api', '--paginate', '--slurp', f"repos/{os.environ['GITHUB_REPOSITORY']}/releases?per_page=100"))
    folders = [Path('dist')]
    for page in releases:
        for release in page:
            if release['draft'] or release['prerelease']:
                continue
            tag = release['tag_name']
            if not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
                continue
            if tuple(map(int, tag[1:].split('.'))) > tuple(map(int, info['version'].split('.'))):
                raise ValueError('Refusing repository downgrade')
            if tag == info['tag']:
                continue
            folder = Path('work/history') / tag
            folder.mkdir(parents=True, exist_ok=True)
            subprocess.run(['gh', 'release', 'download', tag, '--dir', str(folder)], check=True)
            folders.append(folder)
    for folder in folders:
        for p in verify(folder):
            if p.suffix == '.deb':
                dest = site / 'apt/pool/main' / p.name
            elif p.suffix == '.rpm':
                dest = site / 'rpm' / p.name
            elif p.suffix == '.apk':
                dest = site / apk_destination(p)
            elif '.pkg.tar.zst' in p.name:
                arch = 'aarch64' if 'aarch64' in p.name or 'arm64' in p.name else 'x86_64'
                dest = site / 'arch' / arch / p.name
            else:
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, dest)
    if sum(p.stat().st_size for p in site.rglob('*') if p.is_file()) > 800 * 1024 * 1024:
        raise ValueError('Repository exceeds 800 MiB: migrate storage before next promotion')
    shutil.copyfile('README.md', site / 'README.md')
    (site / 'index.html').write_text('<!doctype html><meta charset="utf-8"><title>Tunnex packages</title><h1>Tunnex CLI packages</h1><p>Official signed package repositories.</p><p><a href="https://github.com/tunnexio/packages#installation">Installation instructions</a></p>')
    (site / '.nojekyll').touch()

if __name__ == '__main__':
    main()
