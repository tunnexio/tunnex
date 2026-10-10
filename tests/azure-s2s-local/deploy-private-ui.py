#!/usr/bin/env python3
"""Owned lab static UI update only; review by default, --apply after approval."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import socket
import stat
import subprocess
import tarfile
import tempfile

OWNER = 'azure-s2s-01a12505'
NAME = 'tunnex-azure-private-ui'
BASE = Path('/home/ubuntu/tunnex-azure-lab')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def package(path, expected):
    raw = path.read_bytes()
    if len(raw) > 16 << 20 or digest(raw) != expected:
        raise ValueError('package digest or size refused')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        total = 0
        for member in archive:
            name = PurePosixPath(member.name)
            if (not member.isfile() or name.is_absolute() or '..' in name.parts
                    or str(name) != member.name or member.name in files
                    or member.size > 16 << 20):
                raise ValueError('package entry refused')
            total += member.size
            if total > 32 << 20 or len(files) >= 128:
                raise ValueError('package expansion refused')
            if member.name not in {'manifest.json', 'nginx.conf'} and (name.parts[0] != 'html' or name.suffix == '.map' or any(p.startswith('.') for p in name.parts)):
                raise ValueError('package scope refused')
            files[member.name] = archive.extractfile(member).read()
    manifest = json.loads(files.pop('manifest.json'))
    if (manifest.get('owner') != OWNER or manifest.get('node_version') != '24.21.0'
            or manifest.get('web_tree') != 'b43750ee815f620a9383aca20e6f37c27e306c2c'
            or manifest.get('files') != {p: digest(v) for p, v in files.items()}
            or 'html/index.html' not in files or 'nginx.conf' not in files):
        raise ValueError('package manifest refused')
    return files


def inspect(cid=NAME):
    result = subprocess.run(['docker', 'inspect', cid], capture_output=True, timeout=10, check=True)
    rows = json.loads(result.stdout)
    if len(rows) != 1:
        raise ValueError('container identity refused')
    row = rows[0]
    if (row['Name'] != '/' + NAME or row['Config'].get('Labels', {}).get('tunnex.owner') != OWNER
            or not row['State']['Running'] or row['HostConfig']['NetworkMode'] != 'host'
            or row['Config'].get('User') not in {'101', '101:101'}
            or 'ALL' not in (row['HostConfig'].get('CapDrop') or [])):
        raise ValueError('container ownership or isolation refused')
    return row


def owned_path(path):
    path = Path(path)
    if not path.is_absolute() or BASE not in path.parents or path.resolve() != path:
        raise ValueError('deployment path refused')
    for current in (path, *path.parents):
        if current == BASE.parent:
            break
        st = current.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid not in {0, 1000} or st.st_mode & 0o022:
            raise ValueError('deployment ownership refused')
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if socket.gethostname() != 'tunnex-peer' or os.geteuid() != 0:
        raise ValueError('owned peer root execution required')
    files = package(args.package, args.sha256)
    row = inspect()
    cid = row['Id']
    mounts = {m['Destination']: m for m in row['Mounts'] if m['Type'] == 'bind'}
    if '/srv/azure-private-ui' not in mounts or '/etc/nginx/nginx.conf' not in mounts:
        raise ValueError('expected private UI mounts required')
    html = owned_path(mounts['/srv/azure-private-ui']['Source'])
    config = owned_path(mounts['/etc/nginx/nginx.conf']['Source'])
    if not html.is_dir() or digest(config.read_bytes()) != digest(files['nginx.conf']):
        raise ValueError('existing same-origin nginx layout differs')
    subprocess.run(['docker', 'exec', cid, 'nginx', '-t'], capture_output=True, timeout=10, check=True)
    # Static-only overlay: retain old hashed assets for already-open browser tabs.
    # Publish index last; bind-mounted directory inode and nginx process stay intact.
    targets = []
    for name, data in files.items():
        if name == 'nginx.conf':
            continue
        target = html.joinpath(*PurePosixPath(name).parts[1:])
        parent = target.parent
        while not parent.exists():
            parent = parent.parent
        owned_path(parent)
        if target.exists() or target.is_symlink():
            owned_path(target)
            if not target.is_file():
                raise ValueError('static target refused')
        targets.append((target, data))
    if not args.apply:
        print(json.dumps({'reviewed': True, 'static_files': len(targets), 'nginx_unchanged': True}))
        return
    for target, data in sorted(targets, key=lambda v: (v[0].name == 'index.html', str(v[0]))):
        if inspect(cid)['Id'] != cid or digest(config.read_bytes()) != digest(files['nginx.conf']):
            raise ValueError('deployment identity changed')
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        owned_path(target.parent)
        fd, temp = tempfile.mkstemp(prefix='.azure-ui-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as output:
                os.fchmod(output.fileno(), 0o644)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp, target)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    print(json.dumps({'updated': True, 'static_files': len(targets), 'nginx_unchanged': True, 'restart_performed': False}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError, subprocess.SubprocessError, tarfile.TarError):
        raise SystemExit('Owned private UI deployment refused; no raw diagnostics emitted.')
