"""Refuse recipe rollback and reuse of a version for different source code."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def identity(info):
    version = info['version']
    sha = info['source_sha']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or info['tag'] != 'v' + version:
        raise ValueError('Invalid stable release identity')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Invalid source SHA')
    return tuple(map(int, version.split('.'))), sha


def validate(candidate, previous=None):
    new_version, new_sha = identity(candidate)
    if previous is None:
        return
    old_version, old_sha = identity(previous)
    if new_version < old_version:
        raise ValueError('Refusing recipe version rollback')
    if new_version == old_version and new_sha != old_sha:
        raise ValueError('Refusing different source for the same recipe version')


def read_ref(ref):
    path = 'nix/release.json'
    names = subprocess.check_output(['git', 'ls-tree', '--name-only', ref, '--', path], text=True)
    if not names.strip():
        return None  # A verified Git tree without a recipe marker is bootstrap.
    return json.loads(subprocess.check_output(['git', 'show', f'{ref}:{path}'], text=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', default='nix/release.json')
    parser.add_argument('--current-ref', required=True)
    args = parser.parse_args()
    validate(json.loads(Path(args.candidate).read_text()), read_ref(args.current_ref))
