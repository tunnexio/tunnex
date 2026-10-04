#!/usr/bin/env python3
"""Check exact external resource names as well as project container ownership."""
import json
import pathlib
import subprocess
import sys

PROJECT = 'tunnex-app-access-aa0-1003'
EXPECTED = [('network', 'default'), ('volume', 'postgres_data'),
            ('volume', 'redis_data'), ('volume', 'api_state'),
            ('volume', 'gateway_state')]

class OwnershipError(RuntimeError):
    pass

class MissingResource(RuntimeError):
    pass

def docker(root, *args):
    result = subprocess.run([str(root / 'docker-local.sh'), *args], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        if args[1:2] == ('inspect',) and ('no such' in result.stderr.lower() or 'not found' in result.stderr.lower()):
            raise MissingResource(args[-1])
        raise OwnershipError('local Docker operation failed: ' + ' '.join(args[:2]))
    return result.stdout.strip()

def identity(item):
    return item.get('Id') or (item['Name'] + ':' + item.get('CreatedAt', ''))

def check(root, call=None):
    root = root.resolve()
    call = call or (lambda *args: docker(root, *args))
    owner = str(root)
    marker = root / '.runtime' / 'ownership.json'
    state = json.loads(marker.read_text()) if marker.exists() else {'checkout': owner, 'resources': {}}
    if state.get('checkout') != owner:
        raise OwnershipError('runtime marker belongs to another checkout')
    resources = dict(state['resources'])
    missing = []
    # These are external Compose names: filtering by a project label would hide
    # a colliding resource owned by another project (or carrying no label).
    for kind, suffix in EXPECTED:
        name = PROJECT + '_' + suffix
        key = kind + ':' + name
        try:
            item = json.loads(call(kind, 'inspect', name))[0]
        except MissingResource:
            if key in resources:
                raise OwnershipError('previously recorded resource missing; refusing blank replacement: ' + key)
            missing.append((kind, name))
            continue
        if item.get('Name') != name:
            raise OwnershipError('inspect returned unexpected resource name: ' + key)
        labels = item.get('Labels') or {}
        if labels.get('com.docker.compose.project') != PROJECT:
            raise OwnershipError('external resource belongs to another or unknown project: ' + key)
        if labels.get('app-access.checkout') not in (None, '', owner):
            raise OwnershipError('external resource belongs to another checkout: ' + key)
        current = identity(item)
        prior = resources.get(key)
        if prior is not None and prior != current:
            raise OwnershipError('recorded resource identity changed: ' + key)
        if labels.get('app-access.checkout') != owner and prior != current:
            raise OwnershipError('unrecognized external resource checkout: ' + key)
        resources[key] = current
    names = call('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + PROJECT).splitlines()
    for name in names:
        item = json.loads(call('container', 'inspect', name))[0]
        labels = item.get('Config', {}).get('Labels') or {}
        if labels.get('com.docker.compose.project') != PROJECT or labels.get('com.docker.compose.project.working_dir') != owner:
            raise OwnershipError('existing container belongs to another checkout: ' + name)
        resources['container:' + item['Name'].lstrip('/')] = identity(item)
    marker.parent.mkdir(exist_ok=True)
    marker.write_text(json.dumps({'checkout': owner, 'resources': resources}, indent=2) + '\n')
    marker.chmod(0o600)
    return missing

def main():
    try:
        check(pathlib.Path(__file__).resolve().parent)
    except (OwnershipError, ValueError, KeyError) as error:
        sys.exit('App Access ownership refusal: ' + str(error))

if __name__ == '__main__':
    main()
