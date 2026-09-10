"""Fail-closed resource ownership checks; no assertions removable by python -O."""
import json


def ensure_absent(docker, planned):
    for kind, names in planned.items():
        args = ('container', 'ls', '-a', '--format', '{{.Names}}') if kind == 'container' else (kind, 'ls', '--format', '{{.Name}}')
        existing = set(docker(*args).splitlines())
        if existing.intersection(names):
            raise RuntimeError('Refusing existing exact-name '+kind+' resource')


def verify_volume(docker, name, project):
    value = json.loads(docker('volume', 'inspect', name))[0]
    if value.get('Name') != name or value.get('Labels', {}).get('com.docker.compose.project') != project:
        raise RuntimeError('Volume ownership verification failed')


def verify_container(docker, identifier, project, network, mounts=None, running=False):
    value = json.loads(docker('inspect', identifier))[0]
    if value.get('Config', {}).get('Labels', {}).get('com.docker.compose.project') != project:
        raise RuntimeError('Container ownership verification failed')
    if network not in value.get('NetworkSettings', {}).get('Networks', {}):
        raise RuntimeError('Container network verification failed')
    if running and not value.get('State', {}).get('Running'):
        raise RuntimeError('Container is not running')
    for destination, name in (mounts or {}).items():
        actual = [m for m in value.get('Mounts', []) if m.get('Destination') == destination]
        if len(actual) != 1 or actual[0].get('Type') != 'volume' or actual[0].get('Name') != name:
            raise RuntimeError('Container volume mount verification failed')
        verify_volume(docker, name, project)
    return value
