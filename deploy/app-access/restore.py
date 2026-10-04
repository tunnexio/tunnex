#!/usr/bin/env python3
"""Explicit single-host Compose restore with an external browser-authority gate.

No automatic restart, credential issuance, publication, or HA fencing. The
operator must use this procedure for either restored store; raw restores are
not automatically detected by a generation stored in that same database.
"""
import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
import subprocess
import stat
import copy
import uuid

BARRIER = '/var/lib/tunnex/app-restore/app-access.pending.json'
PARTICIPANTS = {'api', 'app-proxy'}


class RestoreError(Exception):
    pass


def local_environment():
    return {key: value for key, value in os.environ.items()
            if key not in {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "COMPOSE_PROFILES"}}


def local_socket(path):
    value = Path(path)
    if not value.is_absolute() or value.resolve(strict=True) != value or not stat.S_ISSOCK(value.stat().st_mode):
        raise RestoreError("explicit canonical local Unix Docker socket required")
    return str(value)


def command(args, *, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, env=local_environment())
    if result.returncode:
        # Do not print subprocess output: environment-derived URLs and secrets
        # must not leak through a failed restore command.
        raise RestoreError('command failed; keep every listener stopped and retain the restore marker')
    return result.stdout


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


class Runner:
    def __init__(self, project, directory, compose_files, docker_socket):
        self.frozen_directory = None
        self.marker_mount = None
        self.api_identity = None
        self.docker = ["docker", "--host", "unix://" + local_socket(docker_socket)]
        self.project = project
        self.directory = str(Path(directory).resolve(strict=True))
        self.compose = self.docker + ['compose', '--project-name', project,
                        '--project-directory', self.directory]
        for file in compose_files:
            self.compose += ['-f', str(Path(file).resolve(strict=True))]

    def tool(self, args, *, data=None):
        self.validate_helper()
        options = ['run', '--rm', '--no-deps', '--pull', 'never', '-T']
        compose = self.compose
        if args and args[0] in {'app-restore-begin', 'app-recovery'}:
            # Compose run --volume :rw does not override service read_only.
            # Derive a helper-only snapshot from the already frozen configuration.
            config = json.loads(Path(self.compose[-1]).read_text())
            config = copy.deepcopy(config)
            config['services']['api'].pop('ports', None)
            for mount in config['services']['api']['volumes']:
                if mount.get('target') == str(Path(BARRIER).parent):
                    mount['read_only'] = False
            snapshot = Path(self.frozen_directory.name) / 'helper.json'
            with open(snapshot, 'w', opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                json.dump(config, stream)
                stream.flush()
                os.fsync(stream.fileno())
            compose = self.compose[:-1] + [str(snapshot)]
        return command(compose + options + ['--entrypoint', 'backupctl', 'api'] + args, data=data)

    def participants(self):
        identifiers = command(self.docker + ['ps', '-a', '--filter',
                               'label=com.docker.compose.project=' + self.project,
                               '--format', '{{.ID}}']).decode().split()
        found = []
        counts = {name: 0 for name in PARTICIPANTS}
        marker_mount = None
        for identifier in identifiers:
            # Environment is inspected in memory solely to validate the guard;
            # neither it nor the full object is emitted or written to evidence.
            item = json.loads(command(self.docker + ['inspect', identifier]))[0]
            labels = item['Config'].get('Labels') or {}
            service = labels.get('com.docker.compose.service')
            if service not in PARTICIPANTS:
                continue
            if labels.get('com.docker.compose.project') != self.project:
                raise RestoreError('foreign project participant; restore refused')
            if labels.get('com.docker.compose.project.working_dir') != self.directory:
                raise RestoreError('foreign checkout participant; restore refused')
            counts[service] += 1
            if service == 'api':
                identity = {key: item[key] for key in ('Config', 'Image', 'Mounts')}
                identity['Mounts'] = sorted(identity['Mounts'], key=lambda mount: mount['Destination'])
                if self.api_identity is not None and self.api_identity != identity:
                    raise RestoreError('API participant identity changed; restore refused')
                self.api_identity = identity
            env = dict(value.split('=', 1) for value in item['Config'].get('Env', []) if '=' in value)
            if env.get('TUNNEX_APP_ACCESS_RESTORE_MARKER') != BARRIER:
                raise RestoreError('every API and proxy must use the configured external restore barrier')
            mounts = [mount for mount in item.get('Mounts', [])
                      if mount.get('Destination') == str(Path(BARRIER).parent)]
            if len(mounts) != 1 or mounts[0].get('Type') != 'volume':
                raise RestoreError('external restore marker must use the dedicated shared named volume')
            volume = mounts[0].get('Name')
            if not volume or (marker_mount is not None and marker_mount != volume):
                raise RestoreError('participants use different restore barriers')
            marker_mount = volume
            found.append((identifier, service))
        if counts['api'] != 1 or any(count > 1 for count in counts.values()):
            raise RestoreError('runner requires one API and at most one proxy; fence HA participants separately')
        if self.marker_mount is not None and self.marker_mount != marker_mount:
            raise RestoreError("restore volume identity changed; restore refused")
        self.marker_mount = marker_mount
        self.validate_helper()
        return sorted(found)

    def validate_helper(self):
        config = json.loads(command(self.compose + ['config', '--format', 'json']))
        api = config.get('services', {}).get('api', {})
        environment = api.get('environment') or {}
        if environment.get('TUNNEX_APP_ACCESS_RESTORE_MARKER') != BARRIER:
            raise RestoreError('backup helper must use the participant restore barrier')
        mounts = [mount for mount in api.get('volumes', [])
                  if mount.get('target') == str(Path(BARRIER).parent)]
        if len(mounts) != 1 or mounts[0].get('type') != 'volume':
            raise RestoreError('backup helper requires the shared named restore volume')
        source = mounts[0].get('source')
        resolved = config.get('volumes', {}).get(source, {}).get('name')
        if not self.marker_mount or resolved != self.marker_mount:
            raise RestoreError('backup helper uses a different restore barrier')
        if self.api_identity is not None:
            actual = dict(value.split('=', 1) for value in self.api_identity['Config'].get('Env', []) if '=' in value)
            database = lambda env: env.get('TUNNEX_DATABASE_URL') or env.get('DATABASE_URL', '')
            if not database(actual) or database(actual) != database(environment):
                raise RestoreError('backup helper database identity differs from API participant')
            for key in ('TUNNEX_MASTER_KEY', 'TUNNEX_MASTER_KEY_FILE', 'TUNNEX_SECRETS_DIR'):
                default = '/var/lib/tunnex/secrets' if key == 'TUNNEX_SECRETS_DIR' else ''
                if actual.get(key, default) != environment.get(key, default):
                    raise RestoreError('backup helper secret source differs from API participant')
            expected_mounts = {}
            for mount in api.get('volumes', []):
                source = mount.get('source')
                if mount.get('type') == 'volume':
                    source = config.get('volumes', {}).get(source, {}).get('name')
                expected_mounts[mount.get('target')] = (mount.get('type'), source)
            actual_mounts = {mount['Destination']: (mount['Type'], mount.get('Name') if mount['Type'] == 'volume' else mount.get('Source')) for mount in self.api_identity['Mounts']}
            if expected_mounts != actual_mounts:
                raise RestoreError('backup helper mounts differ from API participant')
            image = api.get('image')
            if not image or command(self.docker + ['image', 'inspect', '--format', '{{.Id}}', image]).decode().strip() != self.api_identity['Image']:
                raise RestoreError('backup helper image differs from API participant')
            # Pin the helper to the already admitted local content digest.
            api['image'] = self.api_identity['Image']
        if self.frozen_directory is None:
            # Freeze the validated effective configuration so a concurrent edit
            # of an original override cannot move a helper to another volume.
            # Resolved credentials stay in an owned private temporary artifact.
            self.frozen_directory = tempfile.TemporaryDirectory(prefix='tunnex-app-restore-')
            snapshot = Path(self.frozen_directory.name) / 'compose.json'
            with open(snapshot, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                json.dump(config, stream)
                stream.flush()
                os.fsync(stream.fileno())
            self.compose = self.docker + ['compose', '--project-name', self.project,
                            '--project-directory', self.directory, '-f', str(snapshot)]

    def close(self):
        if self.frozen_directory is not None:
            self.frozen_directory.cleanup()
            self.frozen_directory = None

    def require_stopped(self, participants):
        if participants != self.participants():
            raise RestoreError('participant identity changed; restore refused')
        for identifier, _ in participants:
            state = json.loads(command(self.docker + ['inspect', '--format', '{{json .State}}', identifier]))
            if state.get('Running') or state.get('Restarting'):
                raise RestoreError('a listener participant remains running; restore refused')

    def restore(self, dump, manifest, operator, apply=False, resume=None):
        participants = self.participants()
        manifest_bytes = manifest.read_bytes()
        verify_args = ['verify']
        if resume is None:
            if self.frozen_directory is None:
                self.frozen_directory = tempfile.TemporaryDirectory(prefix='tunnex-app-restore-')
            frozen_dump = Path(self.frozen_directory.name) / ('dump-' + str(uuid.uuid4()))
            value = hashlib.sha256()
            with dump.open('rb') as source, open(frozen_dump, 'xb', opener=lambda path, flags: os.open(path, flags, 0o600)) as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
                    value.update(block)
                target.flush()
                os.fsync(target.fileno())
            verify_args += ['--dump-sha256', value.hexdigest()]
        self.tool(verify_args, data=manifest_bytes)
        if not apply:
            return {'ready_for_operator_review': True, 'participants': [service for _, service in participants],
                    'single_host_only': True, 'listeners_restart_automatically': False}
        if resume is None:
            marker = json.loads(self.tool(['app-restore-begin', '--barrier', BARRIER]))
            marker_id = str(uuid.UUID(marker['id']))
        else:
            marker_id = str(uuid.UUID(resume))
        # Marker precedes state replacement; every supported restart refuses it.
        command(self.compose + ['stop', '--timeout', '15'] + sorted({service for _, service in participants}))
        self.require_stopped(participants)
        if resume is None:
            script = 'exec pg_restore --exit-on-error --single-transaction --clean --if-exists --no-owner -d "${TUNNEX_DATABASE_URL:-$DATABASE_URL}"'
            with frozen_dump.open('rb') as archive:
                result = subprocess.run(self.compose + ['run', '--rm', '--no-deps', '--pull', 'never', '-T',
                                        '--entrypoint', 'sh', 'api', '-ec', script],
                                        stdin=archive, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE, check=False, env=local_environment())
            if result.returncode:
                raise RestoreError('database restore failed; marker retained and listeners must remain stopped')
        self.require_stopped(participants)
        self.tool(verify_args, data=manifest_bytes)
        result = json.loads(self.tool(['app-recovery', '--barrier', BARRIER,
                                      '--barrier-id', marker_id, '--operator', operator]))
        if result.get('confirmed') is not True:
            raise RestoreError('authority recovery is unconfirmed; listeners must remain stopped')
        self.require_stopped(participants)
        return {'restore_complete': True, 'listeners_stopped': True,
                'generation': result['generation'], 'version': result['version'],
                'fresh_login_proxy_provision_and_republish_required': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-socket', required=True, help='canonical absolute local Unix Docker socket')
    parser.add_argument('--project', required=True)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--compose-file', action='append', required=True)
    parser.add_argument('--dump', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--operator', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--resume-marker', help='resume offline recovery; never reapply the dump')
    args = parser.parse_args()
    runner = None
    try:
        runner = Runner(args.project, args.directory, args.compose_file, args.docker_socket)
        result = runner.restore(
            args.dump, args.manifest, args.operator, args.apply, args.resume_marker)
        print(json.dumps(result))
    except (RestoreError, OSError, ValueError, KeyError):
        parser.exit(1, 'Restore refused or incomplete. Keep listeners stopped, retain the external marker, and inspect the scoped recovery state.\n')
    finally:
        if runner is not None:
            runner.close()


if __name__ == '__main__':
    main()
