#!/usr/bin/env python3
"""Reviewed single-host, same-schema App Access image replacement only.

Does not pull/build images, migrate stores, start listeners, provision credentials,
publish applications, or replace deployment files. Persist the reviewed image pins
in operator configuration before an intentional start. Rollback uses the same
procedure with the prior verified descriptor, never a database downgrade.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import uuid

spec = importlib.util.spec_from_file_location('app_restore', Path(__file__).with_name('restore.py'))
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def validate_preflight(current, target):
    for value in (current, target):
        if (value.get('schema_version') != value.get('supported_schema_version')
                or not isinstance(value.get('schema_version'), int) or value['schema_version'] < 173
                or value.get('recovery_completed') is not True
                or uuid.UUID(value['generation']).int == 0
                or not isinstance(value.get('authority_version'), int) or value['authority_version'] < 1):
            raise restore.RestoreError('clean same-schema completed authority required')
    if current != target:
        raise restore.RestoreError('schema or authority changed; image replacement refused')


class UpgradeRunner(restore.Runner):
    def preflight(self, config):
        config = copy.deepcopy(config)
        service = config['services']['api']
        # Read-only database tool holds the existing external marker lock. Only
        # this temporary helper gets write access to that exact verified volume.
        service.pop('ports', None)
        for mount in service.get('volumes', []):
            destination = mount['target']
            if destination == str(Path(restore.BARRIER).parent):
                mount['read_only'] = False
            elif destination == '/' or '/usr/local/bin/backupctl'.startswith(destination.rstrip('/') + '/') or destination == '/usr/local/bin/backupctl':
                raise restore.RestoreError('image preflight executable may not be overridden by mounts')
        path = Path(self.frozen_directory.name) / ('preflight-' + str(uuid.uuid4()) + '.json')
        self.write_private(path, config)
        command = self.compose[:-1] + [str(path)]
        raw = restore.command(command + ['run', '--rm', '--no-deps', '--pull', 'never', '-T',
                              '--entrypoint', '/usr/local/bin/backupctl', 'api', 'app-preflight'])
        return json.loads(raw)

    @staticmethod
    def write_private(path, config):
        with open(path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as out:
            json.dump(config, out)
            out.flush()
            os.fsync(out.fileno())

    def verified_images(self, manifest, verifier, public_key, platform):
        frozen = Path(self.frozen_directory.name) / 'release.json'
        # Capture the signed bytes once; verifier and reviewed hash use these bytes.
        data = Path(manifest).read_bytes()
        with open(frozen, 'xb', opener=lambda name, flags: os.open(name, flags, 0o600)) as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        raw = restore.command([str(Path(verifier).resolve(strict=True)), '-manifest', str(frozen),
                               '-public-key', public_key, '-require-app-proxy', '-print-env', '-platform', platform])
        pins = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
        images = {}
        for service, key in [('api', 'TUNNEX_API_IMAGE'), ('app-proxy', 'TUNNEX_APP_PROXY_IMAGE')]:
            pin = pins.get(key, '')
            if not re.fullmatch('ghcr.io/tunnexio/tunnex-' + service + r'@sha256:[0-9a-f]{64}', pin):
                raise restore.RestoreError('verified immutable image pin required')
            item = json.loads(restore.command(self.docker + ['image', 'inspect', pin]))[0]
            if pin not in (item.get('RepoDigests') or []) or item.get('Architecture') != platform:
                raise restore.RestoreError('cached image does not match signed platform pin')
            images[service] = item['Id']
        return images, hashlib.sha256(data).hexdigest()

    def validate_service(self, config, participants, name):
        proxy = next(identifier for identifier, service in participants if service == name)
        actual = json.loads(restore.command(self.docker + ['inspect', proxy]))[0]
        service = config['services'][name]
        if service.get('build') is not None:
            raise restore.RestoreError('local build configuration is outside immutable image replacement')
        image = json.loads(restore.command(self.docker + ['image', 'inspect', service['image']]))[0]
        env = dict(item.split('=', 1) for item in actual['Config'].get('Env', []) if '=' in item)
        if image['Id'] != actual['Image'] or any(env.get(k) != str(v) for k, v in service.get('environment', {}).items()):
            raise restore.RestoreError('participant effective image or configuration identity changed')
        expected_mounts = {m['target']: (m['type'], config.get('volumes', {}).get(m['source'], {}).get('name') if m['type'] == 'volume' else m['source'], not m.get('read_only', False)) for m in service.get('volumes', [])}
        actual_mounts = {m['Destination']: (m['Type'], m.get('Name') if m['Type'] == 'volume' else m['Source'], m['RW']) for m in actual['Mounts']}
        if expected_mounts != actual_mounts:
            raise restore.RestoreError('participant secret or marker mount identity changed')
        expected_ports = set()
        for port in service.get('ports') or []:
            if not isinstance(port, dict) or not str(port.get('published', '')).isdigit() or int(port['published']) < 1:
                raise restore.RestoreError('fixed reviewed published ports required')
            expected_ports.add((str(port['target']) + '/' + port.get('protocol', 'tcp'),
                                port.get('host_ip', ''), str(port['published'])))
        actual_ports = {(target, binding.get('HostIp', ''), str(binding.get('HostPort', '')))
                        for target, bindings in (actual.get('HostConfig', {}).get('PortBindings') or {}).items()
                        for binding in bindings or []}
        if expected_ports != actual_ports:
            raise restore.RestoreError('participant port bindings differ from reviewed configuration')
        configured_networks = service.get('networks') or {'default': None}
        expected_networks = {config.get('networks', {}).get(key, {}).get('name') for key in configured_networks}
        attached = actual.get('NetworkSettings', {}).get('Networks') or {}
        if None in expected_networks or set(attached) != expected_networks:
            raise restore.RestoreError('participant network differs from reviewed configuration')
        identity = {}
        for key in configured_networks:
            definition = config['networks'][key]
            network = definition['name']
            inspected = json.loads(restore.command(self.docker + ['network', 'inspect', network]))[0]
            if inspected.get('Name') != network or not inspected.get('Id'):
                raise restore.RestoreError('reviewed network object unavailable')
            if not definition.get('external') and (inspected.get('Labels') or {}).get('com.docker.compose.project') != self.project:
                raise restore.RestoreError('foreign owned network refused')
            endpoint_id = attached[network].get('NetworkID')
            # Compose --no-start reserves names without creating endpoints.
            # Resolve the existing object rather than starting a listener to
            # populate NetworkID; attached/running endpoints remain exact.
            if endpoint_id and endpoint_id != inspected['Id']:
                raise restore.RestoreError('participant attached to another network object')
            if not endpoint_id and actual.get('State', {}).get('Running'):
                raise restore.RestoreError('running participant network is unconfirmed')
            identity[network] = inspected['Id']
        known = getattr(self, 'network_identities', {})
        if name in known and known[name] != identity:
            raise restore.RestoreError('participant network identity changed')
        known[name] = identity
        self.network_identities = known
        config['services'][name]['image'] = actual['Image']

    def replace(self, manifest, verifier, public_key, platform, expected_plan=None):
        participants = self.participants()
        if {service for _, service in participants} != {'api', 'app-proxy'}:
            raise restore.RestoreError('existing explicitly installed API and proxy required')
        config = json.loads(Path(self.compose[-1]).read_text())
        self.validate_service(config, participants, 'api')
        self.validate_service(config, participants, 'app-proxy')
        images, manifest_sha = self.verified_images(manifest, verifier, public_key, platform)
        target = copy.deepcopy(config)
        for name, image in images.items():
            target['services'][name]['image'] = image
        current = self.preflight(config)
        proposed = self.preflight(target)
        validate_preflight(current, proposed)
        plan = {'participants': participants, 'current_images': {name: config['services'][name]['image'] for name in images},
                'target_images': images, 'authority': current, 'manifest_sha256': manifest_sha,
                'network_identities': self.network_identities,
                'configuration_sha256': hashlib.sha256(canonical(config)).hexdigest(),
                'listeners_restart_automatically': False, 'same_schema_only': True}
        plan_sha = hashlib.sha256(canonical(plan)).hexdigest()
        if expected_plan is None:
            return {'ready_for_operator_review': True, 'plan_sha256': plan_sha, **plan}
        if expected_plan != plan_sha:
            raise restore.RestoreError('reviewed plan changed; no listener stopped')
        # Recheck exact current participants and schema immediately before stop.
        if participants != self.participants():
            raise restore.RestoreError('participants changed since review')
        validate_preflight(current, self.preflight(config))
        self.validate_service(config, participants, 'api')
        self.validate_service(config, participants, 'app-proxy')
        restore.command(self.compose + ['stop', '--timeout', '15', 'api', 'app-proxy'])
        self.require_stopped(participants)
        target_path = Path(self.frozen_directory.name) / 'target.json'
        self.write_private(target_path, target)
        target_compose = self.compose[:-1] + [str(target_path)]
        restore.command(target_compose + ['up', '--no-start', '--no-deps', '--pull', 'never', '--force-recreate', 'api', 'app-proxy'])
        # Re-admit replaced participants from the frozen target before declaring
        # completion. Failure leaves them stopped; no automatic previous restart.
        replacement = restore.Runner(self.project, self.directory, [target_path], self.docker[2][7:])
        try:
            admitted = replacement.participants()
            replacement.require_stopped(admitted)
            self.validate_service(copy.deepcopy(target), admitted, 'api')
            self.validate_service(copy.deepcopy(target), admitted, 'app-proxy')
            if {name for _, name in admitted} != {'api', 'app-proxy'}:
                raise restore.RestoreError('replacement participants missing')
        finally:
            replacement.close()
        validate_preflight(current, self.preflight(target))
        return {'image_replacement_complete': True, 'listeners_stopped': True,
                'plan_sha256': plan_sha, 'target_images': images, 'authority': current,
                'persist_verified_pins_and_review_before_start': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-socket', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--compose-file', action='append', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--releaseverify', required=True)
    parser.add_argument('--public-key', required=True)
    parser.add_argument('--platform', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--apply-plan-sha256', help='apply exactly the reviewed plan; listeners remain stopped')
    args = parser.parse_args(); runner = None
    try:
        runner = UpgradeRunner(args.project, args.directory, args.compose_file, args.docker_socket)
        print(json.dumps(runner.replace(args.manifest, args.releaseverify, args.public_key, args.platform, args.apply_plan_sha256)))
    except (restore.RestoreError, OSError, ValueError, KeyError, TypeError):
        parser.exit(1, 'Image replacement refused or incomplete. Preserve stores and external barrier; inspect stopped participants before an intentional start.\n')
    finally:
        if runner is not None: runner.close()


if __name__ == '__main__':
    main()
