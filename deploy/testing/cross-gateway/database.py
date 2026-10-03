#!/usr/bin/env python3
"""Run only cross-gateway integration tests on an owned tmpfs PostgreSQL fixture."""
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
PROJECT = 'tunnexgatewaydb' + uuid.uuid4().hex[:10]
NETWORK = PROJECT + '-internal'
LABEL = 'com.docker.compose.project'
PROOF = ROOT / '.gateway-update-proof'
PROOF.mkdir(exist_ok=True)
owned = {}
network_id = None


def run(args):
    return subprocess.run(['docker', *args], check=True, capture_output=True,
                          text=True, timeout=90).stdout.strip()


def verify():
    network = json.loads(run(['network', 'inspect', network_id]))[0]
    assert network['Id'] == network_id and network['Name'] == NETWORK
    assert network['Internal'] and network['Labels'][LABEL] == PROJECT
    assert set(network.get('Containers', {})).issubset(set(owned.values()))
    for role, cid in owned.items():
        container = json.loads(run(['inspect', cid]))[0]
        host = container['HostConfig']
        assert container['Id'] == cid and container['Name'] == '/' + PROJECT + '-' + role
        assert container['Config']['Labels'][LABEL] == PROJECT
        assert host['NetworkMode'] == NETWORK and not host['Privileged']
        assert not host.get('Binds') and not host.get('PortBindings')
        if role == 'postgres':
            assert all(m['Type'] == 'tmpfs' for m in container['Mounts'])
        else:
            assert host['ReadonlyRootfs']
            assert all(m['Type'] == 'tmpfs' or (
                m['Type'] == 'bind' and m['Source'] == str(PROOF)
                and m['Destination'] == '/proof' and not m['RW']
            ) for m in container['Mounts'])
        print(f'COMPOSE_PROJECT_NAME={PROJECT} verified container={PROJECT}-{role} network={NETWORK}', flush=True)


def main():
    global network_id
    context = run(['context', 'show'])
    endpoint = json.loads(run(['context', 'inspect', context]))[0]['Endpoints']['docker']['Host']
    if not endpoint.startswith('unix://'):
        raise RuntimeError('qualification requires a local Docker socket')
    arch = run(['version', '--format', '{{.Server.Arch}}'])
    if arch not in ('arm64', 'amd64'):
        raise RuntimeError('unsupported test architecture')
    env = dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0')
    tests = {
        'tenancy': 'TestCrossGatewaySettingDatabaseAtomicityAndMigration',
        'gatewaymesh': 'TestCrossGatewayDatabaseSubjectLifecycle',
        'nodes': 'TestCrossGatewayDatabaseHealthMatchesServedArtifact',
    }
    for suite in tests:
        subprocess.run(['go', 'test', '-c', '-o', str(PROOF / (suite + '.test')),
                        './internal/' + suite], cwd=ROOT / 'apps/api', env=env, check=True)
    for kind, name in [('network', NETWORK), *[
        ('container', PROJECT + '-' + role) for role in ['postgres', *tests]
    ]]:
        if subprocess.run(['docker', kind, 'inspect', name], capture_output=True).returncode == 0:
            raise RuntimeError('refuse existing fixture resource')
    try:
        network_id = run(['network', 'create', '--internal', '--label', LABEL + '=' + PROJECT, NETWORK])
        owned['postgres'] = run([
            'create', '--name', PROJECT + '-postgres', '--label', LABEL + '=' + PROJECT,
            '--network', NETWORK, '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev',
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:16-alpine',
        ])
        verify()
        run(['start', owned['postgres']])
        for _ in range(40):
            verify()
            ready = subprocess.run(['docker', 'exec', owned['postgres'], 'pg_isready', '-U', 'postgres'], capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError('fixture PostgreSQL did not become ready')
        for suite, test in tests.items():
            owned[suite] = run([
                'create', '--name', PROJECT + '-' + suite, '--label', LABEL + '=' + PROJECT,
                '--network', NETWORK, '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev',
                '--mount', f'type=bind,src={PROOF},dst=/proof,readonly',
                '-e', 'COMPOSE_PROJECT_NAME=' + PROJECT,
                '-e', 'TUNNEX_TEST_DATABASE_URL=postgres://postgres@' + PROJECT + '-postgres/postgres?sslmode=disable',
                'alpine:3.23', '/proof/' + suite + '.test', '-test.run=^' + test + '$', '-test.v', '-test.count=1',
            ])
            verify()
            result = subprocess.run(['docker', 'start', '-a', owned[suite]], capture_output=True, text=True, timeout=120)
            print(result.stdout + result.stderr, flush=True)
            (PROOF / (PROJECT + '-' + suite + '.log')).write_text(result.stdout + result.stderr)
            state = json.loads(run(['inspect', owned[suite]]))[0]['State']
            if result.returncode or state['ExitCode'] or '--- PASS: ' + test not in result.stdout:
                raise RuntimeError('integration test did not pass: ' + test)
            verify()
            run(['rm', owned[suite]])
            del owned[suite]
    finally:
        for role, cid in list(owned.items()):
            verify()
            run(['rm', '-f', cid])
            del owned[role]
        if network_id:
            verify()
            run(['network', 'rm', network_id])


if __name__ == '__main__':
    main()
