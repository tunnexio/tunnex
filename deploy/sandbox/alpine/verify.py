#!/usr/bin/env python3
"""Bounded Docker substitute; never claims native rootless qualification."""
import hashlib, json, pathlib, subprocess, sys, tempfile, time, tarfile

def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=60, **kwargs).stdout

image = sys.argv[1]
info = json.loads(run('docker', 'image', 'inspect', image))[0]
arch = info['Architecture']
platform = 'linux/' + arch
profile = info['Config']['Labels']['io.tunnex.sandbox.profile'].split('-')[1]
engine_arch = run('docker', 'info', '--format', '{{.Architecture}}').decode().strip()
emulated = arch == 'amd64' and engine_arch in ('aarch64', 'arm64')
if not image.startswith('tunnex-sandbox-'):
    raise SystemExit('task image required')
with tempfile.TemporaryDirectory(prefix='tunnex-alpine-') as tmp:
    p = pathlib.Path(tmp)
    for key in ('client', 'host_key'):
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(p / key))
    (p / 'authorized_keys').write_bytes((p / 'client.pub').read_bytes())
    root = pathlib.Path(__file__).resolve().parents[3]
    source = (root / 'apps/api/internal/sandboxes/terminal_delivery.go').read_text()
    config = source.split('const terminalConfig = `', 1)[1].split('`', 1)[0]
    (p / 'sshd_config').write_text(config)
    # Copy only task-generated server fixtures into a task-owned Docker volume.
    volume = 'tunnex-alpine-fixture-' + p.name
    run('docker', 'volume', 'create', volume)
    cid = None
    negative_tests = []
    for name, user, command in [
        ('root identity rejected', '0:0', 'exec /bin/bash /usr/local/lib/tunnex/sandbox-entrypoint.sh'),
        ('symlink runtime directory rejected', '1001:1001', 'ln -s /tmp /run/sshd; exec /bin/bash /usr/local/lib/tunnex/sandbox-entrypoint.sh'),
        ('writable SSH directory rejected', '1001:1001', 'mkdir -m 777 /run/sshd; exec /bin/bash /usr/local/lib/tunnex/sandbox-entrypoint.sh'),
        ('extra arguments rejected', '1001:1001', 'exec /bin/bash /usr/local/lib/tunnex/sandbox-entrypoint.sh extra'),
    ]:
        rejected = subprocess.run(['docker', 'run', '--rm', '--platform=' + platform, '--network=none', '--memory=128m', '--cpus=1', '--read-only', '--cap-drop=ALL', '--user=' + user, '--tmpfs', '/run:uid=1001,gid=1001,mode=700,size=4m', '--entrypoint=/bin/bash', image, '-c', command], capture_output=True, timeout=30)
        assert rejected.returncode != 0 and b'sandbox terminal unavailable' in rejected.stderr, (name, rejected.stderr)
        negative_tests.append(name)
    try:
        fixtures = p / 'fixtures.tar'
        with tarfile.open(fixtures, 'w') as archive:
            for name in ('host_key', 'authorized_keys', 'sshd_config'):
                archive.add(p / name, arcname=name)
        run('docker', 'run', '--rm', '--network=none', '--memory=128m', '--cpus=1', '--user=0',
            '-v', volume + ':/fixtures', '--entrypoint=/bin/sh', '-i', image,
            '-c', 'tar -xf - -C /fixtures; chown -R 1001:1001 /fixtures; chmod 700 /fixtures; chmod 600 /fixtures/*', input=fixtures.read_bytes())
        cid = run('docker', 'run', '-d', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--memory=128m', '--cpus=1', '--pids-limit=64', '--tmpfs', '/run:uid=1001,gid=1001,mode=700,size=4m',
            '--tmpfs', '/tmp:uid=1001,gid=1001,size=4m', '--tmpfs', '/workspace:uid=1001,gid=1001,size=8m',
            '-v', volume + ':/run/tunnex-ssh:ro', '-p', '127.0.0.1::22', image).decode().strip()
        port = run('docker', 'port', cid, '22/tcp').decode().strip().rsplit(':', 1)[1]
        hostpub = (p / 'host_key.pub').read_text().split()
        (p / 'known_hosts').write_text(f'[127.0.0.1]:{port} {hostpub[0]} {hostpub[1]}\n')
        opts = ['-i', str(p / 'client'), '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + str(p / 'known_hosts'), '-o', 'ConnectTimeout=2']
        for attempt in range(20):
            try:
                assert run('ssh', *opts, '-p', port, 'sandbox@127.0.0.1', 'id -u').strip() == b'1001'
                break
            except subprocess.CalledProcessError:
                time.sleep(.25)
        else:
            raise RuntimeError(run('docker', 'logs', cid).decode())
        result = subprocess.run(['ssh', *opts, '-p', port, 'sandbox@127.0.0.1', 'exit 37'], capture_output=True)
        assert result.returncode == 37
        payload = 'Unicode: 世界 café\n'.encode() + bytes(range(256)) * 4096
        (p / 'payload').write_bytes(payload)
        batch = f'put {p}/payload /workspace/roundtrip\nget /workspace/roundtrip {p}/returned\n'
        run('sftp', *opts, '-P', port, '-b', '-', 'sandbox@127.0.0.1', input=batch.encode())
        assert (p / 'returned').read_bytes() == payload
        wrong = p / 'wrong_hosts'
        wrong.write_text(f'[127.0.0.1]:{port} ' + (p / 'client.pub').read_text())
        wrong_opts = [arg.replace(str(p / 'known_hosts'), str(wrong)) for arg in opts]
        rejected = subprocess.run(['ssh', *wrong_opts, '-p', port, 'sandbox@127.0.0.1', 'true'], capture_output=True)
        assert rejected.returncode == 255
        # Restart retains the same externally supplied host key, verified by pin.
        run('docker', 'restart', cid)
        time.sleep(1)
        port = run('docker', 'port', cid, '22/tcp').decode().strip().rsplit(':', 1)[1]
        (p / 'known_hosts').write_text(f'[127.0.0.1]:{port} {hostpub[0]} {hostpub[1]}\n')
        run('ssh', *opts, '-p', port, 'sandbox@127.0.0.1', 'true')
        memory = int(run('docker', 'exec', cid, 'cat', '/sys/fs/cgroup/memory.current'))
        inventory = run('docker', 'exec', cid, 'apk', 'info', '-v').decode().splitlines()
        versions = {}
        if profile == 'python':
            versions['python'] = run('docker', 'exec', cid, 'python3', '--version').decode().strip()
            run('docker', 'exec', cid, 'python3', '-c', 'import ssl, sqlite3; assert 2+2 == 4')
        if profile == 'node':
            versions['node'] = run('docker', 'exec', cid, 'node', '--version').decode().strip()
            versions['npm'] = run('docker', 'exec', cid, 'npm', '--version').decode().strip()
            run('docker', 'exec', cid, 'node', '-e', 'if (2+2 !== 4) process.exit(1)')
        excluded = ['git'] + ([] if profile == 'python' else ['python3']) + ([] if profile == 'node' else ['node', 'npm'])
        for tool in excluded:
            result = subprocess.run(['docker', 'exec', cid, '/bin/sh', '-c', 'command -v "$1"', '--', tool], capture_output=True, timeout=30)
            assert result.returncode != 0, tool
        run('docker', 'exec', cid, '/usr/local/bin/tunnex-sandbox-bootstrap', '--help')
        export = p / 'image.tar'
        run('docker', 'save', '-o', str(export), image)
        with tarfile.open(export) as archive:
            index = json.load(archive.extractfile('index.json'))
            descriptor = index['manifests'][0]
            while True:
                manifest = json.load(archive.extractfile('blobs/sha256/' + descriptor['digest'].split(':')[1]))
                if 'layers' in manifest:
                    break
                descriptor = next(x for x in manifest['manifests'] if x.get('platform', {}).get('architecture') == arch)
            compressed = sum(layer['size'] for layer in manifest['layers'])

        print(json.dumps(dict(profile=profile, image_tag=image, image_id=info['Id'], platform_manifest_digest=descriptor['digest'], config_digest=manifest['config']['digest'], source_commit=info['Config']['Labels']['io.tunnex.sandbox.source'], compressed_layer_download_bytes=compressed, compressed_layers=manifest['layers'], emulated=emulated, versions=versions, excluded_tools=excluded, negative_tests=negative_tests, docker_reported_image_bytes=info['Size'], unpacked_filesystem_allocated_bytes=int(run('docker', 'run', '--rm', '--network=none', '--memory=128m', '--cpus=1', '--read-only', '--cap-drop=ALL', '--user=0', '--entrypoint=/usr/bin/du', image, '-sx', '-B1', '--exclude=/proc', '--exclude=/sys', '--exclude=/dev', '/').split()[0]), idle_cgroup_bytes=memory,
            memory_cap_bytes=134217728, workspace_tmpfs_cap_bytes=8388608, architecture=info['Architecture'],
            tests=['nonroot SSH uid1001', 'exit status 37', 'Unicode/binary SFTP roundtrip', 'pinned host identity', 'mismatched host identity rejected', 'same host identity after restart'],
            packages=inventory, payload_sha256=hashlib.sha256(payload).hexdigest()), indent=2))
    finally:
        if cid:
            run('docker', 'rm', '-f', cid)
        run('docker', 'volume', 'rm', volume)
