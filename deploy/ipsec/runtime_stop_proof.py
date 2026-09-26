#!/usr/bin/env python3
"""Root-only, read-only Docker stop observer. Never stops or restarts a workload.

Run on the Linux Docker HOST (not a container): snapshot before a controlled
stop; prove while the exact container remains stopped. Output is lifecycle
evidence, NOT authorization or a controller restoration receipt.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


def command(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def inspect(container):
    # Deliberately exclude Config/Env: they can contain credentials.
    return {
        'id': command('docker', 'inspect', '--format', '{{.Id}}', container),
        'state': json.loads(command('docker', 'inspect', '--format', '{{json .State}}', container)),
        'sandbox': command('docker', 'inspect', '--format', '{{.NetworkSettings.SandboxKey}}', container),
        'mounts': json.loads(command('docker', 'inspect', '--format', '{{json .Mounts}}', container)),
    }


def boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def private_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600 or not stat.S_ISREG(st.st_mode):
            raise ValueError('unsafe evidence file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def private_read(path):
    return json.loads(private_bytes(path))


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def unescape_mount(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), value)


def namespace_holders(ns):
    """Scan all host threads, open descriptors and nsfs mounts in every mnt ns.

    Disappearing processes are harmless; permission/parse errors fail closed.
    Two passes bracketed by stopped-container checks are required by prove().
    """
    wanted = (ns['device'], ns['inode'])
    found = []
    def check(path):
        try:
            s = os.stat(path)
            if (s.st_dev, s.st_ino) == wanted:
                found.append(str(path))
        except (FileNotFoundError, ProcessLookupError):
            pass
    seen_mounts = set()
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            for thread in (proc / 'task').iterdir():
                check(thread / 'ns/net')
                for fd in (thread / 'fd').iterdir():
                    check(fd)
            mount_ns = os.readlink(proc / 'ns/mnt')
            if mount_ns in seen_mounts:
                continue
            # Mount paths are resolved through this process's root, not ours.
            for line in (proc / 'mountinfo').read_text().splitlines():
                before, after = line.split(' - ', 1)
                if after.split()[0] == 'nsfs':
                    target = unescape_mount(before.split()[4])
                    check(str(proc / 'root') + target)
            seen_mounts.add(mount_ns)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return found


def journal_entries_digest(document):
    payload = document['Payload']
    if not isinstance(payload['Entries'], list) or not payload['OwnerID']:
        raise ValueError('invalid journal identity or entries')
    binding = {'OwnerID': payload['OwnerID'], 'Entries': payload['Entries']}
    return hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def state_mount(identity, journal):
    mounts = [m for m in identity['mounts'] if m['Destination'] == '/var/lib/tunnex-node']
    if len(mounts) != 1 or mounts[0]['Type'] not in ('volume', 'bind') or not mounts[0]['RW']:
        raise ValueError('expected exactly one writable gateway state mount')
    mount = mounts[0]
    expected = Path(mount['Source']) / 'ipsec/journal.json'
    if Path(journal).resolve() != expected.resolve():
        raise ValueError('journal does not belong to exact stopped container state mount')
    return {'source': mount['Source'], 'destination': mount['Destination'], 'type': mount['Type']}


def snapshot(container, journal):
    journal_raw = private_bytes(journal)
    journal_value = json.loads(journal_raw)
    journal_digest = journal_entries_digest(journal_value)
    identity = inspect(container)
    mount = state_mount(identity, journal)
    s = identity['state']
    if not re.fullmatch('[0-9a-f]{64}', identity['id']) or not s['Running'] or s['Pid'] <= 0:
        raise ValueError('expected exact running Docker container')
    pid = s['Pid']
    ns = os.stat(f'/proc/{pid}/ns/net')
    cg = Path(f'/proc/{pid}/cgroup').read_text().strip()
    expected = '0::/docker/' + identity['id']
    if cg != expected:
        raise ValueError('unsupported cgroup layout; requires dedicated cgroup v2 Docker host')
    b = boot()
    again = inspect(identity['id'])
    if again != identity:
        raise ValueError('runtime changed during snapshot')
    return {'version': 1, 'boot': b, 'container': identity['id'],
            'pid': pid, 'started': s['StartedAt'], 'sandbox': identity['sandbox'], 'state_mount': mount,
            'namespace': {'device': ns.st_dev, 'inode': ns.st_ino},
            'cgroup': '/sys/fs/cgroup/docker/' + identity['id'],
            'observed_ns': time.time_ns(), 'journal': str(Path(journal).resolve()),
            'journal_entries_sha256': journal_digest,
            'journal_raw_sha256': hashlib.sha256(journal_raw).hexdigest()}


def validate_stopped(before, identity, current_boot):
    if state_mount(identity, before['journal']) != before['state_mount']:
        raise ValueError('state mount changed')
    s = identity['state']
    if current_boot != before['boot'] or identity['id'] != before['container']:
        raise ValueError('boot/container identity changed')
    if s['Running'] or s['Pid'] != 0 or s.get('Restarting') or s['StartedAt'] != before['started']:
        raise ValueError('exact prior runtime is not stably stopped')
    if not s.get('FinishedAt') or s['FinishedAt'].startswith('0001-'):
        raise ValueError('missing Docker termination timestamp')


def prove(before):
    if before.get('version') != 1 or not re.fullmatch('[0-9a-f]{64}', before['container']):
        raise ValueError('invalid snapshot')
    if before['cgroup'] != '/sys/fs/cgroup/docker/' + before['container']:
        raise ValueError('foreign cgroup')
    current_raw = private_bytes(before['journal'])
    current_journal = json.loads(current_raw)
    if journal_entries_digest(current_journal) != before['journal_entries_sha256']:
        raise ValueError('journal entries changed after runtime snapshot; take a fresh snapshot')
    for _ in range(2):
        validate_stopped(before, inspect(before['container']), boot())
        events_path = Path(before['cgroup']) / 'cgroup.events'
        if events_path.exists() and 'populated 0' not in events_path.read_text().splitlines():
            raise ValueError('old cgroup still populated')
        if namespace_holders(before['namespace']):
            raise ValueError('old namespace still referenced by a thread, descriptor, or mount')
        validate_stopped(before, inspect(before['container']), boot())
    end = time.time_ns()
    raw = command('docker', 'events', '--since', str(before['observed_ns'] // 1000000000),
                  '--until', str(end // 1000000000 + 1), '--filter',
                  'container=' + before['container'], '--filter', 'event=die', '--format', '{{json .}}')
    matching = []
    for line in raw.splitlines():
        event = json.loads(line)
        event_id = event.get('Actor', {}).get('ID', event.get('id'))
        if event_id == before['container'] and event.get('Action', event.get('status')) == 'die' and event.get('timeNano', 0) >= before['observed_ns']:
            matching.append({'container': event_id, 'action': 'die', 'time_ns': event['timeNano']})
    if len(matching) != 1:
        raise ValueError('missing or ambiguous retained Docker die event')
    validate_stopped(before, inspect(before['container']), boot())
    final_raw = private_bytes(before['journal'])
    if final_raw != current_raw:
        raise ValueError('stopped journal changed during proof')
    return {'version': 1, 'kind': 'supervisor-confirmed-runtime-stop',
            'stopped_journal_raw_sha256': hashlib.sha256(final_raw).hexdigest(),
            'snapshot': before, 'termination': matching[0], 'verified_ns': end,
            'checks': ['exact-stopped-runtime', 'empty-cgroup', 'no-namespace-holders-two-passes']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['snapshot', 'prove'])
    parser.add_argument('--container')
    parser.add_argument('--snapshot')
    parser.add_argument('--journal')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path('/proc/1').exists():
        raise SystemExit('Requires root on the Linux Docker host')
    value = snapshot(args.container, args.journal) if args.mode == 'snapshot' else prove(private_read(args.snapshot))
    private_write(args.output, value)
    print('Lifecycle evidence saved; controller authorization remains separate.')


if __name__ == '__main__':
    main()
