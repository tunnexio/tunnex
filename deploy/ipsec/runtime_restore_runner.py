#!/usr/bin/env python3
"""Automate an explicitly requested Docker gateway restart and restoration.

Run on the real Linux Docker host as root. This is a controlled supervisor
workflow, not an unexpected-crash detector or a host/VM reboot qualification.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

import runtime_stop_proof as proof


def active_entry(document):
    entries = [e for e in document['Payload']['Entries'] if e['Phase'] != 'retained_refusal']
    if len(entries) != 1 or entries[0]['Phase'] != 'applied' or entries[0].get('ContractVersion') != 2:
        raise ValueError('requires exactly one applied recovery obligation')
    return entries[0]


def validate_previous_receipt(entry, raw):
    history = entry.get('Restoration', {}).get('Retired') or []
    if not history or history[-1]['EvidenceDigest'] != hashlib.sha256(raw).hexdigest():
        raise ValueError('existing receipt is not the exact retained prior restoration receipt')
    receipt = json.loads(raw)
    if receipt['DeliveryID'] != entry['DeliveryID'] or receipt['Namespace'] != entry['Allocation']['Namespace']:
        raise ValueError('previous receipt target differs from current runtime')


def write_bytes(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(Path(path).parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def restored(before, after, ns):
    old_epoch = (before.get('Restoration') or {}).get('Epoch', 0)
    r = after.get('Restoration') or {}
    prior_duty = before.get('Recovery') or {}
    expected_slot = prior_duty.get('PendingTo') if prior_duty.get('Stage') == 'pending' else prior_duty.get('SelectedSlot')
    return (after['DeliveryID'] == before['DeliveryID'] and after['Phase'] == 'applied'
            and r.get('Epoch') == old_epoch + 1
            and after['Allocation']['Namespace'] == ns
            and after['Allocation']['Generation'] != before['Allocation']['Generation']
            and len(after['Observed']) == 2
            and all(o['Namespace'] == ns and o['InterfaceIndex'] > 0 for o in after['Observed'])
            and (after.get('Recovery') or {}).get('Stage') in ('', 'completed')
            and (after.get('Recovery') or {}).get('PendingFrom', 0) == 0
            and (after.get('Recovery') or {}).get('PendingTo', 0) == 0
            and expected_slot in (1, 2)
            and (after.get('Recovery') or {}).get('SelectedSlot') == expected_slot
            and (after.get('Recovery') or {}).get('Sequence') == prior_duty.get('Sequence'))


def tunnels_installed(text, entry):
    # Human swanctl output has unindented IKE headers and indented CHILD lines.
    blocks = re.split(r'(?m)(?=^tnx-ipsec-)', text)
    for e in entry['Engines']:
        b = e['Binding']
        name = 'tnx-ipsec-%s-d%s-c%s-s%s' % (e['TunnelID'], b['DesiredRevision'], b['ConfigurationRevision'], e['SecretRevision'])
        found = False
        for block in blocks:
            lines = block.splitlines()
            if lines and lines[0].startswith(name + ':') and 'ESTABLISHED' in lines[0]:
                found = any(line.lstrip().startswith(name + ':') and 'INSTALLED' in line for line in lines[1:])
                if found:
                    break
        if not found:
            return False
    return True


def links_owned(links, entry):
    for allocated, observed in zip(entry['Allocation']['Tunnels'], entry['Observed']):
        matches = [link for link in links if link.get('ifname') == allocated['Name']]
        if len(matches) != 1:
            return False
        link = matches[0]
        info = link.get('linkinfo', {})
        xfrm_id = info.get('info_data', {}).get('if_id')
        if isinstance(xfrm_id, str) and re.fullmatch(r'(?:0x[0-9a-fA-F]+|[0-9]+)', xfrm_id):
            xfrm_id = int(xfrm_id, 16 if xfrm_id.startswith('0x') else 10)
        if (link.get('ifindex') != observed['InterfaceIndex']
                or link.get('ifalias') != allocated['Alias']
                or info.get('info_kind') != 'xfrm'
                or type(xfrm_id) is not int or xfrm_id != allocated['XFRMID']):
            return False
    return True


def release_gate(path, expected_raw, identity):
    current = Path(path).lstat()
    if (identity is None or not stat.S_ISREG(current.st_mode) or current.st_uid != 0
            or stat.S_IMODE(current.st_mode) != 0o600
            or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
            or proof.private_bytes(path) != expected_raw):
        raise ValueError('startup gate identity changed; retained for explicit recovery')
    os.unlink(path)
    sync_directory(Path(path).parent)


def preflight(args):
    if os.geteuid() != 0:
        raise ValueError('requires Docker host root')
    directory = Path(args.evidence_dir)
    st = directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError('evidence directory must exist as root-owned mode 0700')
    helper = Path(args.receipt_helper)
    h = helper.lstat()
    if not stat.S_ISREG(h.st_mode) or h.st_uid != 0 or h.st_mode & 0o022 or not os.access(helper, os.X_OK):
        raise ValueError('receipt helper must be root-owned, executable, and not writable by others')
    identity = proof.inspect(args.container)
    policy = proof.command('docker', 'inspect', '--format', '{{.HostConfig.RestartPolicy.Name}}', identity['id'])
    if policy != 'no':
        raise ValueError('automatic Docker restart policy must be disabled before controlled supervision')
    proof.state_mount(identity, args.journal)
    gate = Path(args.journal).parent / 'restoration-startup-gate'
    if os.path.lexists(gate):
        raise ValueError('preexisting restoration startup gate requires explicit recovery')
    entry = active_entry(proof.private_read(args.journal))
    uuid.UUID(entry['DeliveryID'])
    target = Path(args.journal).parent / ('restore-' + entry['DeliveryID'] + '.json')
    previous = None
    if os.path.lexists(target):
        previous = proof.private_bytes(target)
        validate_previous_receipt(entry, previous)
    # Serialize supervisor runs, without taking the agent's own journal lock.
    lock = Path(args.journal).parent / '.restoration-supervisor.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ValueError('unsafe supervisor lock')
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return identity, entry, target, previous, fd


def run(args):
    identity, before_entry, target, previous, lock = preflight(args)
    cid = identity['id']
    directory = Path(args.evidence_dir) / ('run-' + str(uuid.uuid4()))
    directory.mkdir(mode=0o700)
    print('Evidence directory: ' + str(directory), flush=True)
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    stop_started = None
    stopped = False
    receipt_installed = False
    gate = Path(args.journal).parent / 'restoration-startup-gate'
    gate_raw = json.dumps({'Version': 1, 'SupervisorRun': directory.name, 'ContainerID': cid}, sort_keys=True).encode()
    gate_identity = None
    try:
        write_bytes(gate, gate_raw)
        gate_identity = gate.lstat()
        proof.private_write(directory / 'startup-gate.json', {'file': str(gate), 'sha256': hashlib.sha256(gate_raw).hexdigest()})
        before = proof.snapshot(cid, args.journal)
        proof.private_write(directory / 'before.json', before)
        if previous is not None:
            write_bytes(directory / 'previous-receipt.json', previous)
        print('Snapshot captured; controlled stop starting.', flush=True)
        # Mark before invocation: even a CLI timeout may have stopped the runtime.
        stopped = True
        stop_started = time.monotonic()
        proof.command('docker', 'stop', '--time', str(args.stop_timeout), cid)
        evidence = proof.prove(before)
        proof.private_write(directory / 'stopped.json', evidence)
        journal_raw = proof.private_bytes(args.journal)
        if hashlib.sha256(journal_raw).hexdigest() != evidence['stopped_journal_raw_sha256']:
            raise ValueError('stopped journal changed')
        write_bytes(directory / 'stopped-journal.json', journal_raw)
        print('Exact stop proof captured; starting same container.', flush=True)
        proof.command('docker', 'start', cid)
        stopped = False
        deadline = time.monotonic() + args.timeout
        current = proof.inspect(cid)
        while not current['state']['Running'] or current['state']['Pid'] <= 0:
            if time.monotonic() >= deadline:
                raise TimeoutError('container failed to start')
            time.sleep(1)
            current = proof.inspect(cid)
        pid = current['state']['Pid']
        ns = os.readlink('/proc/%d/ns/net' % pid)
        new_boot = proof.boot()
        if new_boot != before['boot'] or current['state']['StartedAt'] == before.get('started'):
            raise ValueError('expected a fresh container runtime in the same host boot')
        proof.state_mount(current, args.journal)
        assembled = directory / 'receipt.json'
        proof.command(str(args.receipt_helper), '-journal', str(directory / 'stopped-journal.json'),
                      '-evidence', str(directory / 'stopped.json'), '-boot', new_boot,
                      '-namespace', ns, '-out', str(assembled))
        raw = proof.private_bytes(assembled)
        # Do not overwrite an unknown receipt or follow a changed path.
        now_previous = proof.private_bytes(target) if os.path.lexists(target) else None
        if now_previous != previous:
            raise ValueError('receipt changed while restart was in progress')
        again = proof.inspect(cid)
        if again['state']['Pid'] != pid or again['state']['StartedAt'] != current['state']['StartedAt'] or not again['state']['Running']:
            raise ValueError('new runtime changed before receipt installation')
        temporary = target.parent / ('.restore-' + str(uuid.uuid4()) + '.tmp')
        write_bytes(temporary, raw)
        os.replace(temporary, target)
        sync_directory(target.parent)
        receipt_installed = True
        # The gate blocks startup from reusing old ownership if Linux recycles the
        # namespace inode. Only remove this run's exact gate after receipt fsync.
        release_gate(gate, gate_raw, gate_identity)
        print('Bound receipt installed; awaiting journal recovery and both tunnel sessions.', flush=True)
        while time.monotonic() < deadline:
            after = active_entry(proof.private_read(args.journal))
            if restored(before_entry, after, ns):
                try:
                    sas = proof.command('docker', 'exec', '-e', 'STRONGSWAN_CONF=' + args.strongswan_conf,
                                        cid, args.swanctl, '--list-sas', '--uri', args.vici)
                    links = json.loads(proof.command('docker', 'exec', cid, 'ip', '-j', '-d', 'link', 'show'))
                    if tunnels_installed(sas, after) and links_owned(links, after):
                        final = proof.inspect(cid)
                        if (not final['state']['Running'] or final['state']['Pid'] != pid
                                or final['state']['StartedAt'] != current['state']['StartedAt']
                                or os.readlink('/proc/%d/ns/net' % pid) != ns or proof.boot() != new_boot):
                            raise ValueError('runtime identity changed during acceptance')
                        result = {'version': 1, 'status': 'controller-and-tunnels-restored',
                                  'scope': 'controlled-supervisor-container-restart',
                                  'epoch': after['Restoration']['Epoch'], 'payload_verified': False,
                                  'started_utc': started_utc, 'stop_to_both_established_seconds': round(time.monotonic() - stop_started, 3)}
                        proof.private_write(directory / 'result.json', result)
                        print('PASS: controller restoration and both fresh tunnel sessions. Client payload verification remains separate.', flush=True)
                        return result
                except subprocess.CalledProcessError:
                    pass
            time.sleep(2)
        raise TimeoutError('bounded recovery wait expired; journal and receipt preserved')
    except Exception:
        if stopped:
            # Restore the same process container only; no cleanup, receipts, or CP toggles.
            try:
                proof.command('docker', 'start', cid)
                print('Container restarted after proof failure; recovery remains unproven.', flush=True)
            except Exception:
                print('Container restart failed; operator recovery required.', flush=True)
        proof.private_write(directory / 'failure.json', {'version': 1, 'status': 'failed', 'receipt_installed': receipt_installed, 'startup_gate_present': os.path.lexists(gate)})
        if os.path.lexists(gate):
            print('Startup gate retained: runtime restoration remains refused until explicit recovery.', flush=True)
        raise
    finally:
        os.close(lock)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('container', 'journal', 'receipt-helper', 'evidence-dir', 'swanctl', 'vici', 'strongswan-conf'):
        p.add_argument('--' + option, required=True)
    p.add_argument('--timeout', type=int, required=True)
    p.add_argument('--stop-timeout', type=int, required=True)
    args = p.parse_args()
    if not 10 <= args.timeout <= 600 or not 1 <= args.stop_timeout <= 20:
        p.error('bounded timeout required: recovery 10..600 seconds; stop 1..20 seconds')
    run(args)


if __name__ == '__main__':
    main()
