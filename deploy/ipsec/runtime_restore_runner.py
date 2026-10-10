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


def zero_tuple(value):
    # Go fixed wire arrays retain the exact empty inactive slot. The receipt
    # helper subsequently validates the complete strict typed journal/checksum.
    if isinstance(value, dict):
        return all(zero_tuple(v) for v in value.values())
    if isinstance(value, list):
        return not value
    return value is None or value is False or value == 0 or value in ('', '00000000-0000-0000-0000-000000000000')


def active_count(entry):
    contract = entry.get('ContractVersion')
    if type(contract) is not int:
        raise ValueError('invalid restoration contract')
    allocation = entry['Allocation']
    profile = allocation.get('ProfileID', '')
    if contract == 4 and profile == 'gcp-classic-static-ipv4-v1':
        count = 1
    elif contract == 3 and profile in ('', 'gcp-ha-bgp-ipv4-v1'):
        count = 2
    elif contract == 2 and profile == '':
        count = 2
    else:
        raise ValueError('unsupported restoration profile/contract')
    bgp = contract == 3
    if bool(allocation.get('BGP')) != bgp or bool(entry.get('BGP')) != bgp:
        raise ValueError('mixed restoration transport')
    if (contract == 2) != bool(entry.get('Recovery')):
        raise ValueError('mixed restoration recovery duty')
    for rows in (allocation['Tunnels'], entry['Engines'], entry['Observed']):
        if len(rows) != 2 or (count == 1 and not zero_tuple(rows[1])):
            raise ValueError('invalid restoration cardinality')
    for i in range(count):
        engine, tunnel = entry['Engines'][i], allocation['Tunnels'][i]
        if (engine.get('ProfileID', '') != profile or bool(engine.get('BGP')) != bgp
                or engine['TunnelID'] != tunnel['TunnelID'] or tunnel['Slot'] != i + 1
                or tunnel['Selected'] != (not bgp and i == 0)):
            raise ValueError('mixed restoration tunnel binding')
    return count


def active_entry(document, phases=('applied',)):
    entries = [e for e in document['Payload']['Entries'] if e['Phase'] != 'retained_refusal']
    if (len(entries) != 1 or entries[0]['Phase'] not in phases
            or entries[0].get('AbsenceOnly') or entries[0].get('ResetCleanup')):
        raise ValueError('requires exactly one applied restoration obligation')
    active_count(entries[0])
    return entries[0]


def poll_entry(document, before):
    entry = active_entry(document, phases=('reserved', 'applying', 'applied'))
    if (entry['DeliveryID'] != before['DeliveryID']
            or entry['ContractVersion'] != before['ContractVersion']
            or active_count(entry) != active_count(before)):
        raise ValueError('foreign restoration obligation')
    def allocation_identity(value):
        allocation = {k: v for k, v in value['Allocation'].items() if k not in ('Namespace', 'Generation', 'Tunnels')}
        allocation['Tunnels'] = [{k: v for k, v in tunnel.items() if k != 'Alias'} for tunnel in value['Allocation']['Tunnels']]
        return allocation
    def engine_identity(value):
        return [{k: v for k, v in engine.items() if k != 'LocalAddress'} for engine in value['Engines']]
    if allocation_identity(entry) != allocation_identity(before) or engine_identity(entry) != engine_identity(before):
        raise ValueError('restoration intent changed')
    return entry


def acceptance_result(before, after, started_utc, elapsed, resumed=False):
    metric = 'resume_wait_to_active_established_seconds' if resumed else 'stop_to_active_established_seconds'
    return {'version': 1, 'status': 'controller-and-tunnels-restored',
            'scope': 'controlled-supervisor-container-restart',
            'epoch': after['Restoration']['Epoch'], 'payload_verified': False,
            'started_utc': started_utc, 'active_tunnel_count': active_count(after),
            metric: round(elapsed, 3)}


def validate_previous_receipt(entry, raw):
    history = (entry.get('Restoration') or {}).get('Retired') or []
    if not history or history[-1]['EvidenceDigest'] != hashlib.sha256(raw).hexdigest():
        raise ValueError('existing receipt is not the exact retained prior restoration receipt')
    receipt = json.loads(raw)
    if receipt['DeliveryID'] != entry['DeliveryID'] or receipt['Namespace'] != entry['Allocation']['Namespace']:
        raise ValueError('previous receipt target differs from current runtime')


def validate_unconsumed_identity(entry, raw, archived, fresh, identity, boot, namespace, cgroup, ticks):
    if entry.get('Restoration') is not None or raw != archived:
        raise ValueError('receipt is consumed or differs from exact historical bytes')
    receipt = json.loads(raw)
    state = identity['state']
    if (receipt['DeliveryID'] != entry['DeliveryID'] or receipt['BootID'] != boot
            or receipt['Namespace'] != namespace or fresh['boot'] != boot
            or fresh['namespace'] != namespace or fresh['container'] != identity['id']
            or not state['Running'] or state.get('Restarting')
            or fresh['pid'] != state['Pid'] or fresh['started_at'] != state['StartedAt']
            or fresh['pid_start_ticks'] != ticks or ticks <= 0
            or cgroup != '0::/docker/' + identity['id']):
        raise ValueError('unconsumed receipt target is not the exact current fresh runtime')


def validate_unconsumed_receipt(args, entry, raw, identity):
    directory = Path(args.supersede_unconsumed_evidence_dir)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('historical attempt must be root-owned mode 0700')
    archived = proof.private_bytes(directory / 'receipt.json')
    fresh = proof.private_read(directory / 'fresh-runtime.json')
    journal_entries_unchanged(proof.private_bytes(directory / 'current-journal.json'), proof.private_bytes(args.journal))
    pid = identity['state']['Pid']
    process = Path('/proc/%d/stat' % pid).read_text()
    ticks = int(process.rsplit(') ', 1)[1].split()[19])
    validate_unconsumed_identity(entry, raw, archived, fresh, identity, proof.boot(),
        os.readlink('/proc/%d/ns/net' % pid), Path('/proc/%d/cgroup' % pid).read_text().strip(), ticks)
    proof.command(str(args.receipt_helper), '-journal', str(directory / 'stopped-journal.json'),
        '-evidence', str(directory / 'stopped.json'), '-fresh-runtime', str(directory / 'fresh-runtime.json'),
        '-current-journal', str(directory / 'current-journal.json'), '-boot', fresh['boot'],
        '-namespace', fresh['namespace'], '-verify-existing', str(directory / 'receipt.json'))
    if proof.inspect(identity['id']) != identity:
        raise ValueError('runtime changed during historical receipt verification')


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
    try:
        count = active_count(before)
        if after.get('AbsenceOnly') or after.get('ResetCleanup'):
            return False
        if active_count(after) != count or after['ContractVersion'] != before['ContractVersion']:
            return False
        if after['Allocation'].get('ProfileID', '') != before['Allocation'].get('ProfileID', ''):
            return False
        for i in range(count):
            a, b, o = after['Allocation']['Tunnels'][i], before['Allocation']['Tunnels'][i], after['Observed'][i]
            if (a['TunnelID'] != b['TunnelID'] or {k: v for k, v in after['Engines'][i].items() if k != 'LocalAddress'}
                    != {k: v for k, v in before['Engines'][i].items() if k != 'LocalAddress'}
                    or o.get('Namespace') != ns or type(o.get('InterfaceIndex')) is not int or o['InterfaceIndex'] <= 0
                    or o.get('InterfaceName') != a['Name'] or o.get('XFRMID') != a['XFRMID']):
                return False
        old_epoch = (before.get('Restoration') or {}).get('Epoch', 0)
        r = after.get('Restoration') or {}
        if not (after['DeliveryID'] == before['DeliveryID'] and after['Phase'] == 'applied'
                and r.get('Epoch') == old_epoch + 1
                and after['Allocation']['Namespace'] == ns
                and after['Allocation']['Generation'] != before['Allocation']['Generation']):
            return False
        if before['ContractVersion'] != 2:
            return True  # Classic has one static duty; HA has BGP, never recovery slots.
        prior = before['Recovery']
        expected = prior.get('PendingTo') if prior.get('Stage') == 'pending' else prior.get('SelectedSlot')
        recovery = after['Recovery']
        return (recovery.get('Stage') in ('', 'completed')
                and recovery.get('PendingFrom', 0) == 0 and recovery.get('PendingTo', 0) == 0
                and expected in (1, 2) and recovery.get('SelectedSlot') == expected
                and recovery.get('Sequence') == prior.get('Sequence'))
    except (ValueError, KeyError, TypeError):
        return False


def tunnels_installed(text, entry):
    # Human swanctl output has unindented IKE headers and indented CHILD lines.
    blocks = re.split(r'(?m)(?=^tnx-ipsec-)', text)
    try:
        count = active_count(entry)
    except (ValueError, KeyError, TypeError):
        return False
    for e in entry['Engines'][:count]:
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
    try:
        count = active_count(entry)
    except (ValueError, KeyError, TypeError):
        return False
    for allocated, observed in zip(entry['Allocation']['Tunnels'][:count], entry['Observed'][:count]):
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
        if getattr(args, 'supersede_unconsumed_evidence_dir', None):
            validate_unconsumed_receipt(args, entry, previous, identity)
        else:
            validate_previous_receipt(entry, previous)
    elif getattr(args, 'supersede_unconsumed_evidence_dir', None):
        raise ValueError('explicit supersession requires an existing receipt')
    # Serialize supervisor runs, without taking the agent's own journal lock.
    lock = Path(args.journal).parent / '.restoration-supervisor.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ValueError('unsafe supervisor lock')
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return identity, entry, target, previous, fd


def observe_fresh_runtime(before, stopped, journal_raw, current_journal, current, ns, gate, gate_raw, gate_identity):
    cid = before['container']
    state = current['state']
    pid = state['Pid']
    if (current['id'] != cid or not state['Running'] or state.get('Restarting')
            or pid <= 0 or pid == before['pid'] or state['StartedAt'] == before['started']
            or proof.boot() != before['boot']):
        raise ValueError('fresh container instance not independently observed')
    if Path('/proc/%d/cgroup' % pid).read_text().strip() != '0::/docker/' + cid:
        raise ValueError('fresh runtime is outside the exact dedicated container cgroup')
    process = Path('/proc/%d/stat' % pid).read_text()
    ticks = int(process.rsplit(') ', 1)[1].split()[19])
    if ticks <= 0 or os.readlink('/proc/%d/ns/net' % pid) != ns:
        raise ValueError('fresh runtime process identity invalid')
    info = Path(gate).lstat()
    if (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600
            or not stat.S_ISREG(info.st_mode) or not os.path.samestat(info, gate_identity)
            or proof.private_bytes(gate) != gate_raw):
        raise ValueError('retained startup gate changed')
    if proof.inspect(cid) != current or proof.boot() != before['boot']:
        raise ValueError('fresh runtime changed during observation')
    return {'version': 1, 'kind': 'supervisor-confirmed-fresh-runtime',
            'container': cid, 'boot': before['boot'], 'namespace': ns, 'pid': pid,
            'pid_start_ticks': ticks, 'started_at': state['StartedAt'],
            'stop_evidence_sha256': hashlib.sha256(stopped).hexdigest(),
            'stopped_journal_sha256': hashlib.sha256(journal_raw).hexdigest(),
            'current_journal_sha256': hashlib.sha256(current_journal).hexdigest(),
            'startup_gate_sha256': hashlib.sha256(gate_raw).hexdigest(),
            'startup_gate_device': info.st_dev, 'startup_gate_inode': info.st_ino}


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
        if getattr(args, 'supersede_unconsumed_evidence_dir', None):
            # Recheck after acquiring the supervisor lock and creating this run's
            # gate, before any stop. The historical receipt never authorizes this stop.
            validate_unconsumed_receipt(args, before_entry, proof.private_bytes(target), identity)
        before = proof.snapshot(cid, args.journal)
        if getattr(args, 'supersede_unconsumed_evidence_dir', None):
            if (before['pid'] != identity['state']['Pid'] or before['started'] != identity['state']['StartedAt']
                    or proof.inspect(cid) != identity):
                raise ValueError('exact historical target changed before new stop snapshot')
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
        return finish_restoration(args, cid, before_entry, before, directory, journal_raw, target, previous, gate, gate_raw, gate_identity, stop_started, started_utc)
    except Exception:
        if stopped:
            # Restore the same process container only; no cleanup, receipts, or CP toggles.
            try:
                proof.command('docker', 'start', cid)
                print('Container restarted after proof failure; recovery remains unproven.', flush=True)
            except Exception:
                print('Container restart failed; operator recovery required.', flush=True)
        proof.private_write(directory / 'failure.json', {'version': 1, 'status': 'failed', 'receipt_installed': target.exists() and proof.private_bytes(target) != previous, 'startup_gate_present': os.path.lexists(gate)})
        if os.path.lexists(gate):
            print('Startup gate retained: runtime restoration remains refused until explicit recovery.', flush=True)
        raise
    finally:
        os.close(lock)

def finish_restoration(args, cid, before_entry, before, directory, journal_raw, target, previous, gate, gate_raw, gate_identity, stop_started, started_utc, resumed=False):
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
    if proof.state_mount(current, args.journal) != before['state_mount']:
        raise ValueError('original state mount changed')
    current_journal = proof.private_bytes(args.journal)
    journal_entries_unchanged(journal_raw, current_journal)
    write_bytes(directory / 'current-journal.json', current_journal)
    fresh = observe_fresh_runtime(before, proof.private_bytes(directory / 'stopped.json'),
                                  journal_raw, current_journal, current, ns, gate, gate_raw, gate_identity)
    proof.private_write(directory / 'fresh-runtime.json', fresh)
    assembled = directory / 'receipt.json'
    proof.command(str(args.receipt_helper), '-journal', str(directory / 'stopped-journal.json'),
                  '-evidence', str(directory / 'stopped.json'), '-boot', new_boot,
                  '-namespace', ns, '-fresh-runtime', str(directory / 'fresh-runtime.json'),
                  '-startup-gate', str(gate), '-current-journal', str(directory / 'current-journal.json'), '-out', str(assembled))
    raw = proof.private_bytes(assembled)
    # Do not overwrite an unknown receipt or follow a changed path.
    now_previous = proof.private_bytes(target) if os.path.lexists(target) else None
    if now_previous != previous:
        raise ValueError('receipt changed while restart was in progress')
    again = proof.inspect(cid)
    if again['state']['Pid'] != pid or again['state']['StartedAt'] != current['state']['StartedAt'] or not again['state']['Running']:
        raise ValueError('new runtime changed before receipt installation')
    journal_entries_unchanged(journal_raw, proof.private_bytes(args.journal))
    gate_now = gate.lstat()
    if not os.path.samestat(gate_now, gate_identity) or proof.private_bytes(gate) != gate_raw:
        raise ValueError('startup gate changed before receipt installation')
    temporary = target.parent / ('.restore-' + str(uuid.uuid4()) + '.tmp')
    write_bytes(temporary, raw)
    os.replace(temporary, target)
    sync_directory(target.parent)
    receipt_installed = True
    # The gate blocks startup from reusing old ownership if Linux recycles the
    # namespace inode. Only remove this run's exact gate after receipt fsync.
    release_gate(gate, gate_raw, gate_identity)
    print('Bound receipt installed; awaiting journal restoration and active tunnel sessions.', flush=True)
    while time.monotonic() < deadline:
        after = poll_entry(proof.private_read(args.journal), before_entry)
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
                    result = acceptance_result(before_entry, after, started_utc,
                                               time.monotonic() - stop_started, resumed=resumed)
                    proof.private_write(directory / 'result.json', result)
                    print('PASS: controller restoration and all active fresh tunnel sessions. Client payload verification remains separate.', flush=True)
                    return result
            except subprocess.CalledProcessError:
                pass
        time.sleep(2)
    raise TimeoutError('bounded recovery wait expired; journal and receipt preserved')

def journal_entries_unchanged(stopped, current):
    before = json.loads(stopped)['Payload']
    after = json.loads(current)['Payload']
    if (before['Entries'] != after['Entries'] or before['OwnerID'] != after['OwnerID']
            or before['Version'] != after['Version'] or after['Sequence'] < before['Sequence']):
        raise ValueError('immutable journal lineage changed')
    # Complete checksum, typed entries and guard validity are independently
    # checked by the receipt helper's product reader on both private snapshots.


def resume(args):
    if os.geteuid() != 0:
        raise ValueError('requires Docker host root')
    directory = Path(args.resume_evidence_dir)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('original evidence directory must be root-owned mode 0700')
    helper=Path(args.receipt_helper)
    helper_info=helper.lstat()
    if not stat.S_ISREG(helper_info.st_mode) or helper_info.st_uid!=0 or helper_info.st_mode & 0o022 or not os.access(helper,os.X_OK):
        raise ValueError('unsafe receipt helper')
    before = proof.private_read(directory / 'before.json')
    stopped = proof.private_read(directory / 'stopped.json')
    journal_raw = proof.private_bytes(directory / 'stopped-journal.json')
    if (stopped['snapshot'] != before
            or hashlib.sha256(journal_raw).hexdigest() != stopped['stopped_journal_raw_sha256']):
        raise ValueError('captured stop proof or current journal changed; explicit diagnosis required')
    journal_entries_unchanged(journal_raw, proof.private_bytes(args.journal))
    current = proof.inspect(args.container)
    if proof.command('docker', 'inspect', '--format', '{{.HostConfig.RestartPolicy.Name}}', current['id']) != 'no':
        raise ValueError('automatic Docker restart policy must remain disabled')
    if current['id'] != before['container'] or proof.state_mount(current, args.journal) != before['state_mount']:
        raise ValueError('original container/state mount changed')
    gate = Path(args.journal).parent / 'restoration-startup-gate'
    gate_raw = proof.private_bytes(gate)
    expected = json.dumps({'Version': 1, 'SupervisorRun': directory.name, 'ContainerID': before['container']}, sort_keys=True).encode()
    record = proof.private_read(directory / 'startup-gate.json')
    if (gate_raw != expected or record['file'] != str(gate)
            or record['sha256'] != hashlib.sha256(gate_raw).hexdigest()):
        raise ValueError('existing startup gate is not owned by the original run')
    gate_identity = gate.lstat()
    before_entry = active_entry(json.loads(journal_raw))
    target = Path(args.journal).parent / ('restore-' + before_entry['DeliveryID'] + '.json')
    previous = proof.private_bytes(directory / 'previous-receipt.json') if os.path.lexists(directory / 'previous-receipt.json') else None
    now_previous = proof.private_bytes(target) if os.path.lexists(target) else None
    if previous != now_previous:
        raise ValueError('receipt already changed; resume refused')
    lock = os.open(Path(args.journal).parent / '.restoration-supervisor.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('unsafe supervisor lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Historical gate dev/inode was not persisted by older runners. Observe
        # and hold its CURRENT exact identity after matching the original private
        # hash/run/container record; never invent a historical inode claim.
        attempt = directory / ('resume-' + str(uuid.uuid4()))
        attempt.mkdir(mode=0o700)
        write_bytes(attempt / 'stopped.json', proof.private_bytes(directory / 'stopped.json'))
        write_bytes(attempt / 'stopped-journal.json', journal_raw)
        return finish_restoration(args, before['container'], before_entry, before, attempt,
                                  journal_raw, target, previous, gate, gate_raw, gate_identity,
                                  time.monotonic(), datetime.datetime.now(datetime.timezone.utc).isoformat(), resumed=True)
    finally:
        os.close(lock)



def main():
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('container', 'journal', 'receipt-helper', 'evidence-dir', 'swanctl', 'vici', 'strongswan-conf'):
        p.add_argument('--' + option, required=True)
    p.add_argument('--resume-evidence-dir', help='explicitly resume the exact captured stopped run; never synthesize stop proof')
    p.add_argument('--supersede-unconsumed-evidence-dir', help='explicit exact prior attempt; verify and preserve receipt before a NEW controlled stop')
    p.add_argument('--timeout', type=int, required=True)
    p.add_argument('--stop-timeout', type=int, required=True)
    args = p.parse_args()
    if not 10 <= args.timeout <= 600 or not 1 <= args.stop_timeout <= 45:
        p.error('bounded timeout required: recovery 10..600 seconds; stop 1..45 seconds')
    if args.resume_evidence_dir and args.supersede_unconsumed_evidence_dir:
        p.error('resume and fresh-stop supersession are distinct workflows')
    resume(args) if args.resume_evidence_dir else run(args)


if __name__ == '__main__':
    main()
