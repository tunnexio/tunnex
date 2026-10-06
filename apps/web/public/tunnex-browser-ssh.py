#!/usr/bin/env python3
"""Root-managed dedicated SSH certificate listener with Linux OS preflight."""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path('/etc/tunnex-browser-ssh')
UNIT = Path('/etc/systemd/system/tunnex-browser-sshd.service')
SERVICE = 'tunnex-browser-sshd'
MARKER = 'tunnex-browser-ssh-v1'
BUNDLE = None  # Replaced only in the administrator-downloaded server bundle.

def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)

def safe_tree():
    for parent in (Path('/etc'), Path('/etc/systemd'), UNIT.parent, ROOT):
        if parent.is_symlink():
            raise ValueError(f'Refusing symlink: {parent}')
        if parent.exists() and (parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022):
            raise ValueError(f'Refusing non-root-owned or writable path: {parent}')
    if UNIT.is_symlink():
        raise ValueError('Refusing symlink service unit')
    if ROOT.exists():
        for p in ROOT.rglob('*'):
            if p.is_symlink() or not (p.is_dir() or p.is_file()):
                raise ValueError(f'Refusing unexpected file type: {p}')
            if p.stat().st_uid != 0 or p.stat().st_mode & 0o022:
                raise ValueError(f'Refusing non-root-owned or writable file: {p}')

def write(path, value, mode=0o644):
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as f:
            f.write(value)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def identity(org, server, account):
    uuid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    if not re.fullmatch(uuid, org) or not re.fullmatch(uuid, server):
        raise ValueError('Use exact organization and registered server UUIDs from Tunnex')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', account):
        raise ValueError('Invalid Linux account name')
    u = pwd.getpwnam(account)
    if u.pw_uid == 0 or u.pw_shell in ('/bin/false', '/usr/sbin/nologin', '/sbin/nologin'):
        raise ValueError('Account must be an existing non-root login account')
    return f'tunnex:{org}:{server}:{account}'

def load():
    m = json.loads((ROOT / 'managed.json').read_text())
    if m.get('owner') != MARKER or MARKER not in UNIT.read_text():
        raise ValueError('Existing configuration is not owned by this helper')
    return m

def render(m):
    accounts = ' '.join(sorted(m['accounts']))
    return f'''# {MARKER}
Port {m['port']}
ListenAddress 0.0.0.0
HostKey {ROOT}/host
PidFile /run/tunnex-browser-sshd.pid
TrustedUserCAKeys {ROOT}/ca.pub
AuthorizedPrincipalsFile {ROOT}/principals/%u
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM yes
AllowUsers {accounts}
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserRC no
LogLevel VERBOSE
'''

def apply(m):
    write(ROOT / 'sshd.conf', render(m))
    run('/usr/sbin/sshd', '-t', '-f', str(ROOT / 'sshd.conf'))
    write(ROOT / 'managed.json', json.dumps(m, indent=2) + '\n', 0o600)

def reload():
    run('systemctl', 'kill', '--kill-whom=main', '--signal=HUP', SERVICE)
    run('systemctl', 'is-active', '--quiet', SERVICE)

def report(m):
    print(f'Dedicated SSH port: {m["port"]}; accounts: {", ".join(sorted(m["accounts"]))}')
    run('ssh-keygen', '-lf', str(ROOT / 'host.pub'), '-E', 'sha256')
    print('Independently verify this host fingerprint, save it in Tunnex, then run Check for each account.')
    print('Access grants and recent MFA remain required. Management SSH port 22 is unchanged.')

def eligible_accounts():
    uid_min = 1000
    defs = Path('/etc/login.defs')
    if defs.exists():
        match = re.search(r'^\s*UID_MIN\s+(\d+)', defs.read_text(), re.MULTILINE)
        if match:
            uid_min = max(1, int(match.group(1)))
    shells = Path('/etc/shells')
    allowed = {line.strip() for line in shells.read_text().splitlines() if line.strip().startswith('/')} if shells.exists() else {'/bin/bash', '/bin/sh', '/usr/bin/bash', '/usr/bin/sh'}
    return sorted({u.pw_name for u in pwd.getpwall() if is_eligible(u, uid_min, allowed)})

def is_eligible(u, uid_min, shells):
    return (uid_min <= u.pw_uid < 65534 and u.pw_shell in shells
            and Path(u.pw_shell).name not in ('false', 'nologin')
            and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', u.pw_name) is not None)

def selected_accounts(args):
    eligible = eligible_accounts()
    selected = eligible if args.all_login_users else sorted(set(args.accounts.split(',')))
    if not selected or any(account not in eligible for account in selected):
        raise ValueError('Choose existing eligible non-system login accounts: ' + ', '.join(eligible))
    if len(selected) > 16:
        raise ValueError('This server supports at most 16 accounts. Use --accounts to select up to 16 eligible users.')
    return selected

def sync(m, accounts):
    accounts = sorted(set(m['accounts'] + accounts))
    if len(accounts) > 16:
        raise ValueError('This server supports at most 16 configured accounts')
    fp = run('ssh-keygen', '-lf', str(ROOT / 'ca.pub'), '-E', 'sha256', capture_output=True).stdout.split()[1]
    if fp != m['ca_fingerprint']:
        raise ValueError('Installed CA changed; inspect trust before adding accounts')
    principals = {ROOT / 'principals' / a: identity(m['org'], m['server'], a) + '\n' for a in accounts}
    for file, principal in principals.items():
        if file.exists() and file.read_text().strip() != principal.strip():
            raise ValueError('Existing principal differs; refusing to overwrite it')
    before = {x: x.read_bytes() if x.exists() else None for x in (*principals, ROOT / 'sshd.conf', ROOT / 'managed.json')}
    try:
        for file, principal in principals.items():
            write(file, principal)
        m['accounts'] = accounts
        apply(m)
        reload()
    except Exception:
        for x, old in before.items():
            if old is None:
                x.unlink(missing_ok=True)
            else:
                write(x, old.decode(), 0o600 if x.name == 'managed.json' else 0o644)
        subprocess.run(['systemctl', 'kill', '--kill-whom=main', '--signal=HUP', SERVICE], capture_output=True)
        raise

def setup_result(m):
    fp = run('ssh-keygen', '-lf', str(ROOT / 'host.pub'), '-E', 'sha256', capture_output=True).stdout.split()[1]
    result = dict(version=1, org_id=m['org'], server_id=m['server'], host_fingerprint=fp,
                  ssh_port=m['port'], accounts=m['accounts'])
    write(ROOT / 'setup-result.json', json.dumps(result, indent=2) + '\n')
    print('Import this public result in the admin UI: ' + str(ROOT / 'setup-result.json'))
    print('BEGIN TUNNEX SSH RESULT')
    print(json.dumps(result))
    print('END TUNNEX SSH RESULT')
    print('Configured Linux accounts are not Tunnex access grants. Run checks, then grant access explicitly.')

def install_helper():
    dest = Path('/usr/local/sbin/tunnex-browser-ssh')
    if dest.is_symlink() or dest.parent.is_symlink():
        raise ValueError('Refusing symlink helper installation path')
    if dest.exists() and (dest.stat().st_uid != 0 or MARKER not in dest.read_text()):
        raise ValueError('Existing helper path is not owned by this helper')
    write(dest, Path(__file__).read_text(), 0o755)

def platform_preflight():
    if sys.platform != 'linux':
        raise ValueError('Unsupported OS: automatic enrollment currently requires Linux')
    values = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip('"')
    family = {values.get('ID', ''), *values.get('ID_LIKE', '').split()}
    if not family.intersection({'ubuntu', 'debian', 'rhel', 'fedora', 'centos', 'rocky', 'almalinux', 'amzn'}):
        raise ValueError('Unsupported Linux distribution: ' + values.get('ID', 'unknown'))
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('This Linux adapter requires systemd')
    for command in ('systemctl', 'ssh-keygen', 'ip'):
        if not shutil.which(command):
            raise ValueError('Install prerequisite on target: ' + command)
    if not Path('/usr/sbin/sshd').is_file():
        raise ValueError('Install the distribution OpenSSH server before enrollment')
    # Do not disable SELinux or guess a policy for a dedicated listener.
    if Path('/sys/fs/selinux/enforce').exists() and Path('/sys/fs/selinux/enforce').read_text().strip() == '1':
        raise ValueError('SELinux enforcing adapter is not supported yet; no changes were made')
    print('Detected Linux: ' + values.get('PRETTY_NAME', values.get('ID', 'unknown')))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init', help='Create one dedicated listener; refuses existing setup')
    init.add_argument('--ca', required=True, type=Path)
    init.add_argument('--ca-fingerprint', required=True)
    init.add_argument('--port', type=int, default=2222)
    add = sub.add_parser('add-account', help='Reuse CA and host key; add an existing Linux account')
    for parser in (init, add):
        parser.add_argument('--org', required=parser is init)
        parser.add_argument('--server', required=parser is init)
        parser.add_argument('--account', required=True)
    for name in ('bootstrap', 'sync-accounts'):
        parser = sub.add_parser(name, help='Configure all eligible login accounts or a selected set; never grants access')
        choice = parser.add_mutually_exclusive_group(required=True)
        choice.add_argument('--all-login-users', action='store_true')
        choice.add_argument('--accounts', help='Comma-separated existing eligible Linux login users')
    sub.add_parser('status')
    sub.add_parser('remove', help='Stop and remove only helper-owned browser SSH configuration')
    a = p.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Run with sudo')
    platform_preflight()
    # Serialize helper mutations; lock path is protected by root-owned /run.
    fd = os.open('/run/tunnex-browser-ssh.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        os.umask(0o022)
        safe_tree()
        bundle = None
        accounts = None
        if a.command in ('bootstrap', 'sync-accounts'):
            accounts = selected_accounts(a)
            if a.command == 'sync-accounts':
                m = load()
                sync(m, accounts)
                report(m)
                setup_result(m)
                return
            if not isinstance(BUNDLE, dict) or BUNDLE.get('version') != 1:
                raise ValueError('Download a server-specific bootstrap bundle from the administrator UI')
            bundle = BUNDLE
            for account in accounts:
                identity(bundle['org_id'], bundle['server_id'], account)
            if not isinstance(bundle['ssh_port'], int) or not 1024 <= bundle['ssh_port'] <= 65535:
                raise ValueError('Bootstrap needs a dedicated SSH port between 1024 and 65535')
            addresses = json.loads(run('ip', '-j', 'addr', 'show', capture_output=True).stdout)
            local_ips = {addr.get('local') for interface in addresses for addr in interface.get('addr_info', [])}
            if bundle['private_ip'] not in local_ips:
                raise ValueError('This machine does not own the registered target IP; refusing another host identity')
            if ROOT.exists():
                m = load()
                if (m['org'], m['server'], m['port'], m['ca_fingerprint']) != (bundle['org_id'], bundle['server_id'], bundle['ssh_port'], bundle['ca_fingerprint']):
                    raise ValueError('Bootstrap identity or trust differs from existing setup; inspect it first')
                sync(m, accounts)
                install_helper()
                report(m)
                setup_result(m)
                return
            a.command = 'init'
            a.org, a.server, a.account = bundle['org_id'], bundle['server_id'], accounts[0]
            a.port, a.ca_fingerprint = bundle['ssh_port'], bundle['ca_fingerprint']
        if a.command == 'init':
            accounts = accounts or [a.account]
            principals = {account: identity(a.org, a.server, account) for account in accounts}
            if ROOT.exists() or UNIT.exists() or Path('/usr/lib/systemd/system/tunnex-browser-sshd.service').exists() or Path('/lib/systemd/system/tunnex-browser-sshd.service').exists():
                raise ValueError('Existing setup found. Use add-account, or inspect and explicitly remove it first.')
            if not 1024 <= a.port <= 65535:
                raise ValueError('Dedicated listener port must be between 1024 and 65535')
            key = bundle['public_key'].strip() if bundle else a.ca.read_text().strip()
            if '\n' in key or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?', key):
                raise ValueError('Expected exactly one public Ed25519 SSH CA key')
            with tempfile.NamedTemporaryFile(mode='w', prefix='tunnex-public-ca-') as staged:
                staged.write(key + '\n')
                staged.flush()
                fp = run('ssh-keygen', '-lf', staged.name, '-E', 'sha256', capture_output=True).stdout.split()[1]
            if fp != a.ca_fingerprint:
                raise ValueError('CA fingerprint differs from independently verified Tunnex public CA')
            # Refuse occupied port before writing any target configuration.
            import socket
            with socket.socket() as sock:
                sock.bind(('0.0.0.0', a.port))
            m = dict(owner=MARKER, org=a.org, server=a.server, port=a.port, ca_fingerprint=fp, accounts=accounts)
            try:
                ROOT.mkdir(mode=0o755)
                (ROOT / 'principals').mkdir(mode=0o755)
                write(ROOT / 'ca.pub', key + '\n')
                for account, principal in principals.items():
                    write(ROOT / 'principals' / account, principal + '\n')
                run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(ROOT / 'host'))
                Path('/run/sshd').mkdir(mode=0o755, exist_ok=True)
                apply(m)
                write(UNIT, f'''# {MARKER}
[Unit]
Description=Tunnex browser SSH listener
After=network.target
[Service]
ExecStart=/usr/sbin/sshd -D -e -f {ROOT}/sshd.conf
Restart=on-failure
[Install]
WantedBy=multi-user.target
''')
                run('systemctl', 'daemon-reload')
                run('systemctl', 'enable', '--now', SERVICE)
                run('systemctl', 'is-active', '--quiet', SERVICE)
            except Exception:
                subprocess.run(['systemctl', 'disable', '--now', SERVICE], capture_output=True)
                UNIT.unlink(missing_ok=True)
                if ROOT.exists():
                    shutil.rmtree(ROOT)
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
                raise
            if bundle:
                install_helper()
                setup_result(m)
            report(m)
        elif a.command == 'add-account':
            m = load()
            org, server = a.org or m['org'], a.server or m['server']
            principal = identity(org, server, a.account)
            if (org, server) != (m['org'], m['server']):
                raise ValueError('Organization/server identity differs from this configured target')
            fp = run('ssh-keygen', '-lf', str(ROOT / 'ca.pub'), '-E', 'sha256', capture_output=True).stdout.split()[1]
            if fp != m['ca_fingerprint']:
                raise ValueError('Installed CA changed; inspect trust before adding accounts')
            file = ROOT / 'principals' / a.account
            if file.exists() and file.read_text().strip() != principal:
                raise ValueError('Existing principal differs; refusing to overwrite it')
            before = {x: x.read_bytes() if x.exists() else None for x in (file, ROOT / 'sshd.conf', ROOT / 'managed.json')}
            try:
                write(file, principal + '\n')
                m['accounts'] = sorted(set(m['accounts'] + [a.account]))
                apply(m)
                reload()
            except Exception:
                for x, old in before.items():
                    if old is None:
                        x.unlink(missing_ok=True)
                    else:
                        write(x, old.decode(), 0o600 if x.name == 'managed.json' else 0o644)
                subprocess.run(['systemctl', 'kill', '--kill-whom=main', '--signal=HUP', SERVICE], capture_output=True)
                raise
            report(m)
        elif a.command == 'status':
            report(load())
            run('systemctl', 'is-active', SERVICE)
        else:
            load()  # Never remove an unrelated or legacy configuration.
            run('systemctl', 'disable', '--now', SERVICE)
            UNIT.unlink()
            shutil.rmtree(ROOT)
            run('systemctl', 'daemon-reload')
            print('Removed dedicated browser SSH setup. Management SSH, Linux users and Tunnex records remain.')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)
