# Template embedded in the API. SETUP is replaced with a public job binding.
import base64, hashlib, json, os, pwd, subprocess, sys, time
from pathlib import Path
SETUP = None

def safe(p, owner=0):
    if p.is_symlink() or p.exists() and (p.stat().st_uid != owner or p.stat().st_mode & 0o022):
        raise ValueError('Unsafe setup path: ' + str(p))

def atomic(p, content, mode, owner=0, group=0):
    import tempfile
    fd, temp = tempfile.mkstemp(dir=p.parent)
    try:
        os.fchmod(fd, mode); os.fchown(fd, owner, group)
        with os.fdopen(fd, 'w') as f:
            f.write(content); f.flush(); os.fsync(f.fileno())
        os.replace(temp, p)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def configure():
    if os.geteuid() != 0: raise ValueError('Run this authorization command with sudo')
    if SETUP['expires'] <= time.time(): raise ValueError('Setup authorization expired; prepare a new job')
    account = pwd.getpwnam(SETUP['account'])
    if account.pw_uid == 0: raise ValueError('Root SSH setup account is refused')
    for p in (Path('/var'), Path('/var/lib'), Path('/etc'), Path('/etc/sudoers.d')): safe(p)
    root = Path('/var/lib/tunnex-enrollment'); safe(root); root.mkdir(mode=0o700, exist_ok=True)
    home = Path(account.pw_dir); safe(home, account.pw_uid)
    directory = home / '.ssh'; safe(directory, account.pw_uid)
    directory.mkdir(mode=0o700, exist_ok=True); os.chown(directory, account.pw_uid, account.pw_gid)
    keys = directory / 'authorized_keys'; safe(keys, account.pw_uid)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if os.fstat(directory_fd).st_uid != account.pw_uid: raise ValueError('Unsafe SSH directory owner')
    tag = 'tunnex-enroll-' + SETUP['id']
    launcher = root / (SETUP['id'] + '.py'); rule = Path('/etc/sudoers.d') / tag
    safe(launcher); safe(rule)
    payload = dict(SETUP, keys=str(keys), owner=account.pw_uid, group=account.pw_gid, launcher=str(launcher), rule=str(rule), tag=tag)
    wrapper = WRAPPER.replace('JOB = None', 'JOB = ' + repr(payload))
    atomic(launcher, wrapper, 0o700)
    atomic(rule, f"{SETUP['account']} ALL=(root) NOPASSWD: /usr/bin/python3 {launcher}\n", 0o440)
    try:
        subprocess.run(['visudo', '-cf', str(rule)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['systemd-run', '--quiet', '--unit=' + tag, '--on-active=' + str(max(1, int(SETUP['expires'] - time.time()))) + 's', '/usr/bin/python3', str(launcher), '--cleanup'], check=True)
        line = 'restrict,expiry-time="' + SETUP['expiry_ssh'] + '",command="sudo -n /usr/bin/python3 ' + str(launcher) + '" ' + SETUP['key'].strip() + ' ' + tag
        try:
            key_fd = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            if os.fstat(key_fd).st_uid != account.pw_uid: raise ValueError('Unsafe SSH key owner')
            with os.fdopen(key_fd) as f: existing = f.read()
        except FileNotFoundError: existing = ''
        name = '.tunnex-' + SETUP['id']
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        try:
            os.fchown(fd, account.pw_uid, account.pw_gid)
            with os.fdopen(fd, 'w') as f:
                f.write(existing.rstrip('\n') + '\n' + line + '\n'); f.flush(); os.fsync(f.fileno())
            os.rename(name, 'authorized_keys', src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        finally:
            try: os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError: pass
            os.close(directory_fd)
    except Exception:
        rule.unlink(missing_ok=True); launcher.unlink(missing_ok=True); raise
    print('Temporary gateway setup authorized. Return to Tunnex and click Configure automatically.')

WRAPPER = r'''import hashlib, os, subprocess, sys, tempfile, time
from pathlib import Path
JOB = None

def cleanup():
    keys = Path(JOB['keys'])
    import fcntl
    try:
        directory = os.open(keys.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if os.fstat(directory).st_uid != JOB['owner']: raise ValueError('Unsafe key directory')
            fd = os.open(keys.name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory)
            if os.fstat(fd).st_uid != JOB['owner']:
                os.close(fd); raise ValueError('Unsafe key owner')
            with os.fdopen(fd, 'r+') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                data = ''.join(line for line in f.readlines() if not line.rstrip().endswith(' ' + JOB['tag']))
                f.seek(0); f.write(data); f.truncate(); f.flush(); os.fsync(f.fileno())
        finally: os.close(directory)
    except (OSError, ValueError): pass
    Path(JOB['rule']).unlink(missing_ok=True)
    Path(JOB['launcher']).unlink(missing_ok=True)

if '--cleanup' in sys.argv:
    cleanup(); sys.exit(0)
try:
    if time.time() >= JOB['expires']: raise ValueError('Enrollment authorization expired')
    # This key can only execute the exact reviewed server-bound installer.
    source = sys.stdin.buffer.read(131073)
    if len(source) > 131072 or hashlib.sha256(source).hexdigest() != JOB['digest']:
        raise ValueError('Installer digest mismatch')
    with tempfile.NamedTemporaryFile(dir=Path(JOB['launcher']).parent, suffix='.py') as f:
        f.write(source); f.flush()
        args = ['--accounts', ','.join(JOB['accounts'])] if JOB['accounts'] else ['--all-login-users']
        subprocess.run(['/usr/bin/python3', f.name, 'bootstrap', *args], check=True, timeout=90)
finally:
    cleanup()
'''
if __name__ == '__main__': configure()
