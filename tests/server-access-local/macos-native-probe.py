import subprocess,tempfile,pathlib,os,pwd,socket,time,json,signal
root=pathlib.Path(tempfile.mkdtemp(prefix='tunnex-sa0-native-'));os.chmod(root,0o700)
def run(args): return subprocess.run(args,capture_output=True,text=True,timeout=12)
for name in ['ca','host','client','wronghost']:
 r=run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/name)]);assert r.returncode==0,r.stderr
principal='tunnex:org-fixture:server-a:account-fixture'
r=run(['/usr/bin/ssh-keygen','-q','-s',str(root/'ca'),'-I','org-fixture/actor-a/session-a','-z','1','-n',principal,'-V','-1m:+2m','-O','clear','-O','permit-pty',str(root/'client.pub')]);assert r.returncode==0,r.stderr
user=pwd.getpwuid(os.getuid()).pw_name;(root/'principals').write_text(principal+'\n')
with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
cfg=f'''Port {port}
ListenAddress 127.0.0.1
HostKey {root}/host
PidFile {root}/sshd.pid
TrustedUserCAKeys {root}/ca.pub
AuthorizedPrincipalsFile {root}/principals
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes yes
PermitRootLogin no
AllowUsers {user}
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
LogLevel VERBOSE
''';(root/'sshd.conf').write_text(cfg)
results={'platform':os.uname().sysname,'fixture':str(root),'certificate_inspection':run(['/usr/bin/ssh-keygen','-L','-f',str(root/'client-cert.pub')]).stdout,'checks':{}}
t=run(['/usr/sbin/sshd','-t','-f',str(root/'sshd.conf')]);results['config_check']={'code':t.returncode,'error':t.stderr}
p=None
try:
 if t.returncode==0:
  log=open(root/'sshd.log','w');p=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(root/'sshd.conf')],stdout=log,stderr=log)
  time.sleep(.4)
  pub=(root/'host.pub').read_text().split();(root/'known_hosts').write_text(f'[127.0.0.1]:{port} {pub[0]} {pub[1]}\n')
  base=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={root}/known_hosts','-i',str(root/'client'),'-p',str(port),f'{user}@127.0.0.1']
  r=run(base+['-tt','stty size; printf "SA0_NATIVE_OK\\n"']);results['checks']['native_certificate_pty']={'code':r.returncode,'out':r.stdout,'error':r.stderr}
  if r.returncode==0:
   # Native validity bounds do not terminate an already authenticated channel.
   r=run(['/usr/bin/ssh-keygen','-q','-s',str(root/'ca'),'-I','org-fixture/actor-a/session-expiry','-z','2','-n',principal,'-V','-1m:+3s','-O','clear','-O','permit-pty',str(root/'client.pub')]);assert r.returncode==0,r.stderr
   live=subprocess.Popen(base+['sleep 5; printf SA0_AFTER_CERT_EXPIRY'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   time.sleep(4)
   r=run(base+['true']);results['checks']['expired_certificate_new_login_denied']=r.returncode!=0
   out,err=live.communicate(timeout=8);results['checks']['authenticated_shell_survives_certificate_expiry']=live.returncode==0 and 'SA0_AFTER_CERT_EXPIRY' in out
   r=run(['/usr/bin/ssh-keygen','-q','-s',str(root/'ca'),'-I','org-fixture/actor-a/session-a','-z','3','-n',principal,'-V','-1m:+2m','-O','clear','-O','permit-pty',str(root/'client.pub')]);assert r.returncode==0,r.stderr
   (root/'principals').write_text('tunnex:org-fixture:server-b:account-fixture\n');r=run(base+['true']);results['checks']['wrong_server_principal_denied']=r.returncode!=0
   (root/'principals').write_text(principal+'\n');pub=(root/'wronghost.pub').read_text().split();(root/'known_hosts').write_text(f'[127.0.0.1]:{port} {pub[0]} {pub[1]}\n');r=run(base+['true']);results['checks']['wrong_host_key_denied']=r.returncode!=0
 finally_marker=True
finally:
 if p is not None:
  p.terminate()
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 if (root/'sshd.log').exists():results['daemon_log']=(root/'sshd.log').read_text()
 pathlib.Path('/private/tmp/tunnex-sa0-spike/native-result.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
 # Destroy only generated disposable private keys; keep public diagnostics.
 for name in ['ca','host','client','wronghost']:(root/name).unlink()
