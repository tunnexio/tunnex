"""Host orchestrator; all SSH connections run inside the exact owned gateway."""
import subprocess,pathlib,json,time,os,shutil
root=pathlib.Path(__file__).resolve().parent;keys=root/'.runtime/ssh';results={}
def cmd(args,timeout=15):return subprocess.run(args,cwd=root,capture_output=True,text=True,timeout=timeout)
def sign(name,principal,valid='-1m:+5m',ca='ca'):
 p=keys/name
 if not p.exists():
  r=cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(p)]);assert r.returncode==0,r.stderr
 r=cmd(['ssh-keygen','-q','-s',str(keys/ca),'-I',f'org-sa0/{name}/session-{name}','-z',str(int(time.time()*1000)),'-n',principal,'-V',valid,'-O','clear','-O','permit-pty',str(p)+'.pub']);assert r.returncode==0,r.stderr
 for suffix in ['', '.pub', '-cert.pub']:shutil.copy2(keys/(name+suffix),keys.parent/'ssh-client'/(name+suffix))
 return name
principal='tunnex:org-sa0:server-linux:account-fixture'
def ssh(name,command='id -un',user='fixture',known='known_hosts'):
 return ['./run.sh','exec','-T','gateway','ssh','-F','/dev/null','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile=/ssh-fixture/{known}','-i',f'/ssh-fixture/{name}','-p','2222',f'{user}@ssh-target',command]
for actor in ['actor-a','actor-b']:
 sign(actor,principal);r=cmd(ssh(actor));assert r.returncode==0,r.stderr;assert r.stdout.strip()=='fixture';results[actor+'_shared_account']=True
sign('wrong-server','tunnex:org-sa0:server-other:account-fixture');r=cmd(ssh('wrong-server'));assert r.returncode!=0 and 'Permission denied' in r.stderr,r.stderr;results['wrong_server_principal_denied']=True
r=cmd(ssh('actor-a',user='nobody'));assert r.returncode!=0 and 'Permission denied' in r.stderr,r.stderr;results['wrong_account_denied']=True
if not (keys/'foreign-ca').exists():
 r=cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(keys/'foreign-ca')]);assert r.returncode==0
sign('foreign-org',principal,ca='foreign-ca');r=cmd(ssh('foreign-org'));assert r.returncode!=0 and 'Permission denied' in r.stderr,r.stderr;results['foreign_ca_denied']=True
pub=(keys/'foreign-ca.pub').read_text().split();(keys.parent/'ssh-client/wrong_known_hosts').write_text('[ssh-target]:2222 '+pub[0]+' '+pub[1]+'\n')
r=cmd(ssh('actor-a',known='wrong_known_hosts'));assert r.returncode!=0 and 'Host key verification failed' in r.stderr,r.stderr;results['wrong_host_key_denied']=True
sign('expiry',principal,'-1m:+3s');p=subprocess.Popen(ssh('expiry','sleep 5; printf SA0_AFTER_EXPIRY'),cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
 time.sleep(4);r=cmd(ssh('expiry'));assert r.returncode!=0 and 'Permission denied' in r.stderr,r.stderr;results['expired_cert_new_login_denied']=True
 out,err=p.communicate(timeout=10);assert p.returncode==0 and 'SA0_AFTER_EXPIRY' in out,(out,err);results['active_shell_survives_cert_expiry']=True
finally:
 if p.poll() is None:p.terminate();p.wait(timeout=3)
# Pinning/certificate identity is not one-time authentication: admission must enforce that.
r=cmd(ssh('actor-a'));assert r.returncode==0;results['certificate_reusable_without_product_admission']=True
(keys.parent/'linux-boundary-results.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
