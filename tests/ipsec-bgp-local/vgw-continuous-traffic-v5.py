#!/usr/bin/env python3
"""Run ONLY on designated bastion after root confirms ZT convergence.
Additive fresh served fixture response; no service restart or echo-server claim.
"""
import argparse,base64,hashlib,json,os,pathlib,secrets,shlex,subprocess,time
ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');ap.add_argument('--gateway-container',required=True);ap.add_argument('--samples',type=int,default=120);ap.add_argument('--pins',required=True);ap.add_argument('--run-id');a=ap.parse_args()
assert a.gateway_container and all(c in '0123456789abcdef' for c in a.gateway_container) and len(a.gateway_container)==64
key='/home/ubuntu/tunnex-bgp-20261007/lab-key';base=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008');os.umask(0o077)
def run(cmd,timeout=35):
 r=subprocess.run(cmd,capture_output=True,timeout=timeout);return {'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
def ssh(host,command,options=[],timeout=35):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-i',key,*options,host,command],timeout=timeout)
client_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'client_known_hosts'),'-o','ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -i '+key+' -W %h:%p ubuntu@13.63.169.255']
target_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','ProxyCommand=aws ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 120']
assert a.samples==120
run_id=a.run_id or secrets.token_hex(16);assert len(run_id)==32 and all(c in '0123456789abcdef'for c in run_id);
nonce=run_id;uri='/tunnex-bgp-acceptance-nonces/'+run_id+'.json'
fixtures=[]
for i in range(a.samples):
 n=secrets.token_hex(32);body=json.dumps({'nonce':n,'target':'10.85.1.10','scope':'fresh owned served acceptance fixture'},sort_keys=True,separators=(',',':'))+'\n'
 fixtures.append({'nonce':n,'uri':'/tunnex-bgp-acceptance-nonces/'+n+'.json?nonce='+n,'body':body})
if not a.execute:
 print(json.dumps({'source_only':True,'samples':a.samples,'cadence_seconds':1,'single_client_ssh':True,'fault_injected':False,'existing_stream_tested':False}));raise SystemExit
assert pathlib.Path('/home/ubuntu').is_dir() and base.is_dir()
def save(name,obj):
 with open(base/name,'x') as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
 fd=os.open(base,os.O_RDONLY);os.fsync(fd);os.close(fd)
import stat
st=pathlib.Path(a.pins).lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600
pin=json.loads(pathlib.Path(a.pins).read_text());assert pin['root_reviewed'] is True and pin['gateway_id']==a.gateway_container and pin['node_sha256']=='987d9c0a0fa170e34ebbec5bc7fa4ab56b6fe0026bf2577e1e0542b605967f3e' and pin['namespace']!='net:[4026532946]' and not pin['gateway_id'].startswith('0faef89')
started=int(time.time());stem='continuous-'+run_id
save(stem+'-intent.json',{'nonce':nonce,'uri':uri,'samples':a.samples,'gateway_container':a.gateway_container,'started':started})
identity_code="import json,os,pathlib,subprocess; p=1353; main=subprocess.check_output(['systemctl','show','tunnex-bgp-target.service','-p','MainPID','--value']).decode().strip(); assert main==str(p); stat=pathlib.Path('/proc/'+str(p)+'/stat').read_text(); print(json.dumps({'pid':p,'start':stat.rsplit(')',1)[1].split()[19],'exe':os.readlink('/proc/'+str(p)+'/exe'),'cmdline':pathlib.Path('/proc/'+str(p)+'/cmdline').read_bytes().decode(),'cwd':os.readlink('/proc/'+str(p)+'/cwd')},sort_keys=True))"
identity_command='sudo -n python3 -c '+shlex.quote(identity_code)
identity_read='sudo -n docker inspect --format '+shlex.quote('{{.Id}} {{.Image}} {{.State.Pid}} {{.State.StartedAt}}')+' '+a.gateway_container+'; sudo -n docker exec '+a.gateway_container+' readlink /proc/1/ns/net; sudo -n docker exec '+a.gateway_container+' sha256sum /proc/1/exe /state/cert.pem'
worker_before=ssh('ubuntu@13.63.169.255',identity_read);assert worker_before['exit']==0
lines=worker_before['stdout'].splitlines();assert len(lines)==4
head=lines[0].split();assert len(head)==4 and head[0]==pin['gateway_id'] and head[1]==pin['image'] and int(head[2])>0
assert lines[1]==pin['namespace'] and lines[2].split()==[pin['node_sha256'],'/proc/1/exe'] and lines[3].split()==[pin['cert_sha256'],'/state/cert.pem']
save(stem+'-worker-before.json',worker_before)
identity_before=ssh('ubuntu@10.85.1.10',identity_command,target_opts);assert identity_before['exit']==0
identity=json.loads(identity_before['stdout']);assert identity['exe']=='/usr/bin/python3.12' and identity['cmdline']=='/usr/bin/python3\x00-m\x00http.server\x008080\x00--bind\x000.0.0.0\x00' and identity['cwd']=='/opt/tunnex-bgp-lab'
save(stem+'-service-identity-before.json',identity_before)
fixture_code="""import os,pathlib,json,hashlib
root=pathlib.Path('/opt/tunnex-bgp-lab');assert pathlib.Path('/proc/1353/cwd').resolve()==root and root.stat().st_uid==0 and root.stat().st_mode&0o777==0o755
p=root/'tunnex-bgp-acceptance-nonces'
try:p.mkdir(mode=0o755)
except FileExistsError:pass
assert not p.is_symlink() and p.stat().st_uid==0 and p.stat().st_mode&0o777==0o755
rows=ROWS_LITERAL
for r in rows:
 fd=os.open(p/(r['nonce']+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
 with os.fdopen(fd,'w')as f:f.write(r['body']);f.flush();os.fsync(f.fileno())
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'fixtures':len(rows)}))
""".replace('ROWS_LITERAL',repr(fixtures))
fixture=ssh('ubuntu@10.85.1.10','sudo -n python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(base64.b64encode(fixture_code.encode()).decode())+'))'),target_opts)
assert fixture['exit']==0 and json.loads(fixture['stdout'])['fixtures']==a.samples
control=ssh('ubuntu@10.85.1.10','curl --noproxy "*" --fail --max-time 5 -s '+shlex.quote('http://127.0.0.1:8080'+fixtures[0]['uri']),target_opts);assert control['exit']==0 and control['stdout']==fixtures[0]['body']
save(stem+'-fixture-control.json',{'fixture':fixture,'control':control,'fixtures':fixtures})
command='sudo -n docker inspect --format "{{.Id}} {{.State.Running}}" '+a.gateway_container+'; sudo -n docker exec '+a.gateway_container+' nft -j list ruleset; sudo -n docker exec -e STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf '+a.gateway_container+' /opt/tunnex-ipsec/sbin/swanctl --list-sas --uri unix:///run/tunnex-ipsec/charon.vici'
before=ssh('ubuntu@13.63.169.255',command);save(stem+'-before.json',before);assert before['exit']==0 and before['stdout'].startswith(a.gateway_container+' true\n')
client_code=r"""import os,pathlib,json,time,subprocess
os.umask(0o077);rows=ROWS_LITERAL;p=pathlib.Path('/home/ubuntu')/('tunnex-vgw-measure-'+RUN_LITERAL);p.mkdir(mode=0o700)
start=time.monotonic();out=[]
with (p/'samples.jsonl').open('x')as f:
 for i,r in enumerate(rows):
  due=start+i
  if time.monotonic()<due:time.sleep(due-time.monotonic())
  began=time.monotonic();wall=time.time()
  q=subprocess.run(['curl','--noproxy','*','--connect-timeout','1','--max-time','2','--silent','--show-error','--write-out','HTTP=%{http_code}\n','http://10.85.1.10:8080'+r['uri']],capture_output=True,text=True,timeout=3)
  ended=time.monotonic();v={'index':i,'nonce':r['nonce'],'started':began,'ended':ended,'wall':wall,'schedule_lag':max(0,began-due),'exit':q.returncode,'stdout':q.stdout,'stderr':q.stderr,'success':q.returncode==0 and q.stdout==r['body']+'HTTP=200\n'}
  out.append(v);f.write(json.dumps(v)+'\n');f.flush();os.fsync(f.fileno())
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'client_result_path':str(p/'samples.jsonl'),'rows':out}))
""".replace('ROWS_LITERAL',repr(fixtures)).replace('RUN_LITERAL',repr(run_id))
probe=ssh('ubuntu@10.84.2.10','python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(base64.b64encode(client_code.encode()).decode())+'))'),client_opts,timeout=600)
save(stem+'-client-output.json',probe);assert probe['exit']==0
measurement=json.loads(probe['stdout']);assert len(measurement['rows'])==a.samples
after=ssh('ubuntu@13.63.169.255',command);save(stem+'-after.json',after);assert after['exit']==0 and after['stdout'].startswith(a.gateway_container+' true\n')
worker_after=ssh('ubuntu@13.63.169.255',identity_read);save(stem+'-worker-after.json',worker_after);assert worker_after['exit']==0 and worker_after['stdout']==worker_before['stdout']
identity_after=ssh('ubuntu@10.85.1.10',identity_command,target_opts);assert identity_after['exit']==0 and identity_after['stdout']==identity_before['stdout']
save(stem+'-service-identity-after.json',identity_after)
log=ssh('ubuntu@10.85.1.10','sudo -n journalctl -u tunnex-bgp-target.service --since @'+str(started)+' --no-pager -o cat',target_opts);assert log['exit']==0
rows=measurement['rows'];by_nonce={r['nonce']:r for r in fixtures}
for r in rows:
 uri=by_nonce[r['nonce']]['uri'];r['target_matches']=sum('10.84.2.10 - 'in line and '"GET '+uri+' HTTP/1.1" 200'in line for line in log['stdout'].splitlines());r['success']=r['success'] and r['target_matches']==1
 r['confirmed_timeout']=r['exit']==28 and r['stdout']=='HTTP=000\n' and r['target_matches']==0
streak=maximum=baseline=0;first_failure=None;recoveries=[];baseline_open=True
for r in rows:
 if baseline_open and r['success']:baseline+=1
 else:baseline_open=False
 if r['confirmed_timeout']:
  streak+=1;maximum=max(maximum,streak)
  if first_failure is None:first_failure=r
 elif r['success']:
  if first_failure is not None:recoveries.append({'first_failed_request':first_failure['index'],'first_healthy_request':r['index'],'sampled_window_seconds':r['ended']-first_failure['started'],'onset_censored':first_failure['index']==0});first_failure=None
  streak=0
 else:streak=0
save(stem+'-result.json',{'measurement':measurement,'before':before,'after':after,'target_log':log,'baseline_successes':baseline,'maximum_consecutive_timeouts':maximum,'recovered_windows':recoveries,'right_censored':first_failure is not None,'uncertain_samples':[r['index']for r in rows if not r['success']and not r['confirmed_timeout']],'scope':'one client process; distinct served nonce per sequential HTTP request; sampled time bounds include request duration and scheduling lag, not exact fault onset','existing_tcp_stream_tested':False,'fault_injected':False,'counter_review_required':True})
print(json.dumps({'receipt':str(base/(stem+'-result.json')),'baseline_successes':baseline,'maximum_consecutive_timeouts':maximum,'right_censored':first_failure is not None}))
