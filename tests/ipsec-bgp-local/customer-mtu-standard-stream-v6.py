#!/usr/bin/env python3
"""LOCAL standard-SSH stages; source-only unless --execute. No remote helper file; reviewed normal API helper executes via stdin."""
import importlib.util
import argparse,hashlib,json,os,pathlib,secrets,shlex,subprocess,time,stat,re
CID='b8baa489a1a6e24020676d75703db1ef28118178e97d38c9a00914dab2c20cad';NS='net:[4026532947]'
NODE='b85a470bfa46fb8d03487381c58d1be004aa5adc3fad6a1e50d9a575b72e6d76';CERT='eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d'
KEY='/home/ubuntu/tunnex-bgp-20261007/lab-key';BASE='/home/ubuntu/tunnex-bgp-vgw-eic-20261008'
API_LOCAL=pathlib.Path(__file__).with_name('customer-mtu-access-normal-v3.py');APISHA='363fba538b7081c922ae32697b725987b45cb1b29bc4a86125d49bcc6ed699a9'
CLIENT='10.84.2.10';TARGET='10.85.1.10';SG='sg-0c90b1ec6f9eb24ff'
def ssh(endpoint,command):
 inner=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-i',KEY]
 if endpoint=='gateway':inner+=['ubuntu@13.63.169.255',command]
 elif endpoint=='client':inner+=['-o','UserKnownHostsFile='+BASE+'/client_known_hosts','-o','ProxyCommand=ssh -o BatchMode=yes -i '+KEY+' ubuntu@13.63.169.255 -W %h:%p','ubuntu@'+CLIENT,command]
 elif endpoint=='target':inner+=['-o','UserKnownHostsFile='+BASE+'/known_hosts','-o','ProxyCommand=aws ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 3600','ubuntu@'+TARGET,command]
 elif endpoint=='bastion':return ['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',command]
 else:raise AssertionError('Unknown endpoint')
 return ['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',shlex.join(inner)]
def save(name,value):
 with (run/name).open('x')as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(run,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def read(name):return json.loads((run/name).read_text())
def call(endpoint,command,timeout=30):
 try:
  result=subprocess.run(ssh(endpoint,command),capture_output=True,text=True,timeout=timeout)
  return {'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'at':time.time()}
 except subprocess.TimeoutExpired as failure:
  def text(value):return value.decode(errors='replace')if isinstance(value,bytes)else(value or '')
  value={'exit':None,'timeout':True,'stdout':text(failure.stdout),'stderr':text(failure.stderr),'at':time.time(),'endpoint':endpoint,'command_sha256':hashlib.sha256(command.encode()).hexdigest()}
  if 'run'in globals() and run.is_dir():save('transport-timeout-'+secrets.token_hex(8)+'.json',value)
  return value
def checked(endpoint,command,timeout=30):
 r=call(endpoint,command,timeout);assert r['exit']==0,r;return r

def identity():
 fmt='{{.Id}} {{.Image}} {{.State.Running}} {{.State.Pid}} {{.State.StartedAt}}'
 c=checked('gateway',shlex.join(['sudo','docker','inspect','--format',fmt,CID]))['stdout'].split();assert c[0]==CID and c[1]=='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2' and c[2]=='true'
 ns=checked('gateway','sudo docker exec '+CID+' readlink /proc/1/ns/net')['stdout'].strip();assert ns==NS
 h=checked('gateway','sudo docker exec '+CID+' sha256sum /proc/1/exe /state/cert.pem')['stdout'].splitlines();assert h[0].split()[0]==NODE and h[1].split()[0]==CERT
 t=checked('target',"systemctl show tunnex-bgp-target.service -p MainPID -p ActiveState; sudo readlink /proc/1353/exe; sudo cat /proc/1353/stat; sudo cat /proc/1353/cmdline | tr '\\000' ' '; printf '\\n'; sudo readlink /proc/1353/cwd")['stdout'];assert 'MainPID=1353' in t and 'ActiveState=active' in t
 lines=t.splitlines();statrow=lines[-3];parts=statrow[statrow.rfind(')')+2:].split();assert len(parts)>19 and parts[19]=='5629'
 assert lines[-4]=='/usr/bin/python3.12' and lines[-2].strip()=='/usr/bin/python3 -m http.server 8080 --bind 0.0.0.0' and lines[-1]=='/opt/tunnex-bgp-lab'
 return {'container':c,'namespace':ns,'hashes':h,'target_service':{'main_pid':1353,'active':True,'exe':lines[-4],'cmdline':lines[-2],'cwd':lines[-1],'startticks':parts[19]}}
def hostrules(nonce):
 common=['-p','tcp'];out=['-i','enp39s0','-o','tnxbgplab0','-s',CLIENT+'/32','-d',TARGET+'/32',*common,'--dport','8081','-m','comment','--comment','tnx-mtu-'+nonce+'-out','-j','ACCEPT'];reply=['-i','tnxbgplab0','-o','enp39s0','-s',TARGET+'/32','-d',CLIENT+'/32',*common,'--sport','8081','-m','conntrack','--ctstate','ESTABLISHED','-m','comment','--comment','tnx-mtu-'+nonce+'-reply','-j','ACCEPT'];return [out,reply]
LEASE_SUFFIX='9d9f98e2cd96456db020a5a79f688040'
OWNED={'tx2d91f0137387':(2912022547,'13.50.7.159'),'tx199f74b5ef5c':(2577364149,'51.20.220.141')}
def same_ip(value,ip):
 return value==ip or value=={'prefix':{'addr':ip,'len':32}}
def match(left,right,op='=='):return {'match':{'op':op,'left':left,'right':right}}
def actual_authority(nft):
 objects=nft['nftables'];sets={x['set']['name']:x['set']for x in objects if 'set'in x and x['set'].get('table')=='tunnex_ipsec'}
 lease='lease_'+LEASE_SUFFIX;reply='reply_lease_'+LEASE_SUFFIX;sa='sa_lease_'+LEASE_SUFFIX
 def elements(name,expected_type):
  value=sets[name];assert value['family']=='inet' and value['type']==expected_type and value['flags']==['timeout'] and value['timeout']==60
  rows=value['elem'];assert 1<=len(rows)<=2;result=[]
  for item in rows:
   e=item['elem'];assert set(e)=={'val','timeout','expires'} and type(e['timeout'])is int and type(e['expires'])is int and 5<e['expires']<=e['timeout']<=60;result.append(e['val'])
  assert len(result)==len(set(result));return set(result)
 healthy=elements(lease,'iface_index');assert healthy==elements(reply,'iface_index') and healthy<=set(OWNED)
 assert elements(sa,{'typeof':{'ipsec':{'key':'reqid','dir':'out','spnum':0}}})=={OWNED[x][0]for x in healthy}
 rules=[x['rule']for x in objects if 'rule'in x and x['rule'].get('table')=='tunnex_ipsec' and x['rule'].get('family')=='inet']
 def has(chain,expected):
  for r in rules:
   if r['chain']!=chain:continue
   expressions=[x for x in r['expr']if 'counter'not in x]
   if expressions==expected+[{'accept':None}]:return True
  return False
 for interface in healthy:
  # Actual /32 NFT spelling is bare address; explicit prefix32 also canonical.
  for source in [CLIENT,{'prefix':{'addr':CLIENT,'len':32}}]:
   for target in [TARGET,{'prefix':{'addr':TARGET,'len':32}}]:
    outgoing=[match({'meta':{'key':'iif'}},'eth0'),match({'meta':{'key':'oif'}},interface),match({'payload':{'protocol':'ip','field':'saddr'}},source),match({'payload':{'protocol':'ip','field':'daddr'}},target),match({'payload':{'protocol':'tcp','field':'dport'}},8081),match({'ct':{'key':'direction'}},'original'),match({'meta':{'key':'oif'}},'@'+lease)]
    incoming=[match({'meta':{'key':'iif'}},interface),match({'meta':{'key':'oif'}},'eth0'),match({'payload':{'protocol':'ip','field':'saddr'}},target),match({'payload':{'protocol':'ip','field':'daddr'}},source),match({'payload':{'protocol':'tcp','field':'sport'}},8081),match({'ct':{'key':'direction'}},'reply'),match({'ct':{'key':'state'}},'established','in'),match({'meta':{'key':'iif'}},'@'+reply)]
    if has('forward_guard',outgoing) and has('forward_guard',incoming):break
   else:continue
   break
  else:raise AssertionError('Exact client32 target32 TCP8081 grant absent')
  reqid,outside=OWNED[interface]
  encrypted=[match({'payload':{'protocol':'ip','field':'daddr'}},{'prefix':{'addr':'10.85.0.0','len':16}}),match({'meta':{'key':'oif'}},'eth0'),match({'ipsec':{'key':'reqid','dir':'out','spnum':0}},reqid),match({'ipsec':{'key':'daddr','family':'ip','dir':'out','spnum':0}},outside),match({'ipsec':{'key':'reqid','dir':'out','spnum':0}},'@'+sa)]
  assert has('postrouting_guard',encrypted),'Exact encrypted egress lease missing'
 return sorted(healthy)
def canonical_sg(value):return sorted(value['SecurityGroupRules'],key=lambda x:x['SecurityGroupRuleId'])
def canonical_rules(raw):return [shlex.split(row)for row in raw.splitlines()]

def native_snapshot():
 return {'at':time.time(),'identity':identity(),'links':json.loads(checked('gateway','sudo docker exec '+CID+' ip -d -j link show')['stdout']),'routes':json.loads(checked('gateway','sudo docker exec '+CID+' ip -j -4 route show table all')['stdout']),'nft':json.loads(checked('gateway','sudo docker exec '+CID+' nft -j list ruleset')['stdout']),'sas':checked('gateway','sudo docker exec -e STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf '+CID+' /opt/tunnex-ipsec/sbin/swanctl --list-sas --uri unix:///run/tunnex-ipsec/charon.vici')['stdout']}

def collect(process,seconds):
 try:
  out,err=process.communicate(timeout=seconds);return {'exit':process.returncode,'stdout':out,'stderr':err,'at':time.time()}
 except subprocess.TimeoutExpired as e:
  def text(v):return v.decode(errors='replace')if isinstance(v,bytes)else(v or '')
  return {'exit':None,'timeout':True,'stdout':text(e.stdout),'stderr':text(e.stderr),'at':time.time(),'remote_bound_still_applies':True}
def api_readback():
 raw=API_LOCAL.read_bytes();assert hashlib.sha256(raw).hexdigest()==APISHA
 prefix=raw.decode().split('def main():')[0]
 body=r"""
os.umask(0o077);d=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api');c=json.loads((d/'credentials.json').read_text());base=c['base_url']
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,body=None):
 with client.open(urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'}),timeout=20)as r:return json.loads(r.read())
assert not api('/api/v1/auth/login',{'email':c['email'],'password':c['password']}).get('mfa_required')
root='/api/v1/organizations/'+ORG;p=api(root+'/ipsec/connections/'+PROVIDER);assert p['desired_intent']=='enabled' and p['desired_revision']==2
configuration=validate_configuration(api(root+'/ipsec/connections/'+PROVIDER+'/configuration'));assert api(root+'/zero-trust-mode')['mode']=='enforcing'
r=resource(json.loads((d/(PREFIX+'resource-result.json')).read_text()));g=json.loads((d/(PREFIX+'grant-result.json')).read_text())
assert [v for v in api(root+'/resources')if v['id']==r['id']]==[r]
assert [v for v in api(root+'/policies')if v['id']==g['id']]==[g]
assert g['src_kind']=='cidr' and g['src_cidr']==SOURCE and g['dst_kind']=='resource' and g['dst_resource_id']==r['id'] and not any(g.get(k)for k in ['src_site_id','src_group_id','src_user_id'])
assert stable(api(root+'/ipsec/connections/'+PROVIDER))==stable(p) and api(root+'/ipsec/connections/'+PROVIDER+'/configuration')==configuration
print(json.dumps({'provider':stable(p),'configuration':configuration,'resource':r,'grant':g,'get_only':True}))
"""
 result=subprocess.run(ssh('gateway','sudo python3 -'),input=prefix+body,text=True,capture_output=True,timeout=100)
 value={'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr};save('api-readback-raw.json',value);assert result.returncode==0
 return json.loads(result.stdout)
def listener_command():
 command="ss -ntlp 'sport = :8081'; p=$(ss -ntlp 'sport = :8081' | grep -o 'pid=[0-9]*' | cut -d= -f2); test -n \"$p\" && test $(printf '%s\\n' \"$p\" | wc -l) -eq 1 && readlink /proc/$p/exe && cat /proc/$p/stat && cat /proc/$p/cmdline"
 return 'sudo sh -c '+shlex.quote(command)
def parse_listener(raw):
 pids=re.findall(r'pid=([0-9]+)',raw);assert len(set(pids))==1 and pids[0]!='1353'
 lines=raw.splitlines();exe=next(x for x in lines if x in ['/usr/bin/nc.openbsd','/usr/bin/netcat.openbsd']);row=next(x for x in lines if x.startswith(pids[0]+' ('));ticks=row[row.rfind(')')+2:].split()[19]
 assert TARGET in raw and '8081'in raw and 'LISTEN'in raw
 argv=lines[-1].split('\x00');argv=[v for v in argv if v];assert argv==['nc','-N','-l',TARGET,'8081']
 return {'pid':int(pids[0]),'startticks':ticks,'exe':exe,'argv':argv,'raw':raw}
def main():
 global run
 parser=argparse.ArgumentParser();parser.add_argument('--run',type=pathlib.Path,required=True);parser.add_argument('--out',type=pathlib.Path,required=True);parser.add_argument('--execute',action='store_true');a=parser.parse_args()
 if not a.execute:print(json.dumps({'transfer_only':True,'source_only':True,'no_api_writes':True}));return
 os.umask(0o077);assert a.run.is_dir() and not a.run.is_symlink() and stat.S_IMODE(a.run.stat().st_mode)==0o700
 release=json.loads((a.run/'root-stage-release-v6.json').read_text());assert release['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
 assert json.loads((a.run/'preflight-complete.json').read_text())=={'passed':True,'runtime_mutations':False}
 assert not a.out.exists();a.out.mkdir(mode=0o700);run=a.out
 baseline=json.loads((a.run/'baseline.json').read_text());nonce=baseline['nonce'];assert re.fullmatch('[0-9a-f]{64}',nonce);original='/var/tmp/tunnex-customer-8081-'+nonce;attempt=secrets.token_hex(16);directory=original+'/attempt-'+attempt
 save('intent.json',{'attempt':attempt,'original_run':str(a.run),'source_sha256':release['source_sha256'],'new_directory':directory,'no_api_writes':True});save('api-readback.json',api_readback())
 prelaunch=checked('target',"sudo ss -ntlp 'sport = :8081'; getconf CLK_TCK; cat /proc/uptime; date -u +%s.%N");save('prelaunch-listener.json',prelaunch);lines=prelaunch['stdout'].splitlines();assert len(lines)==4 and lines[0].startswith('State'),'Existing target8081 listener must not be adopted or killed';launch_ticks=int(float(lines[2].split()[0])*int(lines[1]));
 before=native_snapshot();assert before['identity']==baseline['identity'];save('native-before.json',before);save('authority.json',{'healthy_interfaces':actual_authority(before['nft'])});hostpid=before['identity']['container'][3]
 hashes={'target':'9f1abee2879f25abb51aa4f736c70ad04cee7faf9beadaea86ac49659dc4d920','client':'8cf7b5ae12e218251b32168fe7619c33ce09b5fe3e2a375ac0cb653e38897bcc'}
 for endpoint in ['target','client']:
  command='test ! -L '+original+' && test "$(stat -c %u:%a '+original+')" = 0:700 && test ! -L '+original+'/send.bin && test "$(stat -c %u:%a:%s '+original+'/send.bin)" = 0:600:4194304 && sha256sum '+original+'/send.bin'
  result=checked(endpoint,'sudo sh -c '+shlex.quote(command));save(endpoint+'-original-fixture.json',result);assert result['stdout'].split()[0]==hashes[endpoint]
  result=call(endpoint,'sudo sh -c '+shlex.quote('umask 077; mkdir -m 700 '+directory+' && cp --no-clobber '+original+'/send.bin '+directory+'/send.bin && sha256sum '+directory+'/send.bin'));save(endpoint+'-fresh-fixture.json',result);assert result['exit']==0 and result['stdout'].split()[0]==hashes[endpoint]
 clock_before=time.time();clock=checked('target','date -u +%s.%N');clock_after=time.time();save('target-clock-bound.json',{'raw':clock,'local_before':clock_before,'local_after':clock_after})
 observer_path=pathlib.Path(__file__).with_name('customer-stream-growth-observer.py');assert hashlib.sha256(observer_path.read_bytes()).hexdigest()=='e6ffbcd191fe4ad616ee46bb56338ac91e543afc531e74e36fc80547bb66dd51';spec=importlib.util.spec_from_file_location('growth',observer_path);growth=importlib.util.module_from_spec(spec);spec.loader.exec_module(growth)
 header='sudo nsenter -t '+hostpid+' -n timeout 290 tcpdump -l -nn -tttt -vv -i any '+shlex.quote('tcp and host '+CLIENT+' and host '+TARGET+' and port 8081 and (tcp[13] & 2 != 0)')
 hp=subprocess.Popen(ssh('gateway',header),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 processes=[]
 try:
  server='umask 077; test ! -e '+directory+'/received.bin && timeout -k 3 300 nc -N -l '+TARGET+' 8081 < /dev/null > '+directory+'/received.bin'
  sp=subprocess.Popen(ssh('target','sudo sh -c '+shlex.quote(server)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(('target',sp,320))
  tracked=None
  for _ in range(5):
   result=call('target',listener_command(),timeout=20);save('listener-read-'+secrets.token_hex(4)+'.json',result)
   if result['exit']==0:
    tracked=parse_listener(result['stdout']);assert int(tracked['startticks'])>=launch_ticks;assert tracked['argv']==['nc','-N','-l',TARGET,'8081'];break
   time.sleep(.2)
  assert tracked is not None;save('listener.json',tracked)
  # Start bounded read-only samplers; no extra synchronous SSH between listener and client.
  sampler="for n in $(seq 1 10); do date -u +%s.%N; cat /proc/uptime; ss -ntip 'sport = :8081 or dport = :8081'; sleep 1; done"
  for endpoint in ['target','client']:
   processes.append((endpoint+'-sockets',subprocess.Popen(ssh(endpoint,'sudo sh -c '+shlex.quote(sampler)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True),30))
  owner={'file':directory+'/received.bin','listener':tracked};observer_command=growth.command(owner,240).replace("ss -ntip state established", "ss -ntip")
  gp=subprocess.Popen(ssh('target',observer_command),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(('growth',gp,300))
  # FIFO producer exit and nc exit are recorded independently; outer process-group
  # timeout bounds producer, nc and any blocked FIFO writer together.
  # Explicit producer subshell records its status, avoiding pipeline-last exit.
  body='umask 077; mkfifo -m 600 '+directory+'/fifo || exit; ( ( for n in $(seq 1 200); do dd if='+directory+'/send.bin bs=65536 count=1 status=none || exit; sleep 1; done ) > '+directory+'/fifo; x=$?; printf "%s\\n" "$x" > '+directory+'/producer-exit; exit "$x" ) & producer=$!; timeout -k 3 270 nc -N -s '+CLIENT+' '+TARGET+' 8081 < '+directory+'/fifo > '+directory+'/client-received.bin; nc_exit=$?; wait "$producer"; producer_exit=$?; printf "nc_exit=%s producer_exit=%s\\n" "$nc_exit" "$producer_exit"; test "$nc_exit" = 0 && test "$producer_exit" = 0'
  result=call('client','sudo timeout -k 3 280 sh -c '+shlex.quote(body),timeout=300);save('client-raw.json',result)

 finally:
  for name,process,bound in processes:save(name+'-raw.json',collect(process,bound))
  save('headers-raw.json',collect(hp,310))
 after_listener=call('target','sudo sh -c '+shlex.quote('if test -e /proc/'+str(tracked['pid'])+'/stat; then cat /proc/'+str(tracked['pid'])+'/stat; else echo ABSENT; fi'));save('listener-after.json',after_listener);assert after_listener['exit']==0 and after_listener['stdout'].strip()=='ABSENT','Tracked listener completion not independently proved; retain duty'
 assert result['exit']==0 and read('target-raw.json')['exit']==0,'Raw evidence retained; unknown remote process duty must be inspected, never replayed'
 expected=checked('client','sudo sh -c '+shlex.quote('for n in $(seq 1 200); do dd if='+directory+'/send.bin bs=65536 count=1 status=none; done | sha256sum'));save('expected-stream-hash.json',expected)
 value=checked('target','sudo stat -c %u:%a:%s '+directory+'/received.bin; sudo sha256sum '+directory+'/received.bin');save('target-integrity.json',value);lines=value['stdout'].splitlines();assert lines[0]=='0:600:13107200' and lines[1].split()[0]==expected['stdout'].split()[0]
 producer=checked('client','sudo cat '+directory+'/producer-exit');save('producer-result.json',producer);assert producer['stdout'].strip()=='0'
 raw=read('growth-raw.json');assert raw['exit']==0;save('growth-result.json',growth.parse(raw['stdout'].encode(),owner))
 save('native-after.json',native_snapshot());save('result.json',{'passed':True,'client_to_target_bytes':13107200,'single_socket':True,'paced_blocks':200,'growth_clock_alignment_review_required':True,'counter_review_required':True,'no_api_writes':True,'original_failed_files_preserved':True})
if __name__=='__main__':main()
