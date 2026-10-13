#!/usr/bin/env python3
"""LOCAL standard-SSH stages; source-only unless --execute. No source upload."""
import argparse,hashlib,json,os,pathlib,secrets,shlex,subprocess,time,stat,re
CID='b8baa489a1a6e24020676d75703db1ef28118178e97d38c9a00914dab2c20cad';NS='net:[4026532947]'
NODE='b85a470bfa46fb8d03487381c58d1be004aa5adc3fad6a1e50d9a575b72e6d76';CERT='eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d'
KEY='/home/ubuntu/tunnex-bgp-20261007/lab-key';BASE='/home/ubuntu/tunnex-bgp-vgw-eic-20261008'
API='/home/ubuntu/tunnex-bgp-lab/customer-mtu-access-normal-v2-24759fbe.py';APISHA='24759fbe710aeaf76cc403f66ce66aeb79343cf7a94853ed5e4c493e7112d7d3'
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
 result=subprocess.run(ssh(endpoint,command),capture_output=True,text=True,timeout=timeout)
 return {'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'at':time.time()}
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
def mutation(name,endpoint,command,timeout=30):
 save(name+'-pending.json',{'endpoint':endpoint,'command':command,'identity':identity(),'at':time.time(),'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()})
 r=call(endpoint,command,timeout);save(name+'-result.json',r);assert r['exit']==0,r;return r


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
def listener_identity(listener):
 pids=re.findall(r'pid=([0-9]+)',listener);assert len(set(pids))==1
 pid=pids[0];assert pid!='1353'
 output=checked('target','sudo readlink /proc/'+pid+'/exe; sudo cat /proc/'+pid+'/stat; sudo cat /proc/'+pid+'/cmdline')['stdout'];lines=output.splitlines();parts=lines[1][lines[1].rfind(')')+2:].split()
 assert lines[0]in ['/usr/bin/nc.openbsd','/usr/bin/netcat.openbsd'] and '8081'in lines[2] and TARGET in lines[2]
 return {'pid':int(pid),'startticks':parts[19],'exe':lines[0],'cmdline':lines[2]}
def listener_after(record):
 result=call('target','sudo test -e /proc/'+str(record['pid'])+'/stat')
 assert result['exit']in [0,1]
 if result['exit']==1:return {'original_process_absent':True}
 row=checked('target','sudo cat /proc/'+str(record['pid'])+'/stat')['stdout'];ticks=row[row.rfind(')')+2:].split()[19]
 return {'original_process_absent':ticks!=record['startticks'],'current_startticks':ticks}
def nc_transfer(kind,directory):
 # OpenBSD -N shutdown(SHUT_WR) after stdin EOF; receive stays open.
 # Both full-duplex producers send4MiB; this is not nc -q/reconnect.
 if kind=='duplex':
  server='timeout -k 2s 45s nc -N -l '+TARGET+' 8081 < '+directory+'/send.bin > '+directory+'/duplex-received.bin'
  client='timeout -k 2s 45s nc -N -s '+CLIENT+' '+TARGET+' 8081 < '+directory+'/send.bin > '+directory+'/duplex-received.bin';limit=60
 else:
  server='timeout -k 2s 240s nc -N -l '+TARGET+' 8081 < /dev/null > '+directory+'/stream-received.bin'
  producer='i=0; while [ "$i" -lt 180 ]; do dd if='+directory+'/block.bin bs=65536 count=1 status=none || exit 81; i=$((i+1)); sleep 1; done'
  client='mkfifo '+directory+'/stream.fifo; ('+producer+'; echo $? > '+directory+'/producer-exit) > '+directory+'/stream.fifo & producer=$!; timeout -k 2s 240s nc -N -s '+CLIENT+' '+TARGET+' 8081 < '+directory+'/stream.fifo > '+directory+'/stream-output.bin; nc_status=$?; wait "$producer"; wait_status=$?; cat '+directory+'/producer-exit; printf "nc_exit=%s producer_wait=%s\\n" "$nc_status" "$wait_status"; test "$nc_status" = 0 && test "$wait_status" = 0 && test "$(cat '+directory+'/producer-exit)" = 0';limit=255
 save(kind+'-native-before.json',native_snapshot())
 save(kind+'-pending.json',{'identity':identity(),'server':server,'client':client,'at':time.time()})
 proc=subprocess.Popen(ssh('target','sudo sh -c '+shlex.quote('set -C; '+server)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  for _ in range(15):
   listener=checked('target','sudo ss -lntp sport = :8081')['stdout']
   if TARGET+':8081' in listener:break
   assert proc.poll() is None;time.sleep(1)
  else:raise AssertionError('Listener not ready')
  tracked=listener_identity(listener);save(kind+'-listener.json',{'ss':listener,'identity':tracked,'at':time.time()})
  hostpid=identity()['container'][3]
  filter_text='host '+CLIENT+' and host '+TARGET+' and tcp port 8081 and tcp[tcpflags] & tcp-syn != 0'
  header_command=shlex.join(['sudo','timeout','-k','2s','245s'if kind=='stream'else'50s','nsenter','-t',hostpid,'-n','tcpdump','-l','-i','any','-nn','-tt','-vv','-s','128',filter_text])
  headers=subprocess.Popen(ssh('gateway',header_command),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  time.sleep(1)
  r=call('client','sudo timeout -k 2s '+('240s'if kind=='stream'else'50s')+' sh -c '+shlex.quote('set -C; '+client),limit);save(kind+'-client.json',r)
  output,error=proc.communicate(timeout=20);save(kind+'-target.json',{'exit':proc.returncode,'stdout':output,'stderr':error});assert r['exit']==proc.returncode==0
  post=listener_after(tracked);assert post['original_process_absent'];save(kind+'-listener-after.json',post)
 except BaseException:
  # Do not kill foreign nc/processes; its approved remote timeout remains bound.
  if 'tracked'in locals():save(kind+'-listener-failed.json',{'identity':tracked,'actual':listener_after(tracked),'remote_timeout_seconds':240 if kind=='stream'else 45})
  proc.terminate();raise
 finally:
  if 'headers'in locals():
   try:
    text,error=headers.communicate(timeout=65)
    save(kind+'-headers.json',{'stdout':text,'stderr':error,'exit':headers.returncode,'payload_capture':False})
   except subprocess.TimeoutExpired:
    headers.terminate();save(kind+'-headers-pending.json',{'bounded_remote_timeout':245,'receipt_incomplete':True})
 checks={}
 for endpoint in ['client','target']:
  name='duplex-received.bin' if kind=='duplex' else ('stream-output.bin'if endpoint=='client'else'stream-received.bin')
  checks[endpoint]=checked(endpoint,'sudo stat -c %s '+directory+'/'+name+'; sudo sha256sum '+directory+'/'+name)['stdout']
 if kind=='duplex':
  for endpoint,other in [('client','target'),('target','client')]:
   sent=checked(endpoint,'sudo sha256sum '+directory+'/send.bin')['stdout'].split()[0];assert checks[other].splitlines()[0]=='4194304' and checks[other].splitlines()[1].split()[0]==sent
 else:
  expected=checked('client','sudo sh -c '+shlex.quote('i=0; while [ "$i" -lt 180 ]; do dd if='+directory+'/block.bin bs=65536 count=1 status=none; i=$((i+1)); done | sha256sum'))['stdout'].split()[0]
  assert checks['target'].splitlines()[0]==str(180*65536) and checks['target'].splitlines()[1].split()[0]==expected
 save(kind+'-native-after.json',native_snapshot())
 save(kind+'-integrity.json',{'checks':checks,'identity':identity(),'passed':True,'encryption_counter_review_required':True,'same_socket_header_review_required':kind=='stream'})

def verify_denied(directory):
 save('withdraw-deny-pending.json',{'identity':identity(),'at':time.time()})
 before=native_snapshot()
 control=checked('target','curl -sS --max-time 5 -o /dev/null -w HTTP=%{http_code} http://127.0.0.1:8080/');assert control['stdout']=='HTTP=200'
 server='sudo timeout -k 2s 30s nc -N -l '+TARGET+' 8081 < /dev/null > /dev/null'
 process=subprocess.Popen(ssh('target',server),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  for _ in range(10):
   row=checked('target','sudo ss -lntp sport = :8081')['stdout']
   if TARGET+':8081'in row:break
   assert process.poll()is None;time.sleep(1)
  else:raise AssertionError('Independent target listener unavailable')
  tracked=listener_identity(row);save('withdraw-deny-listener.json',tracked)
  probe=checked('client',"timeout -k 2s 6s nc -z -w 5 -s "+CLIENT+' '+TARGET+" 8081; code=$?; printf '\n__probe_exit:%s\n' \"$code\"")
  code=int(probe['stdout'].split('__probe_exit:')[-1]);assert code in [1,124],'Fresh withdrawn connection unexpectedly allowed'
  still_listening=checked('target','sudo ss -lntp sport = :8081')['stdout'];assert TARGET+':8081'in still_listening and listener_identity(still_listening)==tracked,'Target listener ceased before denial proof'
  save('withdraw-deny-listener-during.json',{'identity':tracked,'ss':still_listening,'at':time.time()})
  output,error=process.communicate(timeout=35);post=listener_after(tracked);assert post['original_process_absent']
  save('withdraw-deny-result.json',{'probe':probe,'target_timeout_exit':process.returncode,'target_stdout':output,'target_stderr':error,'target_control':control,'listener_after':post,'before':before,'after':native_snapshot(),'fresh_connection_denied':True,'drop_counter_review_required':True})
 finally:
  if process.poll()is None:
   save('withdraw-deny-listener-pending.json',{'identity':tracked if 'tracked'in locals()else None,'actual':listener_after(tracked)if 'tracked'in locals()else None,'bounded_remote_timeout_seconds':30,'not_yet_proved_absent':True})
   process.terminate()

def main():
 global run
 p=argparse.ArgumentParser();p.add_argument('stage',choices=['preflight','createfixture','infra','grant-transfer','stream','observe','cleanup']);p.add_argument('--run',type=pathlib.Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args();run=a.run
 if not a.execute:print(json.dumps({'source_only':True,'stage':a.stage,'gateway':CID,'namespace':NS,'no_source_upload':True}));return
 os.umask(0o077);assert run.is_absolute() and run.parent.resolve()==run.parent
 if run.exists():
  st=run.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700 and run.resolve()==run
 if a.stage=='preflight':
  assert not run.exists();run.mkdir(mode=0o700);i=identity();save('baseline.json',{'identity':i,'nonce':secrets.token_hex(32),'host_rules':checked('gateway','sudo iptables -S DOCKER-USER')['stdout'],'sg':checked('bastion','aws --region eu-north-1 --output json ec2 describe-security-group-rules --filters Name=group-id,Values='+SG)['stdout']})
  for endpoint,ip in [('client',TARGET),('target',CLIENT)]:
   help_result=call(endpoint,'nc -h');help_text=help_result['stdout']+help_result['stderr'];assert '-N'in help_text,'Installed nc must support half-close'
   route=checked(endpoint,'ip -j -4 route get '+ip)['stdout'];rows=json.loads(route);assert len(rows)==1 and rows[0]['dev']=='ens5' and rows[0]['prefsrc']==(CLIENT if endpoint=='client'else TARGET)
   save(endpoint+'-preflight.json',{'nc_help':help_text,'route':route,'tools':checked(endpoint,'command -v nc timeout dd sha256sum mkfifo')['stdout']})
  assert checked('gateway','sudo sha256sum '+API)['stdout'].split()[0]==APISHA
  inventory=json.loads(checked('bastion',"aws --region eu-north-1 --output json ec2 describe-instances --instance-ids i-09d129f71f43119c7 i-0cc22d71958707b0d i-0cd8ee7ba1e099092 --query 'Reservations[].Instances[].{id:InstanceId,ip:PrivateIpAddress,state:State.Name,groups:SecurityGroups[].GroupId,tags:Tags}'")['stdout']);assert len(inventory)==3
  for row in inventory:
   tags={v['Key']:v['Value']for v in row['tags']};assert tags.get('TunnexLab')=='tunnex-bgp-20261007' and row['state']=='running'
   if row['id']=='i-0cd8ee7ba1e099092':assert row['ip']==TARGET and set(row['groups'])=={SG,'sg-0cddbe7e854281932'}
   elif row['id']=='i-0cc22d71958707b0d':assert row['ip']==CLIENT and row['groups']==['sg-002b60b59e95eefc0']
   else:assert row['ip']=='10.84.1.10' and tags.get('LabComponent')=='gateway'
  save('aws-ownership.json',inventory)
  links=json.loads(checked('gateway','sudo ip -j link show dev enp39s0')['stdout']);assert len(links)==1 and links[0]['ifindex']==2 and links[0]['address']=='06:ff:c9:e7:22:9f' and 'UP'in links[0]['flags']
  networks=json.loads(checked('gateway','sudo docker inspect --format '+shlex.quote('{{json .NetworkSettings.Networks}}')+' '+CID)['stdout']);e=networks['tunnex-bgp-20261007-net'];assert e['IPAddress']=='172.30.88.2' and e['NetworkID']=='026856f1cdf8332d2e4dfea4994ffe478a2f521067c676a9dd374115ea857a5f'
  save('header-tools.json',{'installed':checked('gateway','command -v tcpdump nsenter')['stdout'],'namespace':checked('gateway','sudo nsenter -t '+i['container'][3]+' -n readlink /proc/self/ns/net')['stdout']});assert read('header-tools.json')['namespace'].strip()==NS
  save('underlay.json',{'links':links,'endpoint':e});save('native-nft-before.json',json.loads(checked('gateway','sudo docker exec '+CID+' nft -j list ruleset')['stdout']));save('preflight-complete.json',{'passed':True,'runtime_mutations':False});return
 assert a.stage=='observe','Mutation stages held pending exact grant/readback and listener cleanup review'
 b=read('baseline.json');assert identity()==b['identity'];nonce=b['nonce'];directory='/var/tmp/tunnex-customer-8081-'+nonce
 if a.stage=='createfixture':
  for endpoint in ['target','client']:
   c='umask 077; mkdir -m 700 '+directory+' && dd if=/dev/urandom of='+directory+'/send.bin bs=1048576 count=4 status=none && dd if=/dev/urandom of='+directory+'/block.bin bs=65536 count=1 status=none && sha256sum '+directory+'/send.bin '+directory+'/block.bin'
   mutation(endpoint+'-fixture',endpoint,'sudo sh -c '+shlex.quote(c))
 elif a.stage=='infra':
  permission=[{'IpProtocol':'tcp','FromPort':8081,'ToPort':8081,'IpRanges':[{'CidrIp':CLIENT+'/32','Description':'tnx-mtu-'+nonce}]}]
  r=mutation('sg-add','bastion',shlex.join(['aws','--region','eu-north-1','--output','json','ec2','authorize-security-group-ingress','--group-id',SG,'--ip-permissions',json.dumps(permission)]));v=json.loads(r['stdout']);ids=[x['SecurityGroupRuleId']for x in v['SecurityGroupRules']];assert len(ids)==1;save('sg-owned.json',{'id':ids[0],'permissions':permission})
  for k,rule in enumerate(hostrules(nonce)):
   c=shlex.join(['sudo','iptables','-C','DOCKER-USER',*rule]);assert call('gateway',c)['exit']==1
   mutation('host-add-'+str(k),'gateway',shlex.join(['sudo','iptables','-I','DOCKER-USER','1',*rule]));checked('gateway',c)
 elif a.stage=='grant-transfer':
  for action in ['resource','grant']:mutation('api-'+action,'gateway','sudo python3 '+API+' '+action+' --execute')
  # Explicit observed convergence precedes permission: operator uses observe then
  # this bounded wait; packet integrity remains counter-review-required.
  for _ in range(30):
   value=json.loads(checked('gateway','sudo docker exec '+CID+' nft -j list ruleset')['stdout'])
   try:healthy=actual_authority(value);break
   except (AssertionError,KeyError,TypeError):time.sleep(2)
  else:raise AssertionError('Exact fresh grant/lease convergence not observed')
  save('grant-convergence.json',{'nft':value,'healthy_interfaces':healthy,'at':time.time(),'exact_tuple_verified':True});nc_transfer('duplex',directory)
 elif a.stage=='stream':nc_transfer('stream',directory)
 elif a.stage=='observe':
  save('observe-'+secrets.token_hex(8)+'.json',{'identity':identity(),'nft':checked('gateway','sudo docker exec '+CID+' nft -j list ruleset')['stdout'],'sas':checked('gateway','sudo docker exec -e STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf '+CID+' /opt/tunnex-ipsec/sbin/swanctl --list-sas --uri unix:///run/tunnex-ipsec/charon.vici')['stdout'],'sockets_client':checked('client','sudo ss -nt sport != :22')['stdout'],'sockets_target':checked('target','sudo ss -nt sport = :8081')['stdout']})
 else:
  mutation('api-withdraw','gateway','sudo python3 '+API+' withdraw --execute')
  verify_denied(directory)
  mutation('api-cleanup-resource','gateway','sudo python3 '+API+' cleanup-resource --execute')
  for k,rule in enumerate(hostrules(nonce)):
   checked('gateway',shlex.join(['sudo','iptables','-C','DOCKER-USER',*rule]));mutation('host-delete-'+str(k),'gateway',shlex.join(['sudo','iptables','-D','DOCKER-USER',*rule]))
  owned=read('sg-owned.json');current=json.loads(checked('bastion','aws --region eu-north-1 --output json ec2 describe-security-group-rules --security-group-rule-ids '+owned['id'])['stdout'])['SecurityGroupRules'];assert len(current)==1 and current[0]['GroupId']==SG and current[0]['CidrIpv4']==CLIENT+'/32' and current[0]['FromPort']==current[0]['ToPort']==8081 and current[0]['Description']=='tnx-mtu-'+nonce
  mutation('sg-delete','bastion','aws --region eu-north-1 --output json ec2 revoke-security-group-ingress --group-id '+SG+' --security-group-rule-ids '+owned['id']);assert canonical_rules(checked('gateway','sudo iptables -S DOCKER-USER')['stdout'])==canonical_rules(b['host_rules']);after_sg=json.loads(checked('bastion','aws --region eu-north-1 --output json ec2 describe-security-group-rules --filters Name=group-id,Values='+SG)['stdout']);assert canonical_sg(after_sg)==canonical_sg(json.loads(b['sg']));save('cleanup.json',{'identity':identity(),'files_preserved':True,'normal_authority_withdrawn':True})
if __name__=='__main__':main()
