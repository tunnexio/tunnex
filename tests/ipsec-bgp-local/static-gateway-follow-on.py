#!/usr/bin/env python3
"""Source-only default. One reviewed additive AWS16 or Linux13 step per execution.
Unknown outcomes remain pending; no replay, replacement, adoption or automatic rollback.
"""
import argparse,fcntl,hashlib,ipaddress,json,os,pathlib,runpy,stat,subprocess,time
PLAN_SHA='90d35637c567402cf3ec85f6b22c624162b9616cd6daa984512b193b001c9648'
OWNER='tunnex-static-central-gateway-20261008';ACCOUNT='867703355911'
AWS_STEPS=['create-sg','udp','attach-sg','detach-sg'];LINUX_STEPS=['route1','route2','route1-remove','route2-remove']+['fw'+str(i)+suffix for i in range(4)for suffix in ['', '-remove']]
def canonical_rules(raw):return [line.split()for line in raw.splitlines()if line.strip()]
def destination(row):
 value=row.get('dst');assert isinstance(value,str)
 return ipaddress.ip_network('0.0.0.0/0'if value=='default'else value,strict=False)
def route_matches(row,w):
 try:dst=destination(row)
 except (KeyError,ValueError):return False
 return dst==ipaddress.ip_network(w['destination'])and row.get('gateway')==w['via']and row.get('dev')==w['device']and row.get('table','main')in ['main',254]and row.get('protocol')in [242,'242']and row.get('metric')==w['metric']and row.get('type','unicast')=='unicast'and row.get('flags',[])==[]and not any(k in row for k in ['nhid','multipath','encap','nexthops'])
def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 with os.fdopen(fd)as f:return json.load(f)
def group_rules(rows):
 out=[]
 for row in rows:
  row=dict(row)
  if 'Tags'in row:row['Tags']=sorted(row['Tags'],key=lambda t:(t['Key'],t['Value']))
  out.append(row)
 return sorted(out,key=lambda r:r['SecurityGroupRuleId'])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--step',choices=AWS_STEPS+LINUX_STEPS,required=True);ap.add_argument('--state',type=pathlib.Path);ap.add_argument('--release',type=pathlib.Path);ap.add_argument('--execute',action='store_true');a=ap.parse_args()
 planpath=pathlib.Path(__file__).with_name('static-gateway-follow-on-plan.py');assert hashlib.sha256(planpath.read_bytes()).hexdigest()==PLAN_SHA;plan=runpy.run_path(str(planpath))['PLAN']
 if not a.execute:print(json.dumps({'source_only':True,'step':a.step,'plan_sha256':PLAN_SHA}));return
 assert os.geteuid()==0 and a.state and a.release;os.umask(0o077);release=private(a.release);assert release['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()and release['plan_sha256']==PLAN_SHA and release['step']==a.step
 assert a.state==pathlib.Path('/home/ubuntu')/OWNER and release['host']==('16.170.207.192'if a.step in AWS_STEPS else'13.63.169.255')
 if not a.state.exists():a.state.mkdir(mode=0o700)
 assert not a.state.is_symlink()and a.state.stat().st_uid==0 and stat.S_IMODE(a.state.stat().st_mode)==0o700
 lock=os.open(a.state/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);info=os.fstat(lock);assert info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600;fcntl.flock(lock,fcntl.LOCK_EX)
 statefd=os.open(a.state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);stateinfo=os.fstat(statefd)
 def state_current():
  now=os.lstat(a.state);assert os.path.samestat(stateinfo,now)and now.st_uid==0 and stat.S_IMODE(now.st_mode)==0o700
 def save(name,value):
  state_current();assert '/'not in name
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=statefd)
  with os.fdopen(fd,'w')as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
  os.fsync(statefd)
  ledgerfd=os.open('ledger.jsonl',os.O_RDWR|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600,dir_fd=statefd);lst=os.fstat(ledgerfd);assert lst.st_uid==0 and stat.S_IMODE(lst.st_mode)==0o600
  prior=os.read(ledgerfd,1048577);assert len(prior)<=1048576
  rows=[json.loads(line)for line in prior.splitlines()];assert all(row['physical_ordinal']==i+1 for i,row in enumerate(rows))
  event={'physical_ordinal':len(rows)+1,'file':name,'sha256':hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest(),'wall':time.time()};os.write(ledgerfd,(json.dumps(event)+'\n').encode());os.fsync(ledgerfd);os.close(ledgerfd);os.fsync(statefd)
 def run(argv):
  p=subprocess.run(argv,capture_output=True,text=True,timeout=40);assert p.returncode==0,'Read-only prerequisite failed';return p.stdout
 def mutate(argv):
  save(a.step+'-pending.json',{'argv':argv,'wall':time.time(),'release':release})
  try:p=subprocess.run(argv,capture_output=True,text=True,timeout=40)
  except subprocess.TimeoutExpired as error:
   save(a.step+'-timeout.json',{'unknown_outcome':True,'stdout':(error.stdout or b'').decode(errors='replace')if isinstance(error.stdout,bytes)else error.stdout,'stderr':(error.stderr or b'').decode(errors='replace')if isinstance(error.stderr,bytes)else error.stderr});raise
  save(a.step+'-raw-result.json',{'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr});assert p.returncode==0,'Mutation outcome retained; never replay pending'
  return json.loads(p.stdout)if p.stdout.strip()else None
 assert not(a.state/(a.step+'-pending.json')).exists(),'Pending step exists; reconcile GET-only independently, never replay'
 if a.step in AWS_STEPS:
  aws=lambda args:json.loads(run(['aws','--region','eu-north-1','--output','json','--no-cli-pager']+args))
  assert aws(['sts','get-caller-identity'])['Account']==ACCOUNT
  en=aws(['ec2','describe-network-interfaces','--network-interface-ids',plan['gateway_eni']])['NetworkInterfaces'];assert len(en)==1;en=en[0];assert en['Attachment']['InstanceId']==plan['gateway_instance']and en['PrivateIpAddress']=='10.84.1.10'
  ins=aws(['ec2','describe-instances','--instance-ids',plan['gateway_instance']])['Reservations'][0]['Instances'][0];assert ins['State']['Name']=='running'and {t['Key']:t['Value']for t in ins['Tags']}['TunnexLab']=='tunnex-bgp-20261007'
  old=plan['previous_expected_groups'];groups=sorted(g['GroupId']for g in en['Groups']);before=group_rules(aws(['ec2','describe-security-group-rules','--filters','Name=group-id,Values='+','.join(old)])['SecurityGroupRules'])
  save(a.step+'-before.json',{'eni':en,'instance_id':ins['InstanceId'],'foreign_rules':before})
  if a.step=='create-sg':
   assert groups==sorted(old)
   collisions=aws(['ec2','describe-security-groups','--filters','Name=tag:TunnexLab,Values='+OWNER])['SecurityGroups'];assert not collisions,'Unknown owner-tag object; no adoption'
   save('aws-baseline.json',{'eni':en,'foreign_rules':before})
   specs=json.dumps([{'ResourceType':'security-group','Tags':[{'Key':k,'Value':v}for k,v in plan['new_sg']['tags'].items()]}])
   result=mutate(['aws','--region','eu-north-1','--output','json','ec2','create-security-group','--vpc-id',en['VpcId'],'--group-name',OWNER,'--description',OWNER,'--tag-specifications',specs]);assert result and result['GroupId'];save('created-sg.json',{'id':result['GroupId'],'vpc':en['VpcId']})
  else:
   sg=private(a.state/'created-sg.json');own=aws(['ec2','describe-security-groups','--group-ids',sg['id']])['SecurityGroups'][0];assert own['VpcId']==en['VpcId']==sg['vpc']and {t['Key']:t['Value']for t in own['Tags']}['TunnexLab']==OWNER
   desired=[{'IpProtocol':'udp','FromPort':port,'ToPort':port,'IpRanges':[{'CidrIp':ip+'/32'}]}for ip in ['3.67.173.125','52.58.98.231','3.65.241.160','63.189.108.24']for port in [500,4500]]
   def expanded(perms):
    tuples=[]
    for x in perms:
     assert set(x)<= {'IpProtocol','FromPort','ToPort','IpRanges','Ipv6Ranges','PrefixListIds','UserIdGroupPairs'}and not x.get('Ipv6Ranges')and not x.get('PrefixListIds')and not x.get('UserIdGroupPairs')
     for cidr in x['IpRanges']:assert set(cidr)=={'CidrIp'};tuples.append((x['IpProtocol'],x['FromPort'],x['ToPort'],cidr['CidrIp']))
    return sorted(tuples)
   if a.step=='udp':assert groups==sorted(old)and own['IpPermissions']==[];mutate(['aws','--region','eu-north-1','--output','json','ec2','authorize-security-group-ingress','--group-id',sg['id'],'--ip-permissions',json.dumps(desired)]);own=aws(['ec2','describe-security-groups','--group-ids',sg['id']])['SecurityGroups'][0];assert expanded(own['IpPermissions'])==expanded(desired)
   elif a.step=='attach-sg':assert groups==sorted(old)and expanded(own['IpPermissions'])==expanded(desired);mutate(['aws','--region','eu-north-1','--output','json','ec2','modify-network-interface-attribute','--network-interface-id',plan['gateway_eni'],'--groups',*old,sg['id']])
   else:assert private(a.state/'attach-sg-verified.json')['passed']is True;assert groups==sorted(old+[sg['id']]);mutate(['aws','--region','eu-north-1','--output','json','ec2','modify-network-interface-attribute','--network-interface-id',plan['gateway_eni'],'--groups',*old])
   after=aws(['ec2','describe-network-interfaces','--network-interface-ids',plan['gateway_eni']])['NetworkInterfaces'][0];assert sorted(g['GroupId']for g in after['Groups'])==sorted(old+([sg['id']]if a.step=='attach-sg'else[]))
  assert group_rules(aws(['ec2','describe-security-group-rules','--filters','Name=group-id,Values='+','.join(old)])['SecurityGroupRules'])==before
 else:
  pin=plan['expected_worker_identity'];cid=pin['cid']
  def worker():
   d=json.loads(run(['docker','inspect',cid]))[0];assert d['Id']==cid and d['Image']==pin['image']and d['State']['Running']and d['State']['Pid']==pin['host_pid']
   ex=lambda args:run(['docker','exec',cid]+args).strip()
   mounts=[m for m in d['Mounts']if m['Destination']=='/binaries'];assert len(mounts)==1;assert run(['sha256sum',str(pathlib.Path(mounts[0]['Source'])/'tunnex-api')]).split()[0]==pin['api_sha256']
   networks=list(d['NetworkSettings']['Networks'].values());assert len(networks)==1 and networks[0]['IPAddress']=='172.30.88.2'
   net=json.loads(run(['docker','network','inspect',networks[0]['NetworkID']]))[0];assert net['Id']==networks[0]['NetworkID']and net['Driver']=='bridge'and net['Options']['com.docker.network.bridge.name']=='tnxbgplab0'
   assert ex(['readlink','/proc/1/ns/net'])==pin['namespace']and ex(['sha256sum','/proc/1/exe']).split()[0]==pin['node_sha256']and ex(['sha256sum','/state/cert.pem']).split()[0]==pin['cert_sha256']and ex(['cat','/proc/1/stat']).rsplit(')',1)[1].split()[19]==pin['startticks']
  worker();links=json.loads(run(['ip','-j','-d','link','show']));physical=next(x for x in links if x['ifname']=='enp39s0');assert physical['address']==plan['physical']['mac']and 'UP'in physical['flags'];bridge=next(x for x in links if x['ifname']=='tnxbgplab0');assert 'UP'in bridge['flags']and bridge['linkinfo']['info_kind']=='bridge'
  addresses=json.loads(run(['ip','-j','-4','addr','show']));assert any(x['ifname']=='enp39s0'and any(v.get('local')=='10.84.1.10'for v in x['addr_info'])for x in addresses)and any(x['ifname']=='tnxbgplab0'and any(v.get('local')=='172.30.88.1'and v.get('prefixlen')==24 for v in x['addr_info'])for x in addresses)
  routes=json.loads(run(['ip','-j','-4','route','show','table','all']));fw=canonical_rules(run(['iptables','-S','DOCKER-USER']));save(a.step+'-before.json',{'worker':pin,'links':links,'routes':routes,'forward':fw})
  if a.step.startswith('route'):
   i=int(a.step[5])-1;w=plan['host_routes'][i];matching=[x for x in routes if destination(x)==ipaddress.ip_network(w['destination'])];remove=a.step.endswith('-remove')
   if remove:assert private(a.state/('route'+str(i+1)+'-verified.json'))['passed']is True;assert len(matching)==1 and route_matches(matching[0],w);argv=list(w['add']);argv[4]='del'
   else:assert not matching;argv=w['add']
   worker();mutate(argv[2:]);after=json.loads(run(['ip','-j','-4','route','show','table','all']));rows=[x for x in after if destination(x)==ipaddress.ip_network(w['destination'])];assert not rows if remove else len(rows)==1 and route_matches(rows[0],w)
   assert [x for x in routes if x not in matching]==[x for x in after if x not in rows]
   if not remove:
    target='10.87.'+str(i+1)+'.10';gets=json.loads(run(['ip','-j','-4','route','get',target,'from','10.84.2.10','iif','enp39s0']));assert len(gets)==1 and gets[0]['dev']=='tnxbgplab0'and gets[0]['gateway']=='172.30.88.2'and gets[0].get('from')=='10.84.2.10';save(a.step+'-route-get.json',gets)
  else:
   i=int(a.step[2]);wanted=list(plan['host_forward_rules'][i][2:]);portkey='--sport'if'--sport'in wanted else'--dport';pos=wanted.index(portkey);wanted[pos:pos]=['-m','tcp'];literal=['-A',wanted[2]]+wanted[4:];remove=a.step.endswith('-remove');assert fw.count(literal)==(1 if remove else 0)
   worker();argv=list(wanted)
   if remove:assert private(a.state/('fw'+str(i)+'-verified.json'))['passed']is True;argv[1]='-D';del argv[3]
   mutate(argv);after=canonical_rules(run(['iptables','-S','DOCKER-USER']));assert after.count(literal)==(0 if remove else 1);assert [x for x in after if x!=literal]==[x for x in fw if x!=literal]
  worker()
 save(a.step+'-verified.json',{'passed':True,'step':a.step,'foreign_preserved':True,'no_api_or_grant_changes':True})
if __name__=='__main__':main()
