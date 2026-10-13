#!/usr/bin/env python3
"""Owned regional target secondary ENI attachment; default is source-only.
Run only on designated16 after root reviews pins; Linux/service phases remain explicit.
"""
import argparse,hashlib,json,os,pathlib,stat,subprocess,time
OWNER='tunnex-static-central-customer-20261008'
ROOT=pathlib.Path('/home/ubuntu')/OWNER
REGION='eu-central-1'
def private(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
  with os.fdopen(os.dup(fd))as f:return json.load(f)
 finally:os.close(fd)
def save(p,value):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w')as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def owned(x, field='Tags'):
 tags=x.get(field);return type(tags)is list and any(type(t)is dict and t.get('Key')=='TunnexLab' and t.get('Value')==OWNER for t in tags)
def validate(target,eni,subnet,p):
 assert target['InstanceId']==p['target_id'] and target['State']['Name']=='running' and target['InstanceType']=='t3.micro' and owned(target)
 assert target['Placement']['AvailabilityZone']=='eu-central-1a'
 primary=[x for x in target['NetworkInterfaces']if x['Attachment']['DeviceIndex']==0]
 assert len(primary)==1 and len(target['NetworkInterfaces'])==1
 assert primary[0]['NetworkInterfaceId']==p['primary_eni_id'] and primary[0]['PrivateIpAddress']=='10.87.1.10' and primary[0]['MacAddress']==p['primary_mac']
 assert eni['NetworkInterfaceId']==p['secondary_eni_id'] and owned(eni, 'TagSet') and eni['Status']=='available' and not eni.get('Attachment')
 assert eni['PrivateIpAddress']=='10.87.2.10' and len(eni['PrivateIpAddresses'])==1 and eni['MacAddress']==p['secondary_mac']
 assert subnet['SubnetId']==eni['SubnetId']==p['secondary_subnet_id'] and owned(subnet) and subnet['CidrBlock']=='10.87.2.0/24' and subnet['AvailabilityZone']=='eu-central-1a'
 assert eni['VpcId']==subnet['VpcId']==target['VpcId']==p['vpc_id'] and {g['GroupId']for g in eni['Groups']}=={p['security_group_id']}
 return primary[0]
def plan():return {'source_only':True,'region':REGION,'owner':OWNER,'target':'phase1 exact new owned t3.micro','primary':{'ip':'10.87.1.10','device_index':0,'preserve_management':True,'service_bind':'10.87.1.10:8080'},'secondary':{'ip':'10.87.2.10','device_index':1,'namespace':'tnx-static-central-tgw-20261008','service_bind':'10.87.2.10:8080'},'linux_order':['Snapshot primary physical MAC/ifindex/IP/routes/rules/default and SSH management identity; all namespace/service/codepaths absent.','Bind secondary physical ENIID/MAC/index1 to exact AWS attachment and current IMDS interface mapping. Never infer ens name.','Only if new NIC routes/addresses exactly owned DHCP tuples, record then networkctl down ONLY that NIC; preserve primary snapshot. Refuse foreign state, no global networkd restart.','O_EXCL namespace intent, move ONLY exact secondary physicalNIC into fresh namespace; lo/NIC up, exact87.2.10/24 and default87.2.1 add with absent-before/readback-after.','Create independent root-private nonce echo services bound exact87.1.10:8080 primary and87.2.10:8080 namespace, no0.0.0.0 listener; code/unit SHA and PID/start/exe/ns/socket readback.','Independent management GET fresh nonce echoes hash and logsource; VPN application proof must use actual client84.2.10 through gateway, never localhostcontrol.'],'excluded':['No provider/SG/gateway/route-table writes','No private key copy','No primary ENI movement','No Linux/service mutation by attach phase']}
def main():
 a=argparse.ArgumentParser();a.add_argument('--execute-attach',action='store_true');a.add_argument('--pins',type=pathlib.Path);x=a.parse_args()
 if not x.execute_attach:print(json.dumps(plan(),indent=2));return
 assert os.getuid()==0 and x.pins;os.umask(0o077);p=private(x.pins)
 assert p['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
 assert subprocess.check_output(['curl','-fsS','--max-time','3','http://checkip.amazonaws.com']).decode().strip()=='16.170.207.192'
 def aws(action,*args):
  q=subprocess.run(['aws','--region',REGION,'--output','json','--no-cli-pager','ec2',action,*args],capture_output=True,timeout=40)
  assert q.returncode==0;return json.loads(q.stdout)
 target=aws('describe-instances','--instance-ids',p['target_id'])['Reservations'][0]['Instances'][0]
 eni=aws('describe-network-interfaces','--network-interface-ids',p['secondary_eni_id'])['NetworkInterfaces'][0]
 subnet=aws('describe-subnets','--subnet-ids',p['secondary_subnet_id'])['Subnets'][0];primary=validate(target,eni,subnet,p)
 d=ROOT/'phase2-attach';d.mkdir(mode=0o700,exist_ok=True);assert not d.is_symlink() and d.stat().st_uid==0 and stat.S_IMODE(d.stat().st_mode)==0o700
 assert not os.path.lexists(d/'intent.json') and not os.path.lexists(d/'result.json'),'Unknown/prior outcome: readonly reconcile, no replay'
 save(d/'before.json',{'target':target,'eni':eni,'subnet':subnet})
 save(d/'intent.json',{'target':p['target_id'],'eni':p['secondary_eni_id'],'device_index':1,'primary':primary,'source_sha256':p['source_sha256']})
 result=aws('attach-network-interface','--network-interface-id',p['secondary_eni_id'],'--instance-id',p['target_id'],'--device-index','1');save(d/'result.json',result)
 after=aws('describe-network-interfaces','--network-interface-ids',p['secondary_eni_id'])['NetworkInterfaces'][0]
 assert after['Attachment']['AttachmentId']==result['AttachmentId'] and after['Attachment']['InstanceId']==p['target_id'] and after['Attachment']['DeviceIndex']==1
 t=aws('describe-instances','--instance-ids',p['target_id'])['Reservations'][0]['Instances'][0];now=[e for e in t['NetworkInterfaces']if e['Attachment']['DeviceIndex']==0];assert now==[primary]
 save(d/'verified.json',{'attachment':after,'primary_preserved':True,'linux_mutations':False});print('Exact owned secondary ENI attached; Linux phases not executed')
if __name__=='__main__':main()
