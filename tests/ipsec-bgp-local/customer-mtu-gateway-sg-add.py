#!/usr/bin/env python3
"""Local standard SSH; one additive owned gateway TCP8081 ingress rule. Review-only default."""
import argparse,hashlib,json,os,pathlib,shlex,stat,subprocess,time
SG='sg-026e49d0f7558609a';ENI='eni-0fbe6981ac51bb28e';INSTANCE='i-09d129f71f43119c7';GROUPS={SG,'sg-03ca9cb5b3b36d17a'}
CLIENT='10.84.2.10/32';DESCRIPTION='tnx-customer-mtu-8081-client32-20261008'
PERMISSION={'IpProtocol':'tcp','FromPort':8081,'ToPort':8081,'IpRanges':[{'CidrIp':CLIENT,'Description':DESCRIPTION}]}
def canonical(rules):return sorted(rules,key=lambda x:x['SecurityGroupRuleId'])
def exact(rule):return rule.get('GroupId')==SG and rule.get('IsEgress')is False and rule.get('IpProtocol')=='tcp' and rule.get('FromPort')==rule.get('ToPort')==8081 and rule.get('CidrIpv4')==CLIENT and rule.get('Description')==DESCRIPTION and not any(rule.get(k)for k in ['CidrIpv6','PrefixListId','ReferencedGroupInfo'])
def save(name,value):
 with(out/name).open('x')as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def aws(name,args):
 argv=['aws','--region','eu-north-1','--output','json',*args];result=subprocess.run(['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',shlex.join(argv)],capture_output=True,text=True,timeout=45);raw={'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'at':time.time()};save(name+'-raw.json',raw);assert result.returncode==0,raw;return json.loads(result.stdout)if result.stdout.strip()else None

def main():
 global out
 p=argparse.ArgumentParser();p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--release',type=pathlib.Path);p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'region':'eu-north-1','gateway_eni':ENI,'group':SG,'permission':PERMISSION,'existing_groups_preserved':True}));return
 assert a.release and json.loads(a.release.read_text())['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
 os.umask(0o077);assert a.out.is_absolute()and not a.out.exists()and a.out.parent.resolve()==a.out.parent;out=a.out;out.mkdir(mode=0o700)
 eni=aws('eni-before',['ec2','describe-network-interfaces','--network-interface-ids',ENI])['NetworkInterfaces'];assert len(eni)==1;v=eni[0];assert v['Attachment']['InstanceId']==INSTANCE and v['PrivateIpAddress']=='10.84.1.10' and {x['GroupId']for x in v['Groups']}==GROUPS
 instance=aws('instance-before',['ec2','describe-instances','--instance-ids',INSTANCE])['Reservations'][0]['Instances'][0];tags={x['Key']:x['Value']for x in instance['Tags']};assert instance['State']['Name']=='running' and instance['PublicIpAddress']=='13.63.169.255' and tags.get('TunnexLab')=='tunnex-bgp-20261007' and tags.get('LabComponent')=='gateway'
 group=aws('group-before',['ec2','describe-security-groups','--group-ids',SG])['SecurityGroups'];assert len(group)==1 and group[0]['VpcId']==v['VpcId'];sgtags={x['Key']:x['Value']for x in group[0]['Tags']};assert sgtags.get('TunnexLab')=='tunnex-bgp-20261007' and sgtags.get('LabComponent')=='gateway-sg'
 before=aws('rules-before',['ec2','describe-security-group-rules','--filters','Name=group-id,Values='+SG])['SecurityGroupRules'];assert not any(exact(r)for r in before),'Existing outcome must be reconciled; never replay an unknown add'
 save('pending.json',{'group':SG,'eni':ENI,'instance':INSTANCE,'permission':PERMISSION,'foreign_rules':canonical(before),'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()})
 added=aws('add',['ec2','authorize-security-group-ingress','--group-id',SG,'--ip-permissions',json.dumps([PERMISSION])]);assert added.get('Return')is True and len(added['SecurityGroupRules'])==1 and exact(added['SecurityGroupRules'][0]);owned=added['SecurityGroupRules'][0]
 after=aws('rules-after',['ec2','describe-security-group-rules','--filters','Name=group-id,Values='+SG])['SecurityGroupRules'];assert [r for r in after if r['SecurityGroupRuleId']==owned['SecurityGroupRuleId']]==[owned];assert canonical([r for r in after if r['SecurityGroupRuleId']!=owned['SecurityGroupRuleId']])==canonical(before)
 current=aws('eni-after',['ec2','describe-network-interfaces','--network-interface-ids',ENI])['NetworkInterfaces'][0];assert current['Attachment']==v['Attachment'] and sorted(current['Groups'],key=lambda x:x['GroupId'])==sorted(v['Groups'],key=lambda x:x['GroupId'])
 save('result.json',{'passed':True,'owned_rule':owned,'foreign_rules_preserved':True,'eni_groups_unchanged':True,'packet_acceptance':False,'cleanup_command':['aws','--region','eu-north-1','ec2','revoke-security-group-ingress','--group-id',SG,'--security-group-rule-ids',owned['SecurityGroupRuleId']],'cleanup_requires_exact_live_owned_readback_and_foreign_preservation':True})
if __name__=='__main__':main()
