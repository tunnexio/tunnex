#!/usr/bin/env python3
"""Exact owned VGW peer2 host forwarding fault. Default review only."""
import argparse,datetime,hashlib,json,os,pathlib,subprocess
os.umask(0o077);assert os.geteuid()==0
p=argparse.ArgumentParser();p.add_argument('action',choices=['begin','restore','observe']);p.add_argument('--execute',action='store_true');a=p.parse_args()
ROOT=pathlib.Path('/home/ubuntu/tunnex-bgp-lab');RUN=ROOT/'vgw-wire-failover-peer2-20261008';CID='382b1763ae4bd0fa21a871839af4be0d9c0c8e37dc7d57c85a68172cfff6be06';PEER='51.20.220.141';LOCAL='172.30.88.2';PREFIX='tunnex-vgw-peer2-fault-20261008-'
def cmd(*args):return subprocess.check_output(list(args),text=True)
def save(p,obj):
 with p.open('x')as f:json.dump(obj,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def identity():
 d=json.loads(cmd('docker','inspect',CID))[0];assert d['Id']==CID and d['State']['Running']and d['Config']['Labels']['tunnex.lab']=='tunnex-bgp-20261007';assert d['Image']=='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2';assert cmd('docker','exec',CID,'sha256sum','/proc/1/exe').split()[0]=='b659a3a54528575f44afb28aa1e2c09508fdc6ef313d1ebe43b7f937cc5f1145';ns=cmd('docker','exec',CID,'readlink','/proc/1/ns/net').strip();assert ns=='net:[4026532807]';cert=cmd('docker','exec',CID,'sha256sum','/state/cert.pem').split()[0];assert cert=='eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d';endpoint=d['NetworkSettings']['Networks']['tunnex-bgp-20261007-net'];assert endpoint['IPAddress']==LOCAL;net=json.loads(cmd('docker','network','inspect',endpoint['NetworkID']))[0];assert net['Labels']['tunnex.lab']=='tunnex-bgp-20261007';bridge=net['Options'].get('com.docker.network.bridge.name','br-'+net['Id'][:12]);route=json.loads(cmd('ip','-j','-4','route','get',PEER));assert len(route)==1 and route[0]['dev']=='enp39s0'and route[0]['gateway']=='10.84.1.1'and route[0]['prefsrc']=='10.84.1.10';physical=route[0]['dev'];link=json.loads(cmd('ip','-j','link','show','dev',physical));assert len(link)==1 and link[0]['ifindex']==2 and link[0]['address']=='06:ff:c9:e7:22:9f'and 'UP'in link[0]['flags'];return {'container':CID,'namespace':ns,'certificate_sha256':cert,'bridge':bridge,'physical':physical,'physical_ifindex':link[0]['ifindex'],'physical_mac':link[0]['address'],'physical_source':route[0]['prefsrc'],'started_at':d['State']['StartedAt'],'pid':d['State']['Pid']}
def rules(identity):
 result=[]
 for direction in ['out','in']:
  for port in [500,4500]:
   path=['-i',identity['bridge'],'-o',identity['physical'],'-s',LOCAL+'/32','-d',PEER+'/32']if direction=='out'else['-i',identity['physical'],'-o',identity['bridge'],'-s',PEER+'/32','-d',LOCAL+'/32'];result.append(path+['-p','udp','--dport',str(port),'-m','comment','--comment',PREFIX+direction+'-'+str(port),'-j','DROP'])
 return result
def foreign():return [line for line in cmd('iptables','-S').splitlines()if PREFIX not in line]
def matches(rule):return subprocess.run(['iptables','-C','FORWARD',*rule],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
id=identity();planned=rules(id)
if a.action=='observe':
 assert RUN.exists();baseline=json.loads((RUN/'before.json').read_text());assert id==baseline['identity']and foreign()==baseline['foreign_rules'];print(cmd('iptables','-L','FORWARD','-v','-n','-x'));raise SystemExit(0)
if not a.execute:print(json.dumps({'action':a.action,'review_only':True,'identity':id,'peer':PEER,'rules':planned}));raise SystemExit(0)
if a.action=='begin':
 assert not RUN.exists();assert not any(PREFIX in line for line in cmd('iptables','-S').splitlines());RUN.mkdir(mode=0o700);save(RUN/'before.json',{'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'identity':id,'foreign_rules':foreign(),'rules':planned,'helper_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()});save(RUN/'begin-pending.json',{'scope':'four exact owned peer2 UDP forwarding drops','identity':id})
 for rule in planned:
  assert identity()==id and not matches(rule);subprocess.run(['iptables','-I','FORWARD','1',*rule],check=True)
 assert foreign()==json.loads((RUN/'before.json').read_text())['foreign_rules'];assert all(matches(rule)for rule in planned);save(RUN/'begun.json',{'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'identity':id,'counter_readback':cmd('iptables','-L','FORWARD','-v','-n','-x')});print('OWNED_PEER2_UDP_FAULT_BEGUN')
else:
 assert RUN.exists();before=json.loads((RUN/'before.json').read_text());assert id==before['identity']and foreign()==before['foreign_rules'];assert before['rules']==planned;save(RUN/'restore-pending.json',{'identity':id,'counter_readback_before':cmd('iptables','-L','FORWARD','-v','-n','-x')})
 for rule in planned:
  if matches(rule):subprocess.run(['iptables','-D','FORWARD',*rule],check=True)
 assert not any(matches(rule)for rule in planned);assert foreign()==before['foreign_rules'];save(RUN/'restored.json',{'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'identity':id,'foreign_rules_preserved':True,'owned_fault_rules_absent':True,'counter_readback_after':cmd('iptables','-L','FORWARD','-v','-n','-x')});print('OWNED_PEER2_UDP_FAULT_RESTORED')
