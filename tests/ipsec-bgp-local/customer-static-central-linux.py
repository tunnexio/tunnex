#!/usr/bin/env python3
"""SOURCE ONLY by default; exact owned central target namespace+nonce services.
Root-reviewed execute on target only. No AWS calls, primary NIC changes or replay.
"""
import argparse,hashlib,json,os,pathlib,re,stat,subprocess,time,urllib.request
INSTANCE='i-04d03ca61b1050e62';NS='tnx-static-central-tgw-20261008'
ROOT=pathlib.Path('/opt/tunnex-static-central-customer-20261008')
PRIMARY=('ens5',2,'02:ff:f5:10:37:2f','10.87.1.10');SECONDARY=('ens6',3,'02:ff:da:42:4f:65','10.87.2.10')
CODE='''import http.server,re,urllib.parse
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  value=urllib.parse.urlsplit(self.path);nonce=urllib.parse.parse_qs(value.query).get('nonce',[])
  if value.path!='/nonce' or len(nonce)!=1 or not re.fullmatch('[0-9a-f]{64}',nonce[0]):self.send_error(400);return
  body=(nonce[0]+'\\n').encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
http.server.HTTPServer((__import__('sys').argv[1],8080),Handler).serve_forever()
'''
def exact_link(links,addresses,binding):
 name,index,mac,ip=binding;l=[x for x in links if x.get('ifname')==name]
 assert len(l)==1 and l[0]['ifindex']==index and l[0]['address']==mac and l[0]['link_type']=='ether' and {'UP','LOWER_UP'}<=set(l[0]['flags'])
 a=[x for x in addresses if x.get('ifindex')==index];assert len(a)==1
 v=[x for x in a[0]['addr_info']if x['family']=='inet'];assert len(v)==1 and v[0]['local']==ip and v[0]['prefixlen']==24
 return {'link':l[0],'ipv4':{k:v[0][k]for k in ['family','local','prefixlen','scope','label']}}
def management(routes,rules):
 return {'routes':[x for x in routes if x.get('dev')!='ens6'],'rules':[x for x in rules if not (x.get('priority')==32765 and x.get('src')=='10.87.2.10' and str(x.get('table'))=='101' and x.get('protocol')=='static')]}
def secondary_routes(rows):
 for row in rows:
  if row.get('dev')=='ens6':
   assert row.get('protocol')in ['dhcp','kernel','static'] and row.get('dst')in ['default','10.87.0.2','10.87.2.0/24','10.87.2.1','10.87.2.10','10.87.2.255']
   assert row.get('gateway')in [None,'10.87.2.1'] and row.get('prefsrc')in [None,'10.87.2.10']
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');parser.add_argument('--pins',type=pathlib.Path);a=parser.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'instance':INSTANCE,'primary':PRIMARY,'secondary':SECONDARY,'namespace':NS,'nonce_service_code_sha256':hashlib.sha256(CODE.encode()).hexdigest(),'runtime_max_seconds':3600}));return
 assert os.getuid()==0 and a.pins;os.umask(0o077)
 st=a.pins.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and not a.pins.is_symlink();p=json.loads(a.pins.read_bytes())
 assert p['root_reviewed'] is True and p['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest() and p['instance_id']==INSTANCE and p['secondary_attachment_verified'] is True
 deadline=time.monotonic()+120
 def run(*args):
  remaining=deadline-time.monotonic();assert remaining>0
  r=subprocess.run(args,capture_output=True,text=True,timeout=min(10,remaining));assert r.returncode==0;assert len(r.stdout.encode())<=262144;return r.stdout
 def read(*args):return json.loads(run(*args))
 token=urllib.request.urlopen(urllib.request.Request('http://169.254.169.254/latest/api/token',method='PUT',headers={'X-aws-ec2-metadata-token-ttl-seconds':'60'}),timeout=3).read().decode()
 def meta(path):return urllib.request.urlopen(urllib.request.Request('http://169.254.169.254/latest/meta-data/'+path,headers={'X-aws-ec2-metadata-token':token}),timeout=3).read().decode()
 assert meta('instance-id')==INSTANCE
 for binding,eni,index in [(PRIMARY,'eni-093b8ee8e096251bc',0),(SECONDARY,'eni-0fe1dd9fe9cd7df16',1)]:
  prefix='network/interfaces/macs/'+binding[2]+'/'
  assert meta(prefix+'interface-id')==eni and meta(prefix+'device-number')==str(index)
 links=read('ip','-j','-d','link','show');addresses=read('ip','-j','addr','show');routes=read('ip','-j','-4','route','show','table','all');rules=read('ip','-j','rule','show')
 old_primary=exact_link(links,addresses,PRIMARY);exact_link(links,addresses,SECONDARY);secondary_routes(routes);old_management=management(routes,rules)
 assert not os.path.lexists(ROOT) and NS not in [x.split()[0]for x in run('ip','netns','list').splitlines()]
 for name in ['tnx-static-central-vgw-nonce','tnx-static-central-tgw-nonce']:
  assert run('systemctl','show',name+'.service','--property=LoadState','--value').strip()=='not-found'
 assert not any(':'+format(8080,'04X') in x.split()[1] and x.split()[3]=='0A' for x in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:])
 ROOT.mkdir(mode=0o700)
 def save(name,value):
  with(ROOT/name).open('x')as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
  fd=os.open(ROOT,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 save('before.json',{'primary':old_primary,'management':old_management,'links':links,'addresses':addresses,'routes':routes,'rules':rules})
 save('intent.json',{'source_sha256':p['source_sha256'],'namespace':NS,'secondary':SECONDARY,'no_replay':True})
 run('networkctl','down','ens6')
 # Only original exact secondary source rule may remain after networkd relinquishes it.
 after_rules=read('ip','-j','rule','show')
 for rule in after_rules:
  if rule.get('src')=='10.87.2.10':
   assert rule=={'priority':32765,'src':'10.87.2.10','table':'101','protocol':'static'}
   run('ip','rule','del','priority','32765','from','10.87.2.10','table','101','protocol','static')
 after_routes=read('ip','-j','-4','route','show','table','all');assert not [x for x in after_routes if x.get('dev')=='ens6' or str(x.get('table','main'))=='101']
 assert management(after_routes,read('ip','-j','rule','show'))==old_management
 run('ip','netns','add',NS);run('ip','link','set','ens6','netns',NS)
 def nsrun(*args):return run('ip','netns','exec',NS,*args)
 nsrun('ip','link','set','lo','up');nsrun('ip','link','set','ens6','up');nsrun('ip','addr','add','10.87.2.10/24','dev','ens6');nsrun('ip','route','add','default','via','10.87.2.1','dev','ens6')
 exact_link(json.loads(nsrun('ip','-j','-d','link','show')),json.loads(nsrun('ip','-j','addr','show')),SECONDARY)
 assert exact_link(read('ip','-j','-d','link','show'),read('ip','-j','addr','show'),PRIMARY)==old_primary
 assert management(read('ip','-j','-4','route','show','table','all'),read('ip','-j','rule','show'))==old_management
 code=ROOT/'nonce-server.py'
 with code.open('x')as f:f.write(CODE);f.flush();os.fsync(f.fileno())
 code.chmod(0o700)
 for name,ip,namespace in [('tnx-static-central-vgw-nonce','10.87.1.10',None),('tnx-static-central-tgw-nonce','10.87.2.10',NS)]:
  unit=pathlib.Path('/etc/systemd/system')/(name+'.service');assert not os.path.lexists(unit)
  text='[Unit]\nDescription=Owned bounded static VPN nonce fixture\n[Service]\nType=simple\nUser=root\nExecStart=/usr/bin/python3 '+str(code)+' '+ip+'\nRuntimeMaxSec=3600\nRestart=no\nNoNewPrivileges=yes\n'
  if namespace:text+='NetworkNamespacePath=/run/netns/'+namespace+'\n'
  with unit.open('x')as f:f.write(text);f.flush();os.fsync(f.fileno())
  unit.chmod(0o600)
 for directory in [ROOT,pathlib.Path('/etc/systemd/system')]:
  fd=os.open(directory,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 run('systemctl','daemon-reload')
 for name in ['tnx-static-central-vgw-nonce','tnx-static-central-tgw-nonce']:run('systemctl','start',name+'.service')
 proof=[]
 for name,ip,namespace in [('tnx-static-central-vgw-nonce','10.87.1.10',None),('tnx-static-central-tgw-nonce','10.87.2.10',NS)]:
  pid=int(run('systemctl','show',name+'.service','--property=MainPID','--value'));assert pid>1
  proc=pathlib.Path('/proc')/str(pid);cmd=(proc/'cmdline').read_bytes().split(b'\0');assert cmd[:3]==[b'/usr/bin/python3',str(code).encode(),ip.encode()]
  inode=os.readlink(proc/'ns/net');expected='net:['+str((pathlib.Path('/run/netns')/NS).stat().st_ino)+']' if namespace else os.readlink('/proc/1/ns/net');assert inode==expected
  nonce=os.urandom(32).hex();args=['curl','-fsS','--max-time','3','http://'+ip+':8080/nonce?nonce='+nonce]
  body=nsrun(*args)if namespace else run(*args);assert body==nonce+'\n'
  proof.append({'unit':name,'pid':pid,'startticks':(proc/'stat').read_text().rsplit(')',1)[1].split()[19],'namespace':inode,'code_sha256':hashlib.sha256(code.read_bytes()).hexdigest(),'control_nonce':nonce,'control_passed':True})
 save('result.json',{'services':proof,'primary_preserved':True,'management_preserved':True,'vpn_packets_proven':False,'runtime_max_seconds':3600})
 print('Owned namespace and bounded nonce controls ready; VPN data proof pending')
if __name__=='__main__':main()
