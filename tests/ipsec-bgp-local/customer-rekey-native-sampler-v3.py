"""Source-only root-on-owned-GW metadata sampler; no initiation or packet generation."""
import argparse,hashlib,json,os,pathlib,re,stat,subprocess,time
NODE='296065d03c4e1f6b69f27708ab9a33d09f77004817bb5f57c10d622c3f30e75c'
def private(p):
 s=p.lstat();assert os.getuid()==0 and s.st_uid==0 and stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600 and not p.is_symlink();return p.read_bytes()
def main():
 p=argparse.ArgumentParser();p.add_argument('--pins',type=pathlib.Path,required=True);p.add_argument('--pins-sha',required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:print('{"source_only":true}');return
 os.umask(0o077);raw=private(a.pins);assert hashlib.sha256(raw).hexdigest()==a.pins_sha;q=json.loads(raw)
 assert q['node_sha256']==NODE and q['root_reviewed'] is True and q['restoration_complete'] is True
 assert q['container']=='35a889a1a6b7e521084715f51a2fb6f8537b581647f8c7ebfa9b61e258df6605' and q['namespace']=='net:[4026532946]' and str(q['pid1_startticks'])=='9961117'
 assert q['source_sha256']=='4674c202643ef54f7239bd1c54af7fd78248b446e743da61b3ef229efc91ec1e' and q['build_receipt_sha256']=='6ac029070ad8ccf9174b9744c7291c1834798a5bebadb114b90c444cc30ab6e6'
 cid=q['container'];assert re.fullmatch('[0-9a-f]{64}',cid) and re.fullmatch(r'net:\[[1-9][0-9]*\]',q['namespace'])
 a.output.mkdir(mode=0o700,exist_ok=False);deadline=time.monotonic()+100
 def run(args):
  left=deadline-time.monotonic();assert left>0
  t=time.time_ns();x=subprocess.run(['docker','exec',cid,*args],capture_output=True,text=True,timeout=min(2,left));assert x.returncode==0 and len(x.stdout.encode())<=262144
  return {'start_ns':t,'end_ns':time.time_ns(),'stdout':x.stdout}
 def identity():
  x=subprocess.run(['docker','inspect','--format','{{.Id}} {{.Image}} {{.State.Pid}} {{.State.StartedAt}}',cid],capture_output=True,text=True,timeout=2);assert x.returncode==0 and x.stdout.split()==[cid,'sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2','3115397','2026-10-08T14:46:54.478240323Z']
  assert run(['readlink','/proc/1/ns/net'])['stdout'].strip()==q['namespace']
  h=run(['sha256sum','/proc/1/exe','/state/cert.pem'])['stdout'].splitlines();assert [x.split()[0]for x in h]==[NODE,q['certificate_sha256']]
  ticks=run(['cat','/proc/1/stat'])['stdout'].rsplit(')',1)[1].split()[19];assert ticks==str(q['pid1_startticks'])
 def save(name,value):
  with(a.output/name).open('x')as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
 identity();started_ns=time.time_ns();save('sampler-started.json',{'pins_sha256':a.pins_sha,'container':cid,'namespace':q['namespace'],'pid1_startticks':str(q['pid1_startticks']),'started_ns':started_ns});start=time.monotonic();i=0
 while time.monotonic()-start<90:
  due=start+i*.2
  if due>time.monotonic():time.sleep(due-time.monotonic())
  identity()
  data={'binding':{'pins_sha256':a.pins_sha,'container':cid,'namespace':q['namespace'],'pid1_startticks':str(q['pid1_startticks']),'sampler_started_ns':started_ns},'vici':run(['env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--raw','--uri','unix:///run/tunnex-ipsec/charon.vici'])}
  # Key-free native kernel proof every tenth sample; overlap cadence is actual timestamped, never assumed.
  if i%10==0:
   data['xfrm']=run(['ip','-s','xfrm','state','list','nokeys']);data['nft']=run(['nft','-j','list','table','inet','tunnex_ipsec']);data['routes']=run(['ip','-j','-4','route','show','table','all'])
  save('sample-%04d.json'%i,data);i+=1
 identity();save('complete.json',{'samples':i,'actual_seconds':time.monotonic()-start,'initiation_performed':False,'acceptance':'pending exact overlap/ownership reconciliation'})
 fd=os.open(a.output,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
if __name__=='__main__':main()
