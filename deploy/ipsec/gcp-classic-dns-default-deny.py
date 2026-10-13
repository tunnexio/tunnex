#!/usr/bin/env python3
"""One bounded ordinary DNS negative observation; no permissions changed."""
import argparse,errno,hashlib,json,os,pathlib,secrets,socket,stat,struct,subprocess,time
CID='5f77c5857fa78b0533eb4fddc46cc4a0e9c69369d8e7987ee068b88ec7ba8c2f'
IMAGE='sha256:347bcb66318aa1b8ef1e949c6f57e28506e56a1497f2f4ae15b9ab74b8fed4c6'
CONNECTION='b79d7eda-fafe-41cf-af2c-4115d4ef32c6';SOURCE='10.70.0.2';RESOLVER='10.81.0.2';NAME='app.classic.gcp.s2s-qa.tunnex.app.'
BOOT='9617762e-19db-4a21-bdee-909dfb31e501'
NFT_SHA='7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f'
def run(*args):
 r=subprocess.run(args,capture_output=True,timeout=10,check=True)
 if len(r.stdout)>2*1024*1024:raise ValueError('bounded capture')
 return r.stdout.decode().strip()
def ex(*args):return run('docker','exec',CID,*args)
def snapshot():
 i=json.loads(run('docker','inspect',CID))[0]
 if i['Id']!=CID or i['Image']!=IMAGE or not i['State']['Running']:raise ValueError('exact owned deployed gateway')
 if run('cat','/proc/sys/kernel/random/boot_id')!=BOOT:raise ValueError('exact deployed boot')
 ns=run('readlink','/proc/self/ns/net')
 if ns!=ex('readlink','/proc/self/ns/net')or ns!='net:[4026531840]':raise ValueError('exact host gateway namespace')
 if ex('sha256sum','/usr/sbin/nft').split()[0]!=NFT_SHA:raise ValueError('qualified nft')
 a=json.loads(ex('/sbin/ip','-j','-4','addr','show'))
 if not any(x.get('local')==SOURCE for link in a for x in link.get('addr_info',[])):raise ValueError('assigned source')
 p=pathlib.Path('/var/lib/tunnex-gcp-s2s-cloud-20261010/ipsec/journal.json')
 if p.stat().st_size>16*1024*1024:raise ValueError('bounded journal')
 payload=json.loads(p.read_text())['Payload'];entries=[e for e in payload['Entries']if e['Allocation']['ConnectionID']==CONNECTION]
 if len(entries)!=1 or len(payload['Guards'])!=1:raise ValueError('exact Classic/guard')
 e=entries[0];allocation=e['Allocation'];active=allocation['Tunnels'][0]
 if e['ContractVersion']!=4 or e['Phase']!='applied' or allocation['Namespace']!=ns or active['Slot']!=1 or not active['Selected']:raise ValueError('applied single active Classic')
 route=json.loads(ex('/sbin/ip','-j','-4','route','get',RESOLVER))
 if len(route)!=1 or route[0].get('dev')!=active['Name']:raise ValueError('exact CloudDNS route')
 inactive=allocation['Tunnels'][1]
 if any(inactive.get(k)not in [None,'',0,False,'00000000-0000-0000-0000-000000000000']for k in ['TunnelID','Slot','Name','Alias','XFRMID','InsideAddress','Selected'])or inactive.get('RemotePrefixes'):raise ValueError('inactive zero slot')
 g=payload['Guards'][0]
 if g['Namespace']!=ns:raise ValueError('guard namespace')
 return {'container_id':CID,'image_id':IMAGE,'namespace':ns,'boot_id':run('cat','/proc/sys/kernel/random/boot_id'),'pid':i['State']['Pid'],'started_at':i['State']['StartedAt'],'delivery_id':e['DeliveryID'],'source':SOURCE,'resolver':RESOLVER,'route':route,'guard':{k:g[k]for k in ['ExpectedJSON','Digest','Revision','Namespace']},'actual_guard':json.loads(ex('/usr/sbin/nft','-j','list','table','inet','tunnex_ipsec')),'links':json.loads(ex('/sbin/ip','-j','-d','link','show')),'scope':'read-only exact guard projection; never full journal/material or raw XFRM state'}
def probe(protocol):
 id=secrets.randbelow(65536);q=b''.join(bytes([len(label)])+label.encode('ascii')for label in NAME.rstrip('.').split('.'))+b'\0'+struct.pack('!HH',1,1);wire=struct.pack('!6H',id,0x100,1,0,0,0)+q;start=time.monotonic();deadline=start+4
 r={'protocol':protocol,'source':SOURCE,'resolver':RESOLVER,'port':53,'name':NAME,'id':id,'no_edns':True,'accepted_negative':False}
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if protocol=='udp'else socket.SOCK_STREAM)as s:
  stage='bind'
  try:
   s.bind((SOURCE,0));s.settimeout(4)
   if protocol=='udp':
    stage='send';s.sendto(wire,(RESOLVER,53));stage='recv';data,peer=s.recvfrom(65535);r['response_source_matches']=peer==(RESOLVER,53)
   else:
    stage='connect';s.connect((RESOLVER,53));remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('total deadline')
    stage='write';s.settimeout(remaining);s.sendall(struct.pack('!H',len(wire))+wire);remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('total deadline')
    stage='read';s.settimeout(remaining);data=s.recv(65535)
   r.update(outcome='response_or_eof',response_length=len(data),response_sha256=hashlib.sha256(data).hexdigest())
  except (TimeoutError,ConnectionRefusedError)as e:r.update(outcome='timeout_or_refusal',error_type=type(e).__name__,errno=e.errno,stage=stage,accepted_negative=stage!='bind')
  except PermissionError as e:
   if e.errno not in (errno.EPERM,errno.EACCES):raise
   r.update(outcome='administrative_refusal',error_type=type(e).__name__,errno=e.errno,stage=stage,accepted_negative=False)
  r.setdefault('stage',stage)
 r['elapsed_ms']=round((time.monotonic()-start)*1000,3);return r
def main():
 p=argparse.ArgumentParser();p.add_argument('--receipt',required=True);a=p.parse_args();s=os.lstat(pathlib.Path(a.receipt).parent)
 if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.getuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('private receipt parent')
 fd=os.open(a.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);r={'started':True,'completed':False,'results':[],'scope':'Socket negative only. Native full guard/permanent refusal and CloudDNS health must be independently reviewed; timeouts alone do not establish gateway deny.'}
 try:
  r['before']=snapshot()
  for protocol in ['udp','tcp']:
   r['results'].append(probe(protocol))
   # Flush after each probe so later observation failure preserves actual outcomes.
   os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0);os.write(fd,json.dumps(r).encode());os.fsync(fd)
  try:r['after']=snapshot()
  except Exception as e:r['after_error_type']=type(e).__name__
  r.update(completed=True,socket_negatives=all(x['accepted_negative']for x in r['results']))
 except Exception as e:r.update(error_type=type(e).__name__);raise
 finally:
  os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0)
  with os.fdopen(fd,'w')as f:json.dump(r,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'completed':r['completed'],'socket_negatives':r['socket_negatives'],'native_deny_independently_verified':False}))
if __name__=='__main__':
 try:main()
 except Exception as e:raise SystemExit('Owned DNS negative observation refused: '+type(e).__name__)
