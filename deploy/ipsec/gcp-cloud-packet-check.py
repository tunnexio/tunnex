#!/usr/bin/env python3
"""Explicit fixed-scope probes; preparation alone performs no SSH or network IO."""
import argparse
import base64
import hashlib
import json
import os
import select
import shlex
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

BASTION='cyberking9560@34.131.23.179'
ROOT='/home/cyberking9560/tn-gcps2s-20261010/hostkey-recovery-b7db7300/'
CLIENT=('34.131.121.30','4751969643435150303','known-hosts-client-2ec2c191-000b-4854-8203-dd4bae0f21b7','10.70.0.10')
TARGETS={
 'ha':('34.131.187.41','7595462031766211538','known-hosts-ha-target-7abbcd80-5479-4196-8079-ce77f7f6e877','10.80.0.10'),
 'classic':('34.131.232.234','139156170322758560','known-hosts-classic-target-056d8338-6b3c-481e-947e-a3fd4bcb9227','10.81.0.10')}
MARKER=b'tunnex-gcp-private-application\n'
FINGERPRINTS={'4751969643435150303':'SHA256:jrN9/q8kVJ++R+kqFmeF8nQ6abU/2UKvYHkOZPxb2Dg','7595462031766211538':'SHA256:uYWViNuq8IF0ya9IK4lZxT3jzcGpiYWT9AQ9ovhKvPg','139156170322758560':'SHA256:8nzbIMCg9c5obv0XPpXWhQtqmNBPO9l51BnQZyooNCs'}

def sha(data):return hashlib.sha256(data).hexdigest()
def unique(pairs):
 out={}
 for k,v in pairs:
  if k in out:raise ValueError('duplicate field')
  out[k]=v
 return out

def probe(address, source, protocol, nonce):
 payload=('tnx-gcp-packet-'+nonce).encode('ascii')
 started=time.monotonic();result={'protocol':protocol,'destination':address,'source':source,'nonce':nonce,'payload_sha256':sha(payload)}
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM) as s:
  s.settimeout(3);s.bind((source,0))
  try:
   if protocol=='udp':
    s.sendto(payload,(address,9000));response,peer=s.recvfrom(2048)
    result['exact_response']=response==payload and peer==(address,9000)
   else:
    s.connect((address,8080));request=('GET /tnx-probe/'+nonce+' HTTP/1.0\r\nHost: owned-gcp-lab\r\nConnection: close\r\n\r\n').encode('ascii');s.sendall(request)
    result['request_sha256']=sha(request);response=b''
    while True:
     part=s.recv(1024)
     if not part:break
     response+=part
     if len(response)>4096:raise ValueError('response limit')
    head,body=response.split(b'\r\n\r\n',1)
    result['exact_response']=head.split(b'\r\n',1)[0].split()[1]==b'200' and body==MARKER
   result.update(outcome='response',response_sha256=sha(response))
  except (TimeoutError,ConnectionRefusedError,OSError) as e:
   result.update(outcome='timeout' if isinstance(e,TimeoutError) else 'socket_refusal',error_type=type(e).__name__,exact_response=False)
 result['elapsed_ms']=round((time.monotonic()-started)*1000,3)
 return result

def frame_match(frame, target, protocol, nonce):
 # Fixed Ethernet/IPv4 observer; fragmentation, VLANs, short frames refuse
 # matching instead of inventing receiver evidence.
 if len(frame)>=14 and frame[12:14] in [b'\x81\x00',b'\x88\xa8']:return 'unsupported'
 if len(frame)<34 or frame[12:14]!=b'\x08\x00':return None
 ip=frame[14:];hlen=(ip[0]&15)*4
 if ip[0]>>4!=4 or hlen<20 or len(ip)<hlen+8 :return None
 if socket.inet_ntoa(ip[12:16])!='10.70.0.10' or socket.inet_ntoa(ip[16:20])!=target:return None
 if struct.unpack('!H',ip[6:8])[0]&0x3fff:return 'unsupported'
 data=ip[hlen:];port=9000 if protocol=='udp' else 8080
 if struct.unpack('!H',data[2:4])[0]!=port:return None
 if protocol=='udp' and ip[9]==17:
  length=struct.unpack('!H',data[4:6])[0]
  return 'exact_payload' if data[8:length]==('tnx-gcp-packet-'+nonce).encode() else 'other_tuple'
 if protocol=='tcp' and ip[9]==6 and len(data)>=20:
  offset=(data[12]>>4)*4
  if offset<20 or offset>len(data):return None
  if ('GET /tnx-probe/'+nonce+' ').encode() in data[offset:]:return 'exact_payload'
  return 'syn' if data[13]&2 else 'other_tuple'
 return None

def observe(target,protocol,nonce):
 # Local self-control is independent of tunnel/client policy and proves the
 # retained startup listeners still serve the known contracts.
 control=probe(target,target,protocol,str(uuid.uuid4()))
 if not control['exact_response']:raise ValueError('target self-control failed')
 addrs=json.loads(subprocess.check_output(['ip','-j','-4','addr','show'],timeout=5),object_pairs_hook=unique)
 names=[i['ifname'] for i in addrs if any(a.get('local')==target for a in i.get('addr_info',[]))]
 if len(names)!=1:raise ValueError('exact assigned target interface absent')
 counts={'exact_payload':0,'syn':0,'other_tuple':0,'unsupported':0}
 with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)) as s:
  s.bind((names[0],0));s.setblocking(False)
  print(json.dumps({'ready':True,'target':target,'interface':names[0],'control':control}),flush=True)
  stopped=False
  deadline=time.monotonic()+20
  while time.monotonic()<deadline:
   ready,_,_=select.select([s,sys.stdin],[],[],max(0,deadline-time.monotonic()))
   if sys.stdin in ready:
    if sys.stdin.readline()!='STOP\n':raise ValueError('observer control refused')
    while True:
     try:kind=frame_match(s.recv(65535),target,protocol,nonce)
     except BlockingIOError:break
     if kind:counts[kind]+=1
    stopped=True
    break
   if s in ready:
    kind=frame_match(s.recv(65535),target,protocol,nonce)
    if kind:counts[kind]+=1
  stats=s.getsockopt(263,6,8);packets,drops=struct.unpack('II',stats)
 print(json.dumps({'stopped_by_request':stopped,'counts':counts,'capture_packets':packets,'capture_drops':drops,'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip(),'scope':'bounded raw receiver observation; no policy authority'}),flush=True)

def ssh(role,code):
 public,instance,pin,_=role
 return ['ssh','-i','/home/cyberking9560/.ssh/google_compute_engine','-o','UserKnownHostsFile='+ROOT+pin,'-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlias=compute.'+instance,'-o','StrictHostKeyChecking=yes','-o','CheckHostIP=no','-o','BatchMode=yes','-o','ConnectTimeout=10','cyberking9560@'+public,code]

def line(proc,timeout):
 if not select.select([proc.stdout],[],[],timeout)[0]:raise ValueError('bounded observer response absent')
 raw=proc.stdout.readline(32769)
 if len(raw)>32768 or not raw.endswith('\n'):raise ValueError('bounded observer framing refused')
 return json.loads(raw,object_pairs_hook=unique)

def verify_pin(role):
 _,instance,pin,_=role
 fd=os.open(ROOT+pin,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>4096:raise ValueError('owned exclusive pin refused')
  data=os.read(fd,4097).decode('ascii').strip().split()
 finally:os.close(fd)
 if len(data)!=3 or data[0]!='compute.'+instance or data[1]!='ssh-ed25519':raise ValueError('exact pinned alias refused')
 wire=base64.b64decode(data[2],validate=True)
 fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip('=')
 if fingerprint!=FINGERPRINTS[instance]:raise ValueError('authenticated fingerprint drift')

def remote(profile,expected,source):
 target=TARGETS[profile];results=[]
 verify_pin(CLIENT);verify_pin(target)
 for protocol in ['tcp','udp']:
  nonce=str(uuid.uuid4())
  command='sudo python3 -c '+shlex.quote(source+'\nobserve('+repr(target[3])+','+repr(protocol)+','+repr(nonce)+')')
  observer=subprocess.Popen(ssh(target,command),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
  try:
   ready=line(observer,15)
   if ready.get('ready') is not True or ready.get('target')!=target[3]:raise ValueError('observer readiness refused')
   command='python3 -c '+shlex.quote(source+'\nprint(json.dumps(probe('+repr(target[3])+','+repr(CLIENT[3])+','+repr(protocol)+','+repr(nonce)+')))')
   p=subprocess.run(ssh(CLIENT,command),capture_output=True,text=True,timeout=15,check=True)
   if len(p.stdout)>32768:raise ValueError('probe response limit')
   result=json.loads(p.stdout,object_pairs_hook=unique)
   observer.stdin.write('STOP\n');observer.stdin.flush();received=line(observer,5)
   observer.wait(timeout=5)
   if observer.returncode!=0:raise ValueError('observer exit refused')
   exact=received['counts']['exact_payload']
   if expected=='allow':accepted=result['exact_response'] and exact>=1
   else:accepted=result['outcome'] in ['timeout','socket_refusal'] and not result['exact_response'] and sum(received['counts'].values())==0
   accepted=bool(accepted and received['capture_drops']==0 and received['counts']['unsupported']==0 and received['stopped_by_request'])
   results.append({'probe':result,'receiver_ready':ready,'receiver':received,'accepted':accepted,'expectation':expected,'scope':'packet observation only; native guard/SA/route and API grant evidence are separate'})
  finally:
   if observer.poll() is None:observer.terminate();observer.wait(timeout=5)
 return results

def main():
 p=argparse.ArgumentParser();p.add_argument('--profile',choices=TARGETS,required=True);p.add_argument('--expect',choices=['allow','deny'],required=True);p.add_argument('--evidence',required=True);a=p.parse_args()
 source=open(__file__).read().split('\nif __name__')[0]
 parent=os.path.dirname(os.path.abspath(a.evidence));s=os.lstat(parent)
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('owned0700 evidence directory required')
 fd=os.open(a.evidence,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  # This source is delivered only to the designated bastion. No gcloud or local
  # private-host route is used and no pin/auth key is created or changed.
  code=source+'\nprint(json.dumps(remote('+repr(a.profile)+','+repr(a.expect)+','+repr(source)+')))'
  run=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',BASTION,'python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=75)
  if run.returncode or len(run.stdout)>128*1024:raise ValueError('bounded bastion runner refused')
  result=json.loads(run.stdout,object_pairs_hook=unique)
  receipt={'profile':a.profile,'expected':a.expect,'source_sha256':sha(source.encode()),'results':result,'accepted':len(result)==2 and all(x['accepted'] for x in result),'executed_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
  with os.fdopen(fd,'w') as f:fd=-1;json.dump(receipt,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 finally:
  if fd>=0:os.close(fd)

if __name__=='__main__':
 try:main()
 except Exception as e:print('GCP scoped packet check refused: '+type(e).__name__,file=sys.stderr);sys.exit(1)
