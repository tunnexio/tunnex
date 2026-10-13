#!/usr/bin/env python3
"""Local-only once-reserved disconnected native component harness. No cleanup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

IMAGE='sha256:00e84e696a0a007f99741b5cb953696ab11084238a5eb3c916bf11d62a40e688'
TEST='TestGuardFQDNV2ExpiryNativeReadback'

def private_file(path):
 if path.absolute()!=path.resolve():raise ValueError('symlink path')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or not 1<=s.st_size<=134217728:raise ValueError('private regular input')
  with os.fdopen(fd,'rb',closefd=False) as f:return f.read()
 finally:os.close(fd)

def parent(path):
 s=path.parent.lstat()
 if path.parent.absolute()!=path.parent.resolve() or not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('private parent')

def write_new(path,value):
 parent(path);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(directory)
 finally:os.close(directory)

def docker(args,data=None,timeout=15):
 r=subprocess.run(['docker',*args],input=data,capture_output=True,timeout=timeout)
 if r.returncode or len(r.stdout)+len(r.stderr)>1048576:raise ValueError('docker operation refused')
 return r.stdout

def component(cid,reservation):
 # Only the final test has evidence capture. No binary input or earlier Docker
 # command payload is recorded. Base64 preserves exact bounded output bytes.
 import base64
 args=['docker','exec','-e','TUNNEX_IPSEC_FQDN_EXPIRY_LAB=1',cid,'/tmp/expiry.test','-test.run','^'+TEST+'$','-test.v','-test.timeout','20s']
 timed_out=False;code=None
 try:
  result=subprocess.run(args,capture_output=True,timeout=25)
  out,err=result.stdout,result.stderr;code=result.returncode
 except subprocess.TimeoutExpired as failure:
  timed_out=True;out=failure.stdout or b'';err=failure.stderr or b''
 if not isinstance(out,bytes) or not isinstance(err,bytes) or len(out)+len(err)>1048576:raise ValueError('component evidence bounds')
 receipt=reservation.with_name(reservation.name+'.component.json')
 value={'version':1,'kind':'native_component_output','container_id':cid,'test':TEST,'outer_timeout_seconds':25,'test_timeout_seconds':20,'timed_out':timed_out,'returncode':code,'stdout_base64':base64.b64encode(out).decode(),'stderr_base64':base64.b64encode(err).decode(),'stdout_sha256':hashlib.sha256(out).hexdigest(),'stderr_sha256':hashlib.sha256(err).hexdigest()}
 write_new(receipt,value)
 digest=hashlib.sha256(private_file(receipt)).hexdigest()
 # Persisted original bytes/exit outcome precede every PASS/refusal decision.
 if timed_out or code!=0:raise ValueError('component failed; private evidence retained')
 text=out.decode('utf-8',errors='strict')
 if 'SKIP' in text or text.count('--- PASS: '+TEST+' ')!=1 or not text.rstrip().endswith('PASS'):raise ValueError('component result not exact PASS')
 return receipt,digest

def native_absence(cid):
 # Unfiltered plain listings in this disconnected container's namespace.
 # Do not turn an empty ip JSON response into a fabricated JSON array.
 # docker() requires command exit zero; absence requires exactly zero bytes.
 for kind in ('state','policy'):
  if docker(['exec',cid,'/sbin/ip','xfrm',kind,'list'])!=b'':raise ValueError('native objects or unexpected output present')

def run(binary,sha,reservation,execute=False):
 if not re.fullmatch('[0-9a-f]{64}',sha):raise ValueError('explicit reviewed binary digest')
 raw=private_file(binary)
 if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('binary digest')
 if len(raw)<64 or raw[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(raw[18:20],'little')!=183:raise ValueError('reviewed Linux ARM64 ELF required')
 parent(reservation)
 if reservation.exists() or reservation.is_symlink():raise ValueError('existing reservation; inspect only, never replay')
 # Preflight is entirely local filesystem validation; no Docker command.
 if not execute:return {'version':1,'stage':'source_preflight_only','image':IMAGE,'binary_sha256':sha,'test':TEST}
 name='azure-fqdn-expiry-'+uuid.uuid4().hex
 write_new(reservation,{'version':1,'stage':'reserved_before_create','name':name,'image':IMAGE,'binary_sha256':sha,'test':TEST,'scope':'disconnected timed-set component; no SAs, CP or packet proof'})
 # No --rm, restart policy, network, host paths, volume, credentials, pull or
 # privileged/SYS_ADMIN authority. Failed/unknown containers are preserved.
 cid=docker(['create','--pull=never','--name',name,'--label','tunnex.qualification=azure-fqdn-expiry','--network','none','--read-only','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=128m','--memory','256m','--pids-limit','64','--entrypoint','/bin/sh',IMAGE,'-c','sleep 300']).decode().strip()
 if not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('unknown create result; inspect reserved name')
 write_new(reservation.with_name(reservation.name+'.created.json'),{'version':1,'stage':'created_identity_only','container_id':cid,'name':name,'image':IMAGE,'binary_sha256':sha})
 info=json.loads(docker(['inspect',cid]))
 if len(info)!=1:raise ValueError('inspect shape')
 value=info[0];host=value['HostConfig']
 if value['Id']!=cid or value['Image']!=IMAGE or value['Name']!='/'+name or host['NetworkMode']!='none' or host['Privileged'] or not host['ReadonlyRootfs'] or host['CapAdd']!=['CAP_NET_ADMIN'] or host['CapDrop']!=['ALL'] or value.get('Mounts') or host.get('Binds') or host.get('RestartPolicy',{}).get('Name') not in ('no','') or host.get('Memory')!=256*1024*1024 or host.get('PidsLimit')!=64 or host.get('Tmpfs')!={'/tmp':'rw,nosuid,nodev,exec,size=128m'} or host.get('SecurityOpt')!=['no-new-privileges'] or value.get('Config',{}).get('Entrypoint')!=['/bin/sh'] or value.get('Config',{}).get('Cmd')!=['-c','sleep 300'] or value.get('Config',{}).get('Labels',{}).get('tunnex.qualification')!='azure-fqdn-expiry':raise ValueError('disconnected isolation refused')
 docker(['start',cid])
 docker(['exec','-i',cid,'/bin/sh','-c','umask 077; cat > /tmp/expiry.test; chmod 700 /tmp/expiry.test'],raw)
 actual=docker(['exec',cid,'sha256sum','/tmp/expiry.test']).decode().split()
 if len(actual)!=2 or actual!=[sha,'/tmp/expiry.test']:raise ValueError('copied binary digest')
 # Empty native SA/SPD namespace, then exactly two disposable XFRM links.
 # Only fixed JSON is interpreted; no native raw inventory is exported.
 native_absence(cid)
 for number in (1,2):docker(['exec',cid,'/sbin/ip','link','add','txexpiry'+str(number),'type','xfrm','if_id',str(1000+number)])
 component_receipt,component_digest=component(cid,reservation)
 receipt=reservation.with_name(reservation.name+'.result.json')
 write_new(receipt,{'version':1,'stage':'component_pass','name':name,'container_id':cid,'image':IMAGE,'binary_sha256':sha,'test':TEST,'scope':'timed nft member/readback only; no encrypted transport, CP, rekey, shared lifecycle or production acceptance'})
 return {'version':1,'stage':'component_pass','container_id':cid,'private_receipt':receipt.name,'component_receipt':component_receipt.name,'component_receipt_sha256':component_digest}

def main():
 if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):raise ValueError('optimized execution refused')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--binary-sha256',required=True);p.add_argument('--reservation',type=Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
 print(json.dumps(run(a.binary,a.binary_sha256,a.reservation,a.execute),sort_keys=True))

if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):raise SystemExit('Native component refused; preserve reservation/container and inspect only. No replay or automatic cleanup.')
