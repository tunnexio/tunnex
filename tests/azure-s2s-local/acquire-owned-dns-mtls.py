#!/usr/bin/env python3
"""Capture normal owned mTLS DNS desired/material inputs privately; no bodies printed."""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
spec=importlib.util.spec_from_file_location('gated',Path(__file__).with_name('assemble-gated-restoration.py'))
gated=importlib.util.module_from_spec(spec);spec.loader.exec_module(gated)
CONNECTION='9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99'
def private_write(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state-dir',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
 a=p.parse_args();stage='owned_private_inputs'
 try:
  if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer':raise ValueError('owned root host')
  gated.private_directory(a.output_dir)
  credentials={name:gated.private_bytes(a.state_dir/name,65536) for name in ('cert.pem','key.pem','ca.pem')}
  context=ssl.create_default_context(cafile=str(a.state_dir/'ca.pem'));context.load_cert_chain(str(a.state_dir/'cert.pem'),str(a.state_dir/'key.pem'))
  class OwnedHTTPS(http.client.HTTPSConnection):
   def connect(self):self.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',48446),timeout=10),server_hostname='tunnex-control')
  for method,path,body,name in [('GET','/agent/desired',None,'desired.json'),('POST','/agent/ipsec/connections/'+CONNECTION+'/material',json.dumps({'desired_revision':6}),'material.json')]:
   stage='normal_mtls_'+name.split('.')[0]
   c=OwnedHTTPS('tunnex-control',timeout=10)
   try:
    c.request(method,path,body=body,headers={'Content-Type':'application/json'});response=c.getresponse();raw=response.read((2<<20)+1)
    if response.status!=200 or len(raw)>2<<20:raise ValueError('normal mTLS refused')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('normal object response required')
    if name=='material.json' and (value.get('desired_revision')!=6 or value.get('manifest',{}).get('connection_id')!=CONNECTION):raise ValueError('exact current connection delivery required')
    private_write(a.output_dir/name,raw)
   finally:c.close()
  if any(gated.private_bytes(a.state_dir/name,65536)!=raw for name,raw in credentials.items()):raise ValueError('credentials changed')
  print(json.dumps({'stage':'normal_mtls_dns_inputs_saved','http_status':200,'private_saved':True,'no_body_printed':True,'observed_at':gated.stamp()}));return 0
 except (OSError,ValueError,KeyError,TypeError,http.client.HTTPException):
  print(json.dumps({'stage':stage,'error_code':'normal_mtls_dns_capture_refused','observed_at':gated.stamp()}));return 1
if __name__=='__main__':raise SystemExit(main())
