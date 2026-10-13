#!/usr/bin/env python3
"""SOURCE-ONLY default. Additive bounded synthetic TCP MTU fixture, never authority.
Root must separately approve service, exact SG, normal CP resource/grants and cleanup.
"""
import argparse,hashlib,http.server,json,pathlib,secrets,sys,time,urllib.request,os,signal
LIMIT=4*1024*1024
class Handler(http.server.BaseHTTPRequestHandler):
 def setup(self):
  super().setup();self.connection.settimeout(15)
 def log_message(self,fmt,*args):
  print(json.dumps({'at':time.time(),'client':self.client_address[0],'request':fmt%args}),flush=True)
 def do_GET(self):
  if self.client_address[0] not in [self.server.expected_client,self.server.server_address[0]] or self.path!=self.server.fixture_path:self.send_error(404);return
  body=self.server.payload;self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('X-Fixture-SHA256',hashlib.sha256(body).hexdigest());self.end_headers();self.wfile.write(body)
 def do_POST(self):
  if self.client_address[0] not in [self.server.expected_client,self.server.server_address[0]] or self.path!=self.server.fixture_path:self.send_error(404);return
  try:n=int(self.headers.get('Content-Length','0'))
  except ValueError:self.send_error(400);return
  if n!=LIMIT:self.send_error(413);return
  self.connection.settimeout(15);body=self.rfile.read(n)
  if len(body)!=n:self.send_error(400);return
  response=json.dumps({'nonce':self.server.nonce,'received_bytes':n,'sha256':hashlib.sha256(body).hexdigest()},sort_keys=True).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(response)));self.end_headers();self.wfile.write(response)
def main():
 p=argparse.ArgumentParser();p.add_argument('role',choices=['target','client']);p.add_argument('--execute',action='store_true');p.add_argument('--target',choices=['10.85.1.10','10.86.1.10'],required=True);p.add_argument('--nonce',required=True);p.add_argument('--source',choices=['10.84.2.10','10.84.3.10'],required=True);p.add_argument('--receipt',type=pathlib.Path);a=p.parse_args()
 assert len(a.nonce)==64 and all(c in '0123456789abcdef'for c in a.nonce)
 if not a.execute:print(json.dumps({'source_only':True,'role':a.role,'target':a.target,'port':8081,'bytes_each_direction':LIMIT,'requires_normal_TCP8081_grant':True,'df_probe_executed':False}));return
 def hard_timeout(signum,frame):
  print(json.dumps({'fixture_wall_timeout':True,'role':a.role}),flush=True);raise TimeoutError('owned fixture hard wall deadline')
 signal.signal(signal.SIGALRM,hard_timeout);signal.alarm(180 if a.role=='target' else 90)
 path='/owned-mtu-'+a.nonce
 if a.role=='target':
  # Deterministic synthetic bytes bind response to this run, without filesystem writes.
  payload=hashlib.sha256(a.nonce.encode()).digest()*(LIMIT//32)
  server=http.server.HTTPServer((a.target,8081),Handler);server.fixture_path=path;server.payload=payload;server.nonce=a.nonce;server.expected_client=a.source;server.timeout=1
  print(json.dumps({'target_ready':True,'pid':os.getpid(),'port':8081,'nonce':a.nonce,'payload_sha256':hashlib.sha256(payload).hexdigest()}),flush=True)
  deadline=time.monotonic()+180
  try:
   while time.monotonic()<deadline:server.handle_request()
  finally:server.server_close();signal.alarm(0)
 else:
  assert a.receipt and not a.receipt.exists();os.umask(0o077)
  upload=secrets.token_bytes(LIMIT);url='http://'+a.target+':8081'+path;opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));begin=time.monotonic()
  with opener.open(urllib.request.Request(url,data=upload,method='POST'),timeout=30)as response:
   assert response.status==200;ack=json.loads(response.read(4096))
  assert ack=={'nonce':a.nonce,'received_bytes':LIMIT,'sha256':hashlib.sha256(upload).hexdigest()}
  uploaded=time.monotonic()
  with opener.open(url,timeout=30)as response:
   assert response.status==200;body=response.read(LIMIT+1);expected=hashlib.sha256(a.nonce.encode()).digest()*(LIMIT//32);assert body==expected and response.headers['X-Fixture-SHA256']==hashlib.sha256(body).hexdigest()
  result={'nonce':a.nonce,'target':a.target,'upload_bytes':LIMIT,'download_bytes':len(body),'upload_sha256':ack['sha256'],'download_sha256':hashlib.sha256(body).hexdigest(),'upload_seconds':uploaded-begin,'download_seconds':time.monotonic()-uploaded,'passed':True,'encrypted_transport_independently_required':True,'existing_connection_failover_tested':False}
  with a.receipt.open('x')as f:json.dump(result,f);f.flush();os.fsync(f.fileno())
  fd=os.open(a.receipt.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);signal.alarm(0);print(json.dumps({'passed':True,'receipt':str(a.receipt)}))
if __name__=='__main__':main()
