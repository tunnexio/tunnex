#!/usr/bin/env python3
"""Finite target-local TCP DNS control. No listeners, grants or metadata changes."""
import argparse,hashlib,types,json,os,pathlib,socket,stat,struct,subprocess,time
_path=pathlib.Path(__file__).with_name('gcp-cloud-dns-wire-probe.py');_bytes=_path.read_bytes()
if hashlib.sha256(_bytes).hexdigest()!='b260ea4e8985926022411a2015e495c3fedbfc56238544af9e8528fef39740ba':raise ValueError('reviewed wire dependency')
wire=types.ModuleType('wire');wire.__file__=str(_path);exec(compile(_bytes,str(_path),'exec'),wire.__dict__)
BOOT='638afa49-665d-4778-b6af-362a5bbd1a7e';SOURCE='10.81.0.10';RESOLVER='10.81.0.2'
def query(sock,record):
 name='app.classic.gcp.s2s-qa.tunnex.app.';ident=int.from_bytes(os.urandom(2),'big');q=struct.pack('!6H',ident,0x100,1,0,0,0)+wire.question(name);deadline=time.monotonic()+4;stage='tcp_bind'
 def remain():
  t=deadline-time.monotonic()
  if t<=0:raise TimeoutError('total deadline')
  sock.settimeout(t)
 try:
  sock.bind((SOURCE,0));stage='tcp_connect';record({'stage':stage,'source_port':sock.getsockname()[1],'id':ident});remain();sock.connect((RESOLVER,53));stage='tcp_write';record({'stage':stage});remain();sock.sendall(struct.pack('!H',len(q))+q)
  def exact(n):
   b=b''
   while len(b)<n:
    remain();part=sock.recv(n-len(b))
    if not part:raise ValueError('short frame')
    b+=part
   return b
  stage='tcp_read_length';record({'stage':stage});n=struct.unpack('!H',exact(2))[0]
  if n<12:raise ValueError('bounded frame')
  stage='tcp_read_body';record({'stage':stage});r=wire.response(exact(n),ident,name,True);return {'accepted':wire.validate_answers(r,'classic','app'),'full':r}
 except Exception as e:record({'stage':stage,'failed':True,'error_type':type(e).__name__,'errno':getattr(e,'errno',None)});raise

def main():
 p=argparse.ArgumentParser();p.add_argument('--receipt',required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:raise ValueError('explicit reviewed execution')
 directory=os.lstat(pathlib.Path(a.receipt).parent)
 if not stat.S_ISDIR(directory.st_mode)or directory.st_uid!=os.getuid()or stat.S_IMODE(directory.st_mode)!=0o700:raise ValueError('private owned receipt parent')
 fd=os.open(a.receipt,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);r={'started':True,'completed':False,'source':SOURCE,'resolver':RESOLVER,'stages':[],'scope':'direct same-VPC target control only; not VPN or gateway DNS proof'}
 def save():
  data=json.dumps(r).encode();os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0)
  while data:
   n=os.write(fd,data)
   if n<=0:raise OSError('receipt write refused')
   data=data[n:]
  os.fsync(fd)
 def record(v):r['stages'].append(v);save()
 try:
  if pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=BOOT:raise ValueError('exact trusted target boot')
  process=subprocess.run(['/sbin/ip','-j','-4','addr','show','dev','ens4'],capture_output=True,check=True,timeout=5)
  if len(process.stdout)>32768:raise ValueError('bounded target addresses')
  if not any(x.get('local')==SOURCE for l in json.loads(process.stdout)for x in l.get('addr_info',[])):raise ValueError('assigned target source')
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as sock:r['query']=query(sock,record)
  r['completed']=True
 except Exception as e:r['error_type']=type(e).__name__;raise
 finally:save();os.close(fd)
 print(json.dumps({'completed':r['completed'],'accepted':r.get('query',{}).get('accepted',False)}))
if __name__=='__main__':
 try:main()
 except Exception as e:raise SystemExit('Owned target TCP control refused: '+type(e).__name__)
