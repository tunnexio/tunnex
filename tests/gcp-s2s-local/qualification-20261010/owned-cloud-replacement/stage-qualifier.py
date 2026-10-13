"""Stage exact observational ELF through the pinned bastion. Never execute it."""
import os,sys,pathlib,hashlib,base64,shlex,json,subprocess,time
BASE=pathlib.Path('/private/tmp/gcp-cloud-replacement-4143d866-20261010')
EXPECTED='62215f47601e225d9ed8a6ae98a5bc90e34c2dafa1e1808cf5fef02eee7b8047'
BROOT='/var/lib/tunnex-gcp-qualifier-courier-4143d866-20261010'
GROOT='/var/lib/tunnex-gcp-replacement-4143d866-20261010'
if sys.flags.optimize:raise RuntimeError('optimized Python refused')
assert len(sys.argv)==2 and len(sys.argv[1])==64 and all(c in '0123456789abcdef' for c in sys.argv[1])
b=(BASE/'gcp-poststop-guard-amd64').read_bytes();assert hashlib.sha256(b).hexdigest()==EXPECTED
ns={};dependency=pathlib.Path('/private/tmp/gcp-cloud-native-build-20261010-1/build.py').read_bytes()
assert hashlib.sha256(dependency).hexdigest()=='f2b27b12b40073ed5ad0d9625d92778047dbf766d460368db2fc97602d77ce38'
exec(dependency.decode().split('receipt=json.loads')[0],ns)
receiver=r'''import os,sys,stat,hashlib,json
root=ROOT;expected=EXPECTED;before=BEFORE
if sys.flags.optimize:raise RuntimeError('optimized Python refused')
assert os.geteuid()==0
if before is None:assert not os.path.lexists(root);os.mkdir(root,0o700)
s=os.lstat(root);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
rd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 d=os.fstat(rd);assert (d.st_dev,d.st_ino)==(s.st_dev,s.st_ino) and d.st_uid==0 and stat.S_IMODE(d.st_mode)==0o700
 if before is not None:
  fd=os.open('before.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rd)
  try:
   f=os.fstat(fd);assert stat.S_ISREG(f.st_mode) and f.st_uid==0 and stat.S_IMODE(f.st_mode)==0o600 and f.st_nlink==1 and 0<f.st_size<=16*1024*1024
   raw=os.read(fd,16*1024*1024+1);a=os.fstat(fd);assert len(raw)==f.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns)==(f.st_dev,f.st_ino,f.st_size,f.st_mtime_ns) and hashlib.sha256(raw).hexdigest()==before
   obj=json.loads(raw);assert obj['source']=='4143d866ab97386411ff1ac4705aaa0e4579bcf6' and obj['old']=='dc81baef1c4924007b39224fd4f9b14bef94e734c2138257b12bfdc46abd8294'
  finally:os.close(fd)
 payload=sys.stdin.buffer.read(32*1024*1024+1);assert 0<len(payload)<32*1024*1024 and hashlib.sha256(payload).hexdigest()==expected
 fd=os.open('gcp-poststop-guard',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700,dir_fd=rd)
 try:
  offset=0
  while offset<len(payload):offset+=os.write(fd,payload[offset:])
  os.fsync(fd);a=os.fstat(fd);assert a.st_uid==0 and stat.S_IMODE(a.st_mode)==0o700 and a.st_nlink==1
 finally:os.close(fd)
 os.fsync(rd)
 fd=os.open('gcp-poststop-guard',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rd)
 try:
  check=os.read(fd,32*1024*1024+1);assert hashlib.sha256(check).hexdigest()==expected
 finally:os.close(fd)
finally:os.close(rd)
print(json.dumps({'sha256':expected,'staged_root0700_file0700':True,'executed':False}))
'''
def command(root,before):
 program=receiver.replace('root=ROOT;expected=EXPECTED;before=BEFORE','root='+repr(root)+';expected='+repr(EXPECTED)+';before='+repr(before))
 compile(program,'<reviewed-staging>','exec')
 encoded=base64.b64encode(program.encode()).decode()
 return 'sudo -n python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(encoded)+'))')
try:
 first=ns['call'](command(BROOT,None),input=b);assert json.loads(first)['sha256']==EXPECTED
 second=ns['call']('sudo -n cat '+shlex.quote(BROOT+'/gcp-poststop-guard')+' | '+shlex.join(ns['G']+[command(GROOT,sys.argv[1])]))
 assert json.loads(second)['sha256']==EXPECTED
except Exception as e:
 raw=getattr(e,'stderr',b'') or b'';p=BASE/('staging-private-error-'+str(time.time_ns())+'.txt');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,raw)
 finally:os.close(fd)
 print(json.dumps({'error_type':type(e).__name__,'returncode':getattr(e,'returncode',None),'private_stderr_sha256':hashlib.sha256(raw).hexdigest(),'executed':False}));raise SystemExit(1)
print(json.dumps({'both_hop_sha256':EXPECTED,'gateway_preflight_sha256':sys.argv[1],'staged':True,'executed':False,'scope':'immutable observational qualifier only; no runtime authority/deployment action'}))
