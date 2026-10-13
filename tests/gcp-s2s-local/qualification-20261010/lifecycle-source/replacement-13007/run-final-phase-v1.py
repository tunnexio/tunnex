"""Execute exactly one reviewed authorized owned-lab deployment phase."""
import pathlib,json,hashlib,base64,shlex,sys,os
if sys.flags.optimize:raise RuntimeError('optimized Python refused')
BASE=pathlib.Path('/private/tmp/gcp-cloud-replacement-13007c40-20261010')
remote_file=BASE/'replace-phased.final-v1.remote.py'
remote=remote_file.read_bytes()
assert hashlib.sha256(remote).hexdigest()=='fc124293c40051111b15ae5782e2687d4291211b45728fc273ded6f29c03b0ea'
phase=sys.argv[1];assert phase in ('stop','create-start')
assert len(sys.argv)==(4 if phase=='create-start'else 3)
for value in sys.argv[2:]:assert len(value)==64 and all(c in '0123456789abcdef' for c in value)
program=remote.decode()
compile(program,'<reviewed-replacement>','exec')
dependency=pathlib.Path('/private/tmp/gcp-cloud-native-build-20261010-1/build.py').read_bytes()
if hashlib.sha256(dependency).hexdigest()!='f2b27b12b40073ed5ad0d9625d92778047dbf766d460368db2fc97602d77ce38':raise RuntimeError('transport dependency drift')
ns={};exec(dependency.decode().split('receipt=json.loads')[0],ns)
payload=base64.b64encode(program.encode()).decode()
command='sudo -n python3 -c '+shlex.quote('import sys,base64;sys.argv='+repr(sys.argv)+';exec(base64.b64decode('+repr(payload)+'))')
try:result=ns['gateway'](command)
except Exception as e:
 raw=getattr(e,'stderr',b'') or b''
 name=BASE/('private-error-'+phase+'-'+str(__import__('time').time_ns())+'.txt')
 fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,raw)
 finally:os.close(fd)
 print(json.dumps({'phase':phase,'error_type':type(e).__name__,'returncode':getattr(e,'returncode',None),'private_stderr_sha256':hashlib.sha256(raw).hexdigest()}));raise SystemExit(1)
obj=json.loads(result);path=BASE/('receipt-'+phase+'-'+str(__import__('time').time_ns())+'.json')
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:os.write(fd,(json.dumps(obj,indent=2)+'\n').encode())
finally:os.close(fd)
print(json.dumps(obj))
