"""Source-only prepared runner. Execution requires parent approval for each phase."""
import pathlib,json,hashlib,base64,shlex,sys,os
if sys.flags.optimize:raise RuntimeError('optimized Python refused')
BASE=pathlib.Path('/private/tmp/gcp-cloud-replacement-4143d866-20261010')
remote_file=BASE/'continue-phased.remote.py';plan_file=BASE/'replacement-review.json'
remote=remote_file.read_bytes();plan=plan_file.read_bytes()
assert hashlib.sha256(remote).hexdigest()=='24e574bfac42b2690fee8309fee6dcda75b039d242dd0cc627f0511a88847eed'
assert hashlib.sha256(plan).hexdigest()=='40e1bd5964b5871848f390b838ddc4959da9f77a90ed270afb086ba0663e1085'
review=json.loads(plan)
public={'TUNNEX_API_URL': 'http://127.0.0.1:38083', 'TUNNEX_AGENT_URL': 'https://127.0.0.1:38446', 'TUNNEX_AGENT_SERVERNAME': 'tunnex-control', 'TUNNEX_AGENT_HEALTH_ADDR': '127.0.0.1:9091', 'TUNNEX_NODE_STATE_DIR': '/var/lib/tunnex-node', 'TUNNEX_NODE_ENDPOINT': '34.131.136.132:51820', 'TUNNEX_WG_INTERFACE': 'wg0', 'TUNNEX_NODE_NAME': 'tn-gcps2s-20261010-gateway', 'TUNNEX_WG_BACKEND': 'wgctrl'}
phase=sys.argv[1];assert phase=='continue-create-start'
assert len(sys.argv)==4
for value in sys.argv[2:]:assert len(value)==64 and all(c in '0123456789abcdef' for c in value)
program='PUBLIC_ENV='+repr(public)+'\nCREATE='+repr(review['create_argv'])+'\n'+remote.decode()
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
