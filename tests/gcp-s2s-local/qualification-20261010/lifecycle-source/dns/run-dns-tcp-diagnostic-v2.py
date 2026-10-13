"""One owned instrumented TCP case, only after fresh complete positive guard proof.

Pinned to retained source4143. It is a preparation, not a future image qualifier.
No grants, routes, tracing rules or credentials are modified.
"""
import pathlib,hashlib,shlex,json,os,subprocess,datetime
D=pathlib.Path('/Users/pawangupta/.codex/worktrees/gcp-s2s/tunnex/deploy/ipsec')
CAP=D.parents[1]/'tests/gcp-s2s-local/qualification-20261010/expiry-observer/capture.py'
OBS=pathlib.Path('/private/tmp/gcp-expiry-guard-observer-darwin-arm64')
P=pathlib.Path('/private/tmp/gcp-cloud-native-build-20261010-1/build.py')
OUT=pathlib.Path('/private/tmp/gcp-lifecycle-archive-20261010')
CAPROOT=pathlib.Path('/private/tmp/gcp-cloud-expiry-observer-20261010')
FILES={'gcp-classic-dns-tcp-diagnostic.py':'b4785695645bff4da2013e1b6562992b36901cc1f2a2133dc47947b74699dbe7','gcp-classic-dns-tcp-trace-plan.py':'29f7bbad3e39eb9b9f63017e98cf663db12ad35056bc0f69f29e5ffae74dd4d2','gcp-cloud-dns-wire-probe.py':'b260ea4e8985926022411a2015e495c3fedbfc56238544af9e8528fef39740ba'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for p,h in [(P,'f2b27b12b40073ed5ad0d9625d92778047dbf766d460368db2fc97602d77ce38'),(CAP,'ad94e5161146c34b3158946526e4087a1675c6474b869d2adffc27e172229d8e'),(OBS,'cd98f213ae95534093eba217c3e26d7d97bc82c58793fa9b082c86eb96159a9f')]+[(D/n,h)for n,h in FILES.items()]:
 if sha(p)!=h:raise ValueError('reviewed dependency drift')
fd=os.open(OUT/'dns-tcp-diagnostic-v2.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);log=os.fdopen(fd,'w')
def record(value):
 row={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),**value};log.write(json.dumps(row)+'\n');log.flush();os.fsync(log.fileno());print(json.dumps(row),flush=True)
def checked(args):
 r=subprocess.run([str(x)for x in args],capture_output=True,timeout=75)
 if r.returncode:raise ValueError('bounded capture/check refused')
 return r.stdout
def full_guard(label):
 name='dns-tcp-app-native-'+label+'-v2.json';checked(['python3',CAP,name]);p=CAPROOT/name
 v=subprocess.run([str(OBS),'--expect','allow','--protocol','tcp'],input=p.read_bytes(),capture_output=True,timeout=10)
 dest=OUT/('dns-tcp-'+label+'-guard-v2.json');fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(v.stdout);f.flush();os.fsync(f.fileno())
 value=json.loads(v.stdout);accepted=v.returncode==0 and value.get('completed')is True
 record({'stage':'complete_native_guard_'+label,'accepted':accepted,'capture_sha256':sha(p),'observer_sha256':sha(dest)})
 if not accepted:raise ValueError('fresh full positive native guard required')
 return value
started=False;ns={};remote_root='/var/lib/tunnex-gcp-cloud-preparation/dns-tcp-diagnostic-b47856';remote_receipt=remote_root+'/classic-tcp-app-native-v2.json'
try:
 record({'started':True,'scope':'one direct TCP app case with observers, no automatic drop-cause claim'})
 full_guard('before')
 exec(P.read_text().split('receipt=json.loads')[0],ns)
 ns['gateway']('test ! -e '+shlex.quote(remote_root)+' && sudo -n install -d -m 0700 '+shlex.quote(remote_root))
 for name,h in FILES.items():
  path=remote_root+'/'+name;ns['call'](shlex.join(ns['G']+['umask 077; sudo -n tee '+shlex.quote(path)+' >/dev/null']),input=(D/name).read_bytes())
  if ns['gateway']('sudo -n sha256sum '+shlex.quote(path)).split()[0]!=h:raise ValueError('delivered bytes changed')
 record({'stage':'reviewed_bytes_delivered','accepted':True})
 started=True
 try:
  ns['gateway']('sudo -n python3 '+shlex.quote(remote_root+'/gcp-classic-dns-tcp-diagnostic.py')+' --execute --receipt '+shlex.quote(remote_receipt))
 except BaseException as e:record({'stage':'remote_command_refused','error_type':type(e).__name__})
finally:
 if started:
  try:
   payload=ns['gateway']('sudo -n cat '+shlex.quote(remote_receipt)).encode();dest=OUT/'classic-tcp-app-native-v2.json'
   fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb')as f:f.write(payload);f.flush();os.fsync(f.fileno())
   value=json.loads(payload);record({'stage':'remote_receipt_preserved','sha256':sha(dest),'completed':value.get('completed',False),'query_accepted':value.get('query',{}).get('accepted',False),'capture_complete':value.get('capture_complete',False),'stable_native_identity':value.get('stable_native_identity',False),'causal_drop_proven':False})
  except BaseException as e:record({'stage':'receipt_collection_refused','error_type':type(e).__name__})
  try:full_guard('after')
  except BaseException as e:record({'stage':'final_guard_refused','error_type':type(e).__name__})
 log.close()
