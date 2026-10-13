"""One bounded owned normal API expiry cycle, restoring originals in finally."""
import datetime,hashlib,json,os,pathlib,subprocess,time
ROOT=pathlib.Path('/Users/pawangupta/.codex/worktrees/gcp-s2s/tunnex')
OUT=pathlib.Path('/private/tmp/gcp-cloud-expiry-20261010')
PREP=pathlib.Path('/private/tmp/gcp-lifecycle-qualification-prep/expiry.py')
BASE=OUT/'baseline-v1.json'; BASE_SHA='7c3e15122a3afc94705050cbc7884264eff44fff8930d3572e313092e7478430'
COOKIE=ROOT/'tests/gcp-s2s-local/.runtime/gateway-owner.cookies'
CAP=ROOT/'tests/gcp-s2s-local/qualification-20261010/expiry-observer/capture.py'
OBS=pathlib.Path('/private/tmp/gcp-expiry-guard-observer-darwin-arm64')
PACKET=ROOT/'deploy/ipsec/gcp-cloud-packet-check.py'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args,timeout=75):
 p=subprocess.run([str(x)for x in args],capture_output=True,timeout=timeout)
 if p.returncode:raise ValueError('bounded command refused: '+str(p.returncode))
 return p.stdout
for p,sha in [(PREP,'7e8ce129762160991edd6e61c1df9b78791a241d3ed10d584a635ab5ccd4c321'),(BASE,BASE_SHA),(OBS,'cd98f213ae95534093eba217c3e26d7d97bc82c58793fa9b082c86eb96159a9f'),(CAP,'ad94e5161146c34b3158946526e4087a1675c6474b869d2adffc27e172229d8e'),(PACKET,'b459a936a7d2b1899cdda72e311a217ea60b771dd97a649291ecb63a82a8bf49')]:
 if digest(p)!=sha:raise ValueError('reviewed input drift')
fd=os.open(OUT/'cycle-v1.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
f=os.fdopen(fd,'w')
def record(value):
 row={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),**value};f.write(json.dumps(row)+'\n');f.flush();os.fsync(f.fileno());print(json.dumps(row),flush=True)
def phase(name):
 path=OUT/(name+'-v1.jsonl')
 args=['python3',PREP,'--phase',name,'--cookie-file',COOKIE,'--baseline',BASE,'--baseline-sha256',BASE_SHA,'--receipt',path]
 if name=='cleanup':args+=['--lease-receipt',OUT/'lease-v1.jsonl','--lease-sha256',digest(OUT/'lease-v1.jsonl')]
 run(args,timeout=90);record({'phase':name,'completed':True,'receipt_sha256':digest(path)})
 return [json.loads(x)for x in path.read_text().splitlines()]
def observe(label,mode):
 filename='classic-app-'+label+'-v1.json';run(['python3',CAP,filename],timeout=75)
 p=pathlib.Path('/private/tmp/gcp-cloud-expiry-observer-20261010')/filename
 results=[]
 for protocol in ('tcp','udp'):
  v=subprocess.run([str(OBS),'--expect',mode,'--protocol',protocol],input=p.read_bytes(),capture_output=True,timeout=10)
  out=OUT/(label+'-'+protocol+'-observer-v1.json');outfd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(outfd,'wb')as file:file.write(v.stdout);file.flush();os.fsync(file.fileno())
  value=json.loads(v.stdout);results.append(v.returncode==0 and value.get('completed')is True)
 record({'stage':'native_'+label,'accepted':all(results),'capture_sha256':digest(p)})
 return all(results)
def packet(label,mode):
 p=OUT/(label+'-packets-v1.json');run(['python3',PACKET,'--profile','classic','--expect',mode,'--evidence',p],timeout=90)
 v=json.loads(p.read_text());accepted=v.get('completed')is True and v.get('accepted')is True
 record({'stage':'packet_'+label,'accepted':accepted,'receipt_sha256':digest(p)});return accepted
record({'started':True,'scope':'Only owned Classic TCP8080/UDP9000 normal API expiry; original two grants always restored; no HA or DNS expiry claim'})
lease_started=False;accepted=False
try:
 # Capture a new generation immediately before the baseline-gated lease writes.
 if not observe('fresh-pre-expiry','allow'):raise ValueError('fresh native preflight refused')
 lease_started=True;rows=phase('lease');leased=next(x for x in rows if x.get('leased')is True)
 deadline=datetime.datetime.fromisoformat(leased['expires_at'].replace('Z','+00:00')).timestamp()
 time.sleep(6)
 allow_native=observe('temporary-allow','allow');allow_packets=packet('temporary-allow','allow')
 while True:
  remaining=deadline+3-time.time()
  if remaining<=0:break
  record({'stage':'waiting_original_api_deadline','remaining_seconds':round(remaining,2)});time.sleep(min(15,remaining))
 deny_native=observe('expired-deny','deny');deny_packets=packet('expired-deny','deny')
 accepted=allow_native and allow_packets and deny_native and deny_packets
 record({'expiry_packet_and_native_acceptance':accepted,'deadline':leased['expires_at'],'scope':'fresh exact TCP/UDP flows; no existing-flow downtime claim'})
except BaseException as e:
 record({'completed':False,'error_type':type(e).__name__,'expiry_packet_and_native_acceptance':False})
finally:
 if lease_started:
  try:
   phase('restore');restored_native=observe('restored-allow','allow');restored_packets=packet('restored-allow','allow')
   phase('cleanup');record({'restoration_native_and_packets':restored_native and restored_packets,'expiry_packet_and_native_acceptance':accepted,'completed':restored_native and restored_packets,'overall_acceptance':accepted and restored_native and restored_packets})
  except BaseException as e:record({'completed':False,'restore_incomplete_or_unverified':True,'error_type':type(e).__name__})
 f.close()
