"""Root-coordinated single read-only observation; no API or cloud writes."""
import pathlib,hashlib,types,subprocess,shlex,base64,json,os,stat,argparse,sys
D=pathlib.Path('/private/tmp/gcp-classic-psk-lifecycle-prep-20261011')
REMOTE=D/'capture-post-lifecycle-cutover-wg24-v1.remote.py';REMOTE_SHA='f198a449c762e10fec840ac470709aa02dfc147d6dff85e2d07fede28892ac6c'
TRANSPORT=pathlib.Path('/private/tmp/gcp-cloud-native-build-20261010-1/build.py');TRANSPORT_SHA='f2b27b12b40073ed5ad0d9625d92778047dbf766d460368db2fc97602d77ce38'
def exclusive(p):
 parent=p.parent.lstat()
 if not stat.S_ISDIR(parent.st_mode)or parent.st_uid!=os.geteuid()or stat.S_IMODE(parent.st_mode)!=0o700:raise ValueError('owned private output parent')
 return os.fdopen(os.open(p,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600),'wb')
def main():
 a=argparse.ArgumentParser();a.add_argument('--receipt',required=True);args=a.parse_args();out=pathlib.Path(args.receipt)
 remote=REMOTE.read_bytes();transport=TRANSPORT.read_bytes()
 if hashlib.sha256(remote).hexdigest()!=REMOTE_SHA or hashlib.sha256(transport).hexdigest()!=TRANSPORT_SHA:raise ValueError('reviewed source drift')
 ns={};exec(compile(transport.decode().split('receipt=json.loads')[0],str(TRANSPORT),'exec'),ns)
 encoded=base64.b64encode(remote).decode();program="import base64;exec(compile(base64.b64decode("+repr(encoded)+"),'owned-classic-current-allocation','exec'),{'__name__':'__main__'})"
 command='sudo -n python3 -c '+shlex.quote(program)
 stdout=out.with_name(out.name+'.stdout');stderr=out.with_name(out.name+'.stderr')
 with exclusive(out)as receipt,exclusive(stdout)as sf,exclusive(stderr)as ef:
  def record(v):receipt.write((json.dumps(v,sort_keys=True)+'\n').encode());receipt.flush();os.fsync(receipt.fileno())
  record({'started':True,'mutations':0,'remote_source_sha256':REMOTE_SHA,'transport_sha256':TRANSPORT_SHA})
  try:
   result=subprocess.run(ns['B']+[shlex.join(ns['G']+[command])],stdout=sf,stderr=ef,timeout=90)
   sf.flush();ef.flush();os.fsync(sf.fileno());os.fsync(ef.fileno())
   raw=stdout.read_bytes()
   if result.returncode or len(raw)>2097152:raise ValueError('native observer returned refusal')
   value=json.loads(raw)
   if not isinstance(value,dict)or value.get('completed')is not True or value.get('source_schema_verified')is not True or value.get('complete_schema_sha256')!='ac14e9cd861b3260b0c30599fe02b8d4cc9730a5b0e1967cb9e0bb1e0382639e' or value.get('schema_source_input_proof_sha256')!='3678eb0404b2e538e37c0b123d39d50a2c697fb8aa484d0e81f9b1c775fd85fe':raise ValueError('native observation incomplete')
   record({'completed':True,'scope':'native observation only; separate normalAPI cleanup ACK and fullguard required','observation':value,'stdout_sha256':hashlib.sha256(raw).hexdigest(),'stderr_sha256':hashlib.sha256(stderr.read_bytes()).hexdigest()})
  except BaseException as e:
   sf.flush();ef.flush();os.fsync(sf.fileno());os.fsync(ef.fileno())
   record({'completed':False,'error_type':type(e).__name__,'stdout_sha256':hashlib.sha256(stdout.read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256(stderr.read_bytes()).hexdigest(),'retry_forbidden':True});raise
if __name__=='__main__':
 try:main()
 except BaseException as e:print(json.dumps({'completed':False,'error_type':type(e).__name__}));raise SystemExit(1)
