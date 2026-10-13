"""Local source-only staging plan. Execute only after scoped root/human review.
Stages reviewed test samplers and observation pins; no initiation, gateway restart,
service, grant or API change. Measures real SSH clock bounds before any write.
"""
import argparse,pathlib,hashlib,json,shlex,subprocess,time,os
P=pathlib.Path(__file__).resolve().parent
CID='35a889a1a6b7e521084715f51a2fb6f8537b581647f8c7ebfa9b61e258df6605'
BASE='/home/ubuntu/tunnex-bgp-lab/rekey-cycle7'
FILES={'customer-rekey-native-sampler-v4.py':'5d349d4f5ddefe09cc12284b7c787962ffa956a82237f04d7902e5a83e0c30e4','customer-rekey-public-status-probe-v2.py':'ff6bcb7ece05daec16f80d019f8ebbfeba501d3dc8ed9149b23eaf109eb98db4'}
def ssh(command):
 inner=shlex.join(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-i','/home/ubuntu/tunnex-bgp-20261007/lab-key','ubuntu@13.63.169.255',command]);return ['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',inner]
def clock_bounds(before,after,remote):
 assert type(before)is int and type(after)is int and type(remote)is int and before<=after
 lower=remote-after;upper=remote-before;bound=max(abs(lower),abs(upper))
 return {'local_before_ns':before,'local_after_ns':after,'gateway_ns':remote,'offset_lower_ns':lower,'offset_upper_ns':upper,'clock_skew_bound_ns':bound,'roundtrip_ns':after-before,'scope':'actual cross-host timing correlation only; not sampler readiness authority'}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args()
 files={name:(P/name).read_text()for name in FILES};assert all(hashlib.sha256(files[n].encode()).hexdigest()==h for n,h in FILES.items())
 if not a.execute:print(json.dumps({'source_only':True,'destination':BASE,'files':FILES,'no_rekey':True,'clock_bound':'actual interval retained; readiness uses same gateway monotonic marker'}));return
 os.umask(0o077);a.out.mkdir(mode=0o700,exist_ok=False)
 def save(n,obj):
  with(a.out/n).open('x')as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
  fd=os.open(a.out,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 before=time.time_ns();r=subprocess.run(ssh('python3 -c '+shlex.quote('import time;print(time.time_ns())')),capture_output=True,text=True,timeout=15);after=time.time_ns();save('clock-raw.json',{'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'local_before_ns':before,'local_after_ns':after});assert r.returncode==0
 bound=clock_bounds(before,after,int(r.stdout.strip()));save('clock-bound.json',bound)
 identity_command="sudo -n docker inspect --format '{{.Id}} {{.Image}} {{.State.Pid}} {{.State.StartedAt}}' "+CID+"; sudo -n docker exec "+CID+" readlink /proc/1/ns/net; sudo -n docker exec "+CID+" sha256sum /proc/1/exe /state/cert.pem"
 r=subprocess.run(ssh(identity_command),capture_output=True,text=True,timeout=15);save('worker-before.json',{'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0
 import importlib.util
 spec=importlib.util.spec_from_file_location('orchestrator',P/'customer-cloud-rekey-orchestrator-v8.py');o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o);o.identity(r.stdout)
 pins={'root_reviewed':True,'restoration_complete':True,'container':CID,'namespace':'net:[4026532946]','node_sha256':'296065d03c4e1f6b69f27708ab9a33d09f77004817bb5f57c10d622c3f30e75c','certificate_sha256':'eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d','pid1_startticks':'9961117','source_sha256':'4674c202643ef54f7239bd1c54af7fd78248b446e743da61b3ef229efc91ec1e','build_receipt_sha256':'6ac029070ad8ccf9174b9744c7291c1834798a5bebadb114b90c444cc30ab6e6'}
 files['native-pins.json']=json.dumps(pins,sort_keys=True);files['clock-bound.json']=json.dumps(bound,sort_keys=True)
 remote="import os,pathlib,json,hashlib;os.umask(0o077);p=pathlib.Path("+repr(BASE)+");p.mkdir(mode=0o700);files="+repr(files)+"\nfor name,data in files.items():\n fd=os.open(p/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,'w')as f:f.write(data);f.flush();os.fsync(f.fileno())\n print(name,hashlib.sha256(data.encode()).hexdigest())\nfd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)\n"
 save('staging-intent.json',{'destination':BASE,'files':{n:hashlib.sha256(v.encode()).hexdigest()for n,v in files.items()},'clock_bound':bound,'unknown_outcome_never_replay':True})
 r=subprocess.run(ssh('sudo -n python3 -'),input=remote,capture_output=True,text=True,timeout=20);save('staging-result.json',{'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0
 print(json.dumps({'staged':BASE,'native_pins_sha256':hashlib.sha256(files['native-pins.json'].encode()).hexdigest(),'clock_skew_bound_ns':bound['clock_skew_bound_ns'],'no_sampler_or_rekey_executed':True}))
if __name__=='__main__':main()
