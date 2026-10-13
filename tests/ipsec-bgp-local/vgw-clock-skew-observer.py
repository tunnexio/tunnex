#!/usr/bin/env python3
"""Source-only default; bounded read-only clock interval observation on bastion16."""
import argparse,json,pathlib,subprocess,time,os,hashlib
p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
if not a.execute:print(json.dumps({'source_only':True,'clock_reads_only':True,'hosts':['owned gateway13','owned LANclient84.2'],'samples_per_host':3}));raise SystemExit
base=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008');assert base.is_dir();key='/home/ubuntu/tunnex-bgp-20261007/lab-key'
common=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','-i',key]
options=['-o','UserKnownHostsFile='+str(base/'client_known_hosts'),'-o','ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -i '+key+' -W %h:%p ubuntu@13.63.169.255']
result={}
for name,host,extra in [('gateway','ubuntu@13.63.169.255',[]),('client','ubuntu@10.84.2.10',options)]:
 intervals=[]
 for _ in range(3):
  start=time.time();mono=time.monotonic();r=subprocess.run(common+extra+[host,"python3 -c 'import time;print(time.time())'"],capture_output=True,text=True,timeout=10);end=time.time();elapsed=time.monotonic()-mono;assert r.returncode==0 and abs((end-start)-elapsed)<0.01
  remote=float(r.stdout.strip());intervals.append({'lower':remote-end,'upper':remote-start,'roundtrip':elapsed,'local_start':start,'local_end':end,'remote':remote})
 # Every observed interval must overlap; otherwise clocks changed during observation.
 low=max(r['lower']for r in intervals);high=min(r['upper']for r in intervals);assert low<=high
 result[name]={'offset_lower':low,'offset_upper':high,'samples':intervals}
gw=result['gateway'];cl=result['client'];bound=max(abs(gw['offset_lower']-cl['offset_upper']),abs(gw['offset_upper']-cl['offset_lower']))
result.update({'maximum_verified_clock_skew_seconds':bound,'scope':'measured interval bound at observation time only; clock step or long delay before fault requires refresh','helper_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()})
os.umask(0o077)
with a.output.open('x')as f:json.dump(result,f,indent=2);f.flush();os.fsync(f.fileno())
fd=os.open(a.output.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);print(json.dumps({'output':str(a.output),'maximum_verified_clock_skew_seconds':bound}))
