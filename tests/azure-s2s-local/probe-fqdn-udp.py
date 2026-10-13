#!/usr/bin/env python3
"""Fixed owned DNS-to-UDP observations only. Never changes grants or sockets after failure."""
import argparse,importlib.util,json,math,os,signal,socket,time
from pathlib import Path
from datetime import datetime,timezone
spec=importlib.util.spec_from_file_location('owned_packets',Path(__file__).with_name('probe-packets.py'))
packets=importlib.util.module_from_spec(spec);spec.loader.exec_module(packets)
HOST='service.azure-s2s.test';TARGET='10.231.1.4';SOURCE='10.233.10.2';PORT=8081

def bounds(seconds,timeout):
 if not 1<=seconds<=60 or not math.isfinite(timeout) or not .2<=timeout<=2:raise ValueError('bounded inputs')
def resolve():
 answers={row[4][0] for row in socket.getaddrinfo(HOST,PORT,socket.AF_INET,socket.SOCK_DGRAM)}
 if answers!={TARGET}:raise ValueError('exact genuine owned DNS answer required')
def sample(connection,reused,timeout):
 entry={'success':False,'reused_existing_socket':reused,'local_port':connection.getsockname()[1]}
 def alarm(_s,_f):raise TimeoutError()
 previous=signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,timeout)
 try:
  resolve();entry['dns_expected_answer']=True
  entry.update(packets.udp_echo(connection,packets.udp_payload(64,time.monotonic_ns())))
 except (OSError,ValueError):entry['error_code']='dns_or_udp_refused'
 finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
 return entry

def write(path,value):
 if path.absolute()!=path.resolve() or path.parent.is_symlink():raise ValueError('private receipt path')
 st=path.parent.stat()
 if st.st_uid!=os.geteuid() or st.st_mode&0o077:raise ValueError('private receipt parent')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as out:json.dump(value,out);out.flush();os.fsync(out.fileno())
def run(receipt,seconds,timeout):
 bounds(seconds,timeout)
 if receipt.exists() or receipt.is_symlink():raise ValueError('no receipt replay')
 def connected():
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  try:s.settimeout(timeout);s.bind((SOURCE,0));s.connect((TARGET,PORT));return s
  except Exception:s.close();raise
 persistent=connected();start=time.monotonic();end=start+seconds
 result={'hostname':HOST,'expected_address':TARGET,'source':SOURCE,'port':PORT,'started_at':datetime.now(timezone.utc).isoformat(),'scope':'Actual DNS/UDP echo only; source preservation requires independent backend capture, no encrypted/native authority inferred','samples':[],'counters':{k:{'success':0,'failure':0} for k in ('fresh_udp','original_udp')}}
 try:
  while time.monotonic()<end:
   for kind in ('fresh_udp','original_udp'):
    if time.monotonic()>=end:break
    s=connected() if kind=='fresh_udp' else persistent
    try:entry=sample(s,kind=='original_udp',min(timeout,max(.001,end-time.monotonic())))
    finally:
     if kind=='fresh_udp':s.close()
    entry.update(kind=kind,elapsed_seconds=round(time.monotonic()-start,6));result['samples'].append(entry)
    result['counters'][kind]['success' if entry['success'] else 'failure']+=1
   time.sleep(min(.2,max(0,end-time.monotonic())))
 finally:
  persistent.close();result['finished_at']=datetime.now(timezone.utc).isoformat();write(receipt,result)
 return result['counters']
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--seconds',type=int,default=60);p.add_argument('--timeout',type=float,default=1);a=p.parse_args();print(json.dumps(run(a.receipt,a.seconds,a.timeout)))
if __name__=='__main__':
 try:main()
 except (OSError,ValueError):raise SystemExit('Owned UDP probe refused; no acceptance claim')
