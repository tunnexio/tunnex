#!/usr/bin/env python3
"""LOCAL, standard SSH only. Read-only target stream metadata; default review-only.
No payload reads, target service changes, file-code upload, or packet probes.
"""
import argparse,hashlib,json,os,pathlib,re,shlex,stat,subprocess,time
KEY='/home/ubuntu/tunnex-bgp-20261007/lab-key';KNOWN='/home/ubuntu/tunnex-bgp-vgw-eic-20261008/known_hosts'
TARGET='10.85.1.10';CLIENT='10.84.2.10'
def ssh(command):
 proxy='aws --region eu-north-1 ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 3600'
 inner=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+KNOWN,'-o','ProxyCommand='+proxy,'-i',KEY,'ubuntu@'+TARGET,command]
 return ['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',shlex.join(inner)]
def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o600
 with os.fdopen(fd,'rb')as f:return f.read()
def save(directory,name,raw):
 fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def jsonsave(directory,name,value):save(directory,name,json.dumps(value,indent=2).encode()+b'\n')
def ownership(baseline,listener):
 nonce=baseline['nonce'];assert re.fullmatch('[0-9a-f]{64}',nonce)
 value=listener['identity'];assert type(value['pid'])is int and value['pid']>1 and value['pid']!=1353 and re.fullmatch('[0-9]+',value['startticks'])
 assert value['exe']in ['/usr/bin/nc.openbsd','/usr/bin/netcat.openbsd'] and TARGET in value['cmdline']and '8081'in value['cmdline']
 file='/var/tmp/tunnex-customer-8081-'+nonce+'/stream-received.bin'
 return {'nonce':nonce,'file':file,'listener':value}
def command(owner,count):
 assert 180<=count<=240;pid=str(owner['listener']['pid']);ticks=owner['listener']['startticks'];exe=owner['listener']['exe'];file=shlex.quote(owner['file'])
 # /proc stat parenthesized comm is removed with sed; remaining field20 is
 # original field22/starttime. No mutable CPU-time fields are used as identity.
 startup="test \"$(systemctl show tunnex-bgp-target.service -p MainPID --value)\" = 1353 && test \"$(sed 's/.*) //' /proc/1353/stat | awk '{print $20}')\" = 5629 && test \"$(readlink /proc/1353/exe)\" = /usr/bin/python3.12 && test \"$(readlink /proc/1353/cwd)\" = /opt/tunnex-bgp-lab && test \"$(sed 's/.*) //' /proc/"+pid+"/stat | awk '{print $20}')\" = "+ticks+" && test \"$(readlink /proc/"+pid+"/exe)\" = "+shlex.quote(exe)+" && test ! -L "+file+" && test -f "+file+" && test \"$(stat -c '%u %a' "+file+")\" = '0 600'"
 loop="i=0; while [ \"$i\" -lt "+str(count)+" ]; do printf '__SAMPLE__ %s\\n' \"$i\"; date --utc +%s.%N; cut -d' ' -f1 /proc/uptime; stat -c '%s %d %i %u %a' "+file+"; if [ -f /proc/"+pid+"/stat ]; then sed 's/.*) //' /proc/"+pid+"/stat | awk '{print $20}'; else printf 'absent\\n'; fi; ss -ntip state established '( sport = :8081 )'; printf '__END__\\n'; i=$((i+1)); sleep 1; done"
 finish="test \"$(systemctl show tunnex-bgp-target.service -p MainPID --value)\" = 1353 && test \"$(sed 's/.*) //' /proc/1353/stat | awk '{print $20}')\" = 5629"
 return 'sudo timeout -k 2s '+str(count+30)+'s sh -c '+shlex.quote('set -eu; '+startup+'; '+loop+'; '+finish)
def parse(raw,owner):
 lines=raw.decode().splitlines();samples=[];index=0;original_file=None
 while index<len(lines):
  assert lines[index].startswith('__SAMPLE__ ');number=int(lines[index].split()[1]);assert number==len(samples);index+=1
  end=lines.index('__END__',index);parts=lines[index:end];assert len(parts)>=4
  wall=float(parts[0]);monotonic=float(parts[1]);metadata=parts[2].split();assert len(metadata)==5 and metadata[3:]==['0','600'];file_identity=metadata[1:]
  if original_file is None:original_file=file_identity
  assert file_identity==original_file,'Received file ownership changed'
  start=parts[3];assert start in [owner['listener']['startticks'],'absent'],'Listener PID recycled'
  sockets='\n'.join(parts[4:]);tuples=re.findall(r'10\.85\.1\.10:8081\s+10\.84\.2\.10:([0-9]+)',sockets)
  if tuples:assert 'pid='+str(owner['listener']['pid'])in sockets and start==owner['listener']['startticks'],'Socket owner changed'
  samples.append({'index':number,'wall':wall,'monotonic':monotonic,'bytes':int(metadata[0]),'listener_startticks':start,'client_ports':sorted(set(tuples)),'socket_metadata':sockets});index=end+1
 assert samples
 ports={port for sample in samples for port in sample['client_ports']};assert len(ports)==1,'Established same-owner connection tuple must be observed exactly once'
 for before,after in zip(samples,samples[1:]):assert after['bytes']>=before['bytes']and after['monotonic']>=before['monotonic']
 gaps=[];start=None
 for before,after in zip(samples,samples[1:]):
  if after['bytes']==before['bytes'] and start is None:start=before
  if after['bytes']>before['bytes']and start is not None:gaps.append({'start_index':start['index'],'resume_index':after['index'],'bound_seconds':after['monotonic']-start['monotonic']});start=None
 return {'samples':samples,'observed_client_ports':sorted(ports),'zero_growth_to_resume_intervals':gaps,'trailing_zero_growth_censored':start is not None,'fault_correlation_requires_clock_bound':True,'payload_read':False}
def main():
 p=argparse.ArgumentParser();p.add_argument('--run',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--count',type=int,default=240);p.add_argument('--execute',action='store_true');a=p.parse_args()
 baseline=json.loads(private(a.run/'baseline.json'));listener=json.loads(private(a.run/'stream-listener.json'));owner=ownership(baseline,listener);text=command(owner,a.count)
 if not a.execute:print(json.dumps({'source_only':True,'scope':owner,'samples':a.count,'one_ssh_observer':True,'payload_read':False}));return
 os.umask(0o077);assert a.out.is_absolute()and a.out.parent.resolve()==a.out.parent and not a.out.exists();a.out.mkdir(mode=0o700)
 jsonsave(a.out,'pending.json',{'owner':owner,'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'command_sha256':hashlib.sha256(text.encode()).hexdigest(),'count':a.count,'wall_started':time.time(),'monotonic_started':time.monotonic()})
 # A fresh target date interval provides an honest bound; EIC latency is included.
 before=time.time();clock=subprocess.run(ssh('date --utc +%s.%N'),capture_output=True,timeout=30);after=time.time();save(a.out,'clock-raw.txt',clock.stdout);save(a.out,'clock-stderr.txt',clock.stderr);assert clock.returncode==0
 target=float(clock.stdout);jsonsave(a.out,'clock-bound.json',{'target':target,'local_before':before,'local_after':after,'offset_lower':target-after,'offset_upper':target-before,'interval_seconds':after-before})
 started=time.monotonic()
 try:result=subprocess.run(ssh(text),capture_output=True,timeout=a.count+65)
 except subprocess.TimeoutExpired as failure:
  save(a.out,'raw.txt',failure.stdout or b'');save(a.out,'stderr.txt',failure.stderr or b'');jsonsave(a.out,'execution.json',{'timeout':True,'elapsed':time.monotonic()-started,'read_only_observation_incomplete':True});raise
 elapsed=time.monotonic()-started
 # Complete stdout/stderr are immutable BEFORE parsing or acceptance.
 save(a.out,'raw.txt',result.stdout);save(a.out,'stderr.txt',result.stderr);jsonsave(a.out,'execution.json',{'exit':result.returncode,'elapsed':elapsed});assert result.returncode==0
 value=parse(result.stdout,owner);assert len(value['samples'])==a.count;jsonsave(a.out,'result.json',value)
 print(json.dumps({'read_only':True,'out':str(a.out),'samples':a.count,'payload_read':False,'fault_correlation':'pending independent clock alignment'}))
if __name__=='__main__':main()
