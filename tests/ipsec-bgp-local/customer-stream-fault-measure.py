#!/usr/bin/env python3
"""Local source-only default. Read-only simultaneous stream/route/RIB/guard/socket
measurement. Does not create traffic, fault rules, policy, or remote source files.
The already-running stream and separate reviewed atomic fault driver are prerequisites.
"""
import argparse,hashlib,importlib.util,json,os,pathlib,re,shlex,stat,subprocess,time
DIR=pathlib.Path(__file__).resolve().parent
KEY='/home/ubuntu/tunnex-bgp-20261007/lab-key'
CID='35a889a1a6b7e521084715f51a2fb6f8537b581647f8c7ebfa9b61e258df6605'
NODE='296065d03c4e1f6b69f27708ab9a33d09f77004817bb5f57c10d622c3f30e75c'
NS='net:[4026532946]';CERT='eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d'
IMAGE='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2'
GROWTH_SHA='e6ffbcd191fe4ad616ee46bb56338ac91e543afc531e74e36fc80547bb66dd51'
def module():
 f=DIR/'customer-stream-growth-observer.py';assert hashlib.sha256(f.read_bytes()).hexdigest()==GROWTH_SHA;s=importlib.util.spec_from_file_location('growth',f);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def ssh(host,cmd):
 inner=shlex.join(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-i',KEY,'ubuntu@'+host,cmd]);return ['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',inner]
def client_ssh(cmd):
 inner=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-i',KEY,'-o','UserKnownHostsFile=/home/ubuntu/tunnex-bgp-vgw-eic-20261008/client_known_hosts','-o','ProxyCommand=ssh -o BatchMode=yes -i '+KEY+' ubuntu@13.63.169.255 -W %h:%p','ubuntu@10.84.2.10',cmd]
 return ['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',shlex.join(inner)]
def process_proof(p):
 assert type(p['pid'])is int and p['pid']>1 and re.fullmatch('[0-9]+',p['startticks'])and p['exe']in ['/usr/bin/nc.openbsd','/usr/bin/netcat.openbsd']
 pid=str(p['pid']);return "test \"$(sed 's/.*) //' /proc/"+pid+"/stat | awk '{print $20}')\" = "+p['startticks']+" && test \"$(readlink /proc/"+pid+"/exe)\" = "+shlex.quote(p['exe'])
def socket_command(p,port,side,count):
 assert type(port)is int and 1024<=port<=65535 and side in ['client','target']and count==240
 proof=process_proof(p);filt='sport = :'+str(port)+' and dport = :8081'if side=='client'else'sport = :8081 and dport = :'+str(port)
 loop="i=0; while [ $i -lt 240 ]; do "+proof+"; printf '__SAMPLE__ %s\\n' $i; date --utc +%s.%N; cut -d' ' -f1 /proc/uptime; ss -ntipo "+shlex.quote('( '+filt+' )')+"; printf '__END__\\n'; i=$((i+1)); sleep 1; done"
 return 'sudo -n timeout -k 2s 270s sh -c '+shlex.quote('set -eu; '+loop)
def gateway_identity():
 return 'test "$(docker inspect --format \'{{.Id}} {{.Image}} {{.State.Pid}} {{.State.StartedAt}}\' '+CID+')" = '+shlex.quote(CID+' '+IMAGE+' 3115397 2026-10-08T14:46:54.478240323Z')+' && test "$(docker exec '+CID+' readlink /proc/1/ns/net)" = '+shlex.quote(NS)+' && test "$(docker exec '+CID+' sha256sum /proc/1/exe /state/cert.pem)" = '+shlex.quote(NODE+'  /proc/1/exe\n'+CERT+'  /state/cert.pem')
def gateway_command(directory):
 assert re.fullmatch('/state/ipsec/bgp-[0-9a-f-]{36}-g[1-9][0-9]*',directory)
 ex='docker exec -e STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf '+CID+' '
 vty=ex+'/opt/tunnex-bgp/vtysh --vty_socket '+shlex.quote(directory)+' -d bgpd'
 sample="i=0; while [ $i -lt 240 ]; do "+gateway_identity()+"; printf '__SAMPLE__ %s\\n' $i; date --utc +%s.%N; cut -d' ' -f1 /proc/uptime; "+ex+"ip -j -4 route show table all; "+vty+" -c 'show bgp summary json'; "+vty+" -c 'show bgp ipv4 unicast json'; "+ex+"nft -j list table inet tunnex_ipsec; printf '__END__\\n'; i=$((i+1)); sleep 1; done"
 return 'sudo -n timeout -k 2s 300s sh -c '+shlex.quote('set -eu; '+sample)
def header_command(port):
 assert type(port)is int and 1024<=port<=65535
 filt='tcp and ((src host 10.84.2.10 and src port '+str(port)+' and dst host 10.85.1.10 and dst port 8081) or (src host 10.85.1.10 and src port 8081 and dst host 10.84.2.10 and dst port '+str(port)+'))'
 return 'sudo -n timeout -s INT -k 2s 270s sh -c '+shlex.quote('set -eu; '+gateway_identity()+'; nsenter -t 3115397 -n timeout -s INT -k 2s 265s tcpdump -l -n -S -tttt -v -s 96 -i any '+shlex.quote(filt))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--pins',type=pathlib.Path);ap.add_argument('--output',type=pathlib.Path);ap.add_argument('--execute',action='store_true');a=ap.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'observations_only':True,'fault_driver_exec':False,'maximum_remote_seconds':300}));return
 growth=module();q=json.loads(growth.private(a.pins));assert q['root_reviewed']is True and q['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()and q['container']==CID and q['node_sha256']==NODE and q['namespace']==NS
 owner=growth.ownership(json.loads(growth.private(pathlib.Path(q['stream_run'])/'baseline.json')),json.loads(growth.private(pathlib.Path(q['stream_run'])/'stream-listener.json')))
 assert q['selected_provider']=='9d9f98e2-cd96-456d-b020-a5a79f688040'and q['peer_outside']=='51.20.220.141'
 assert q['directory_proof_root_reviewed']is True and q['bgp_directory'].endswith('-g'+str(q['bgp_generation']))
 os.umask(0o077);a.output.mkdir(mode=0o700,exist_ok=False);growth.jsonsave(a.output,'intent.json',{'pins_sha256':hashlib.sha256(a.pins.read_bytes()).hexdigest(),'source_sha256':q['source_sha256'],'faults_installed':False,'started_ns':time.time_ns(),'cadence_claim':'Actual timestamps only; shell commands may exceed nominal1s'})
 jobs={'target-growth':growth.ssh(growth.command(owner,240)),'target-sockets':growth.ssh(socket_command(owner['listener'],q['client_port'],'target',240)),'client-sockets':client_ssh(socket_command(q['client_process'],q['client_port'],'client',240)),'gateway-native':ssh('13.63.169.255',gateway_command(q['bgp_directory'])),'tcp-headers':ssh('13.63.169.255',header_command(q['client_port']))}
 procs=[];files=[]
 try:
  for name,argv in jobs.items():
   out=(a.output/(name+'.stdout')).open('xb');err=(a.output/(name+'.stderr')).open('xb');files.extend([out,err]);proc=subprocess.Popen(argv,stdout=out,stderr=err);procs.append((name,proc))
  # No fault invocation: root must independently prove fresh baseline progressing
  # samples and every observer live before using its separately approved driver.
  deadline=time.monotonic()+330
  while any(p.poll()is None for _,p in procs):
   assert time.monotonic()<deadline;time.sleep(1)
  for f in files:f.flush();os.fsync(f.fileno())
  growth.jsonsave(a.output,'results.json',{'exit_codes':{name:p.returncode for name,p in procs},'acceptance_pending_offline_alignment':True,'faults_installed':False,'application_writes':False,'ended_ns':time.time_ns()})
 finally:
  for _,proc in procs:
   if proc.poll()is None:proc.terminate();proc.wait(timeout=5)
  for f in files:f.close()
if __name__=='__main__':main()
