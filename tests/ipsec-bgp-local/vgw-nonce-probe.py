#!/usr/bin/env python3
"""Run ONLY on designated bastion after root confirms ZT convergence.
HTTP server does not echo nonce: require exact target access-log correlation.
"""
import argparse,hashlib,json,os,pathlib,secrets,subprocess,time
ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');ap.add_argument('--gateway-container',required=True);ap.add_argument('--expect',choices=['allow','deny'],required=True);a=ap.parse_args()
assert a.gateway_container and all(c in '0123456789abcdef' for c in a.gateway_container) and len(a.gateway_container)==64
key='/home/ubuntu/tunnex-bgp-20261007/lab-key';base=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008');os.umask(0o077)
def run(cmd):
 r=subprocess.run(cmd,capture_output=True,timeout=35);return {'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
def ssh(host,command,options=[]):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-i',key,*options,host,command])
client_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'client_known_hosts'),'-o','ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -i '+key+' -W %h:%p ubuntu@13.63.169.255']
target_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','ProxyCommand=aws ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 120']
nonce=secrets.token_hex(32);uri='/?nonce='+nonce
if not a.execute:print(json.dumps({'source_only':True,'expect':a.expect,'uri_template':'/?nonce=<fresh64hex>','target':'10.85.1.10:8080','correlation':'exact source10.84.2.10 URI in independent EIC journal, plus actual CHILD/NFT counter snapshots'}));raise SystemExit
assert pathlib.Path('/home/ubuntu').is_dir() and base.is_dir()
def save(name,obj):
 with open(base/name,'x') as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
 fd=os.open(base,os.O_RDONLY);os.fsync(fd);os.close(fd)
started=int(time.time());stem='nonce-'+nonce
save(stem+'-intent.json',{'nonce':nonce,'uri':uri,'expected':a.expect,'gateway_container':a.gateway_container,'started':started})
command='sudo -n docker inspect --format "{{.Id}} {{.State.Running}}" '+a.gateway_container+'; sudo -n docker exec '+a.gateway_container+' nft -j list ruleset; sudo -n docker exec '+a.gateway_container+' swanctl --list-sas --uri unix:///run/tunnex-ipsec/charon.vici'
before=ssh('ubuntu@13.63.169.255',command);assert before['exit']==0 and before['stdout'].startswith(a.gateway_container+' true\n');save(stem+'-before.json',before)
probe=ssh('ubuntu@10.84.2.10','curl --noproxy "*" --connect-timeout 3 --max-time 5 --silent --show-error --output /dev/null --write-out "HTTP=%{http_code}\\n" "http://10.85.1.10:8080'+uri+'"',client_opts)
after=ssh('ubuntu@13.63.169.255',command);assert after['exit']==0
log=ssh('ubuntu@10.85.1.10','sudo -n journalctl -u tunnex-bgp-target.service --since @'+str(started)+' --no-pager -o cat',target_opts);assert log['exit']==0
matched=[line for line in log['stdout'].splitlines() if '10.84.2.10 - ' in line and '"GET '+uri+' HTTP/1.1" 200' in line]
passed=(probe['exit']==0 and 'HTTP=200' in probe['stdout'] and len(matched)==1) if a.expect=='allow' else (probe['exit']!=0 and not matched)
save(stem+'-result.json',{'probe':probe,'after':after,'target_log':log,'matched':matched,'passed':passed,'scope':'actual private VPN request; independently correlated target log; no echo-response claim','counter_review_required':True})
print(json.dumps({'nonce':nonce,'passed':passed,'target_matches':len(matched),'receipt':str(base/(stem+'-result.json'))}));assert passed
