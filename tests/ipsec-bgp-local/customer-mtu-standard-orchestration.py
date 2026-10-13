#!/usr/bin/env python3
"""LOCAL source-only command plan. Does not execute SSH, AWS or API mutations.
The reviewed operator executes one stage at a time, records each result, and
never repeats an unknown mutation without the corresponding read-only census.
"""
import argparse,hashlib,json,pathlib,re,secrets,shlex
CLIENT='10.84.2.10';TARGET='10.85.1.10'
CID_RE=re.compile(r'[0-9a-f]{64}')
def plan(cid,namespace,nonce):
 assert CID_RE.fullmatch(cid) and re.fullmatch(r'net:\[402653[0-9]+\]',namespace) and CID_RE.fullmatch(nonce)
 directory='/var/tmp/tunnex-customer-8081-'+nonce
 comment='tnx-mtu-8081-'+nonce
 rules=[['-i','enp39s0','-o','tnxbgplab0','-s',CLIENT+'/32','-d',TARGET+'/32','-p','tcp','--dport','8081','-m','comment','--comment',comment+'-out','-j','ACCEPT'],['-i','tnxbgplab0','-o','enp39s0','-s',TARGET+'/32','-d',CLIENT+'/32','-p','tcp','--sport','8081','-m','conntrack','--ctstate','ESTABLISHED','-m','comment','--comment',comment+'-reply','-j','ACCEPT']]
 # Host destination85/16 goes towards Docker; reply to client exits physical.
 rules[0][1],rules[0][3]='enp39s0','tnxbgplab0'
 identity={'gateway_container':cid,'namespace':namespace,'node_sha256':'b85a470bfa46fb8d03487381c58d1be004aa5adc3fad6a1e50d9a575b72e6d76','client_instance':'i-0cc22d71958707b0d','target_instance':'i-0cd8ee7ba1e099092','client_ip':CLIENT,'target_ip':TARGET,'preserved_target_main_pid':1353}
 command=lambda xs:shlex.join(xs)
 fixture="umask 077; mkdir -m 700 -- "+shlex.quote(directory)+" && dd if=/dev/urandom of="+shlex.quote(directory+'/send.bin')+" bs=1048576 count=4 status=none && stat -c '%s %u %a %i' "+shlex.quote(directory+'/send.bin')+" && sha256sum "+shlex.quote(directory+'/send.bin')
 target="timeout --signal=TERM --kill-after=2s 45s nc -N -l "+TARGET+" 8081 < "+directory+"/send.bin > "+directory+"/received.bin"
 client="timeout --signal=TERM --kill-after=2s 45s nc -N -s "+CLIENT+" "+TARGET+" 8081 < "+directory+"/send.bin > "+directory+"/received.bin"
 # 128MiB at64KiB/sec produces a single ~2048s socket. Existing pv is optional;
 # standard dd emits one64KiB record persecond, with recorded producer status.
 paced="timeout --signal=TERM --kill-after=2s 2100s sh -c "+shlex.quote("i=0; while [ \"$i\" -lt 2048 ]; do dd if="+directory+"/send.bin bs=65536 count=1 status=none || exit; i=$((i+1)); sleep 1; done")
 stream_target="timeout --signal=TERM --kill-after=2s 2110s nc -N -l "+TARGET+" 8081 > "+directory+"/stream-received.bin"
 stream_client=paced+" | timeout --signal=TERM --kill-after=2s 2110s nc -N -s "+CLIENT+" "+TARGET+" 8081 > "+directory+"/stream-client-output.bin"
 return {'source_only':True,'identity':identity,'nonce':nonce,'directory':directory,'authority':'normal customer-mtu-access-normal-v2.py resource/grant; no fake permit or DB write','aws_cli_location':'ubuntu@16.170.207.192 only','stages':[
 {'name':'readonly-baseline','required':['actual gateway node/ns/cert/API identity','source-bound routeGET on client and host','currentDOCKER-USER fullrules','actualtargetSGs/8080/1353exe/start/service','target/client nc -h supportsOpenBSD-N','currentprovider enabledrev2/delivery44 and exactfresh8081normalgrant absent','headers-only observer and ownedCHILD/NFT counters'], 'no_mutation':True},
 {'name':'fixture','target_standard_command':fixture,'client_standard_command':fixture,'intent':'O_EXCL local endpoint-intents BEFORE commands; if unknown outcome stat exactdir/files/nonce instead of repeat mkdir/dd','preserve':'no existing path overwrite/service change'},
 {'name':'narrow-infra','target_sg':'sg-0c90b1ec6f9eb24ff','aws_permissions':[{'IpProtocol':'tcp','FromPort':8081,'ToPort':8081,'IpRanges':[{'CidrIp':CLIENT+'/32','Description':comment}]}],'gateway_rules':rules,'rule_add':[command(['iptables','-I','DOCKER-USER','1',*r])for r in rules],'rule_read':[command(['iptables','-C','DOCKER-USER',*r])for r in rules],'intent':'persist exactSGrequest+currentgroups+fullforeignrules+tuple obligations O_EXCL before eachadd; reconcile unknown usingexact AWS security-group-rule census/iptables-S, never blind replay'},
 {'name':'normal-authority','commands':['resource','grant'],'helper':'customer-mtu-access-normal-v2.py','require':'readnormal policy compiled exactclient32/TCP8081; provider/revision unchanged; waitactual lease+ownedCHILD+route convergence'},
 {'name':'full-duplex','target_standard_command':target,'client_standard_command':client,'before_client':'actual bound85.1.10:8081 listener PID/start/exe/cmdline; target independent management control1353 unchanged','require':'both exit0, eachreceived4194304, opposite send/receiveSHAequal, actual encryptedcountersdelta andselectedroute; recordduration'},
 {'name':'paced-existing-stream','target_standard_command':stream_target,'client_standard_command':stream_client,'require':'one socket source-port tuple beforefault and afterrecovery; no nc reconnection/relaunch; bytes/hash/producers exit individually captured; headersSYN/SYNACK only; approvedfaultseparate','limitation':'shellpipeline exit alone cannot prove producer success; capture producer status separately; repeated64KiB fixture is transfer-integrity test not random128MiB entropy'},
 {'name':'cleanup','normal_commands':['withdraw','cleanup-resource'],'rule_delete':[command(['iptables','-D','DOCKER-USER',*r])for r in rules],'sg_delete':'ONLY recorded freshSecurityGroupRuleId after fulltuple/source/group identity readback','require':'listener alreadyexited or terminateONLYrecordedexactPID/start/exe; noPID1353signal; guardfreshdenial afterwithdraw; foreignrules/resources/SGs/routes/provider/cert/licence equal; preservefiles/evidence','unknown_outcome':'GET/census existing exclusive intent; never repeat APIcreate/delete or unrelatedrules'}],
 'mtu_evidence':'record actualphysical/XFRM/selectedrouteMTU andfixedCBC256/SHA256/NATT; headers-only SYN/SYNACK MSS+IPv4DF, no payloadPCAP; doesnotqualifyICMPecho/PMTUD or lower1300 until separatelyauthorized test',
 'ssh_routes':'LOCAL→16; keyremains16; client through13ProxyCommand; targetEIC independent management'}
def main():
 p=argparse.ArgumentParser();p.add_argument('--gateway',required=True);p.add_argument('--namespace',required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--nonce');a=p.parse_args()
 value=plan(a.gateway,a.namespace,a.nonce or secrets.token_hex(32));value['orchestrator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
 with a.out.open('x')as f:json.dump(value,f,indent=2);f.write('\n')
 print(json.dumps({'source_only':True,'plan':str(a.out),'nonce':value['nonce'],'runtime_actions':False}))
if __name__=='__main__':main()
