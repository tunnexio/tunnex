#!/usr/bin/env python3
"""Review-only default: fresh sleeping enrolled namespace, no worker startup."""
import argparse,hashlib,json,os,pathlib,subprocess,copy,http.client,socket,urllib.parse
os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--run-directory',type=pathlib.Path);p.add_argument('--execute',action='store_true');p.add_argument('--image',required=True);a=p.parse_args();r=pathlib.Path(__file__).resolve().parent;shared=r/'.runtime';from enrolled_approval import reviewed_run;rt,approval,run_index=reviewed_run(shared,a.run_directory)
d=[str(r/'docker-local.sh')];assert a.image==approval.get('image','sha256:22fe75e15381e4988b9b81f34474222b1117905563850c5f5ff8dd146a02f834');x=json.loads((rt/'enrolled-restoration-before-layout-v3.json').read_text());old=x['container_id'];assert old==approval.get('old_container_id',old);name='tunnexs2sbgplocal1007-gateway-restoration'+('-'+str(run_index)if approval else '');staging='tunnexs2sbgplocal1007-restoration-staging'+('-'+str(run_index)if approval else '');receipt=rt/'enrolled-preallocation.json'
def out(*args):return subprocess.check_output(d+list(args),text=True)
g=json.loads(out('inspect',old))[0];assert g['Id']==old and g['State']['Running'] and g['Image']==x['image'];assert g['HostConfig']==x['host_config']and sorted(g['Mounts'],key=lambda m:m['Destination'])==sorted(x['all_mounts'],key=lambda m:m['Destination']);assert hashlib.sha256(json.dumps(sorted(g['Config']['Env'])).encode()).hexdigest()==x['environment_equality_sha256'];assert g['Config']['Entrypoint']==['/bin/sh','-ec']and len(g['Config']['Cmd'])==1;assert not receipt.exists()
if run_index==3:assert g['Image']=='sha256:84c9dfdffbe27cc5a6992bceb2863d3b045d2fbdaf6b3339a7d7a5cdffba5c98' and x['actual_executable_sha256']=='d8d9ad44e704ccdeee876c8f76923feac9daa335724dab4a5fc4e9b0149775fb','Unreviewed old serving image/binary'
if run_index==4:assert g['Image']=='sha256:e789c8c86054e7b2507e7f00da1c13d4498725b47fc7f8158f7f7102e5ec435e'and x['actual_executable_sha256']=='a14d312802d64be51ab6c06193fd6dc4c7583b79977653ca2eac44197867100e'and x['namespace']=='net:[4026532931]','Unreviewed run4 old runtime'
assert subprocess.run(d+['inspect',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0,'Replacement name collision'
accepted_image=json.loads(out('image','inspect',a.image))[0];assert accepted_image['Architecture']=='arm64'
binary_name=approval.get('binary_name','tunnex-node-bgp9-cleanup-checkpoint');assert pathlib.Path(binary_name).name==binary_name;newpath='/binaries/'+binary_name;newbin=shared/'bin'/binary_name;newsha=approval.get('binary_sha256','f5813d090fdb37474fa7de47cd9e030ae0230c7b2794927e12232c78aa493f69');assert hashlib.sha256(newbin.read_bytes()).hexdigest()==newsha
oldpath=approval.get('old_binary_path','/binaries/tunnex-node');command=g['Config']['Cmd'][0];barrier='while [ ! -f /run/enrolled-restoration-release ]; do sleep 1; done; ';assert command.count(oldpath)==1
if approval:assert command.startswith(barrier)and command.count(barrier)==1;command=command[len(barrier):]
accepted_command=command.replace(oldpath,newpath)
wrapper='while [ ! -f /run/enrolled-restoration-release ]; do sleep 1; done; '+accepted_command
plan={'old_container_id':old,'old_namespace':x['namespace'],'new_name':name,'image':a.image,'network_mode':staging,'staging_network_name':staging,'health_port':19293+run_index if approval else 19294,'entrypoint':g['Config']['Entrypoint'],'gated_cmd':[wrapper],'same_volume_node_certificate_environment':True,'old_networks_attached_before_stop':False,'mounted_node_path':newpath,'mounted_node_sha256':newsha,'worker_started':False,'journal_written':False}
if not a.execute:print(json.dumps(plan,indent=2));raise SystemExit(0)
assert subprocess.run(d+['network','inspect',staging],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0,'Staging network collision'
staging_id=out('network','create','--internal','--label','tunnex.bgp.enrolled.restoration=story9-staging',staging).strip();plan['staging_network_id']=staging_id
newbin.chmod(0o700)
# Docker Engine API preserves exact array-form Healthcheck/Entrypoint and all
# observed resource/security defaults. Only the explicitly reviewed fields
# differ; plaintext environment stays in memory, never in diagnostics.
endpoint=json.loads(out('context','inspect'))[0]['Endpoints']['docker']['Host'];assert endpoint.startswith('unix:///')
class UnixHTTP(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(20);self.sock.connect(endpoint[len('unix://'):])
config=copy.deepcopy(g['Config']);config['Hostname']='';config['Image']=a.image;config['Cmd']=[wrapper];config['Entrypoint']=g['Config']['Entrypoint'];config['Labels']={**(accepted_image['Config'].get('Labels')or{}),**(g['Config'].get('Labels')or{}),'tunnex.bgp.enrolled.restoration':'story9-actual'}
host=copy.deepcopy(g['HostConfig']);host['NetworkMode']=staging;host['PortBindings']={'9091/tcp':[{'HostIp':'127.0.0.1','HostPort':str(19293+run_index)if approval else '19294'}]};body={**config,'HostConfig':host}
conn=UnixHTTP('localhost');conn.request('POST','/containers/create?'+urllib.parse.urlencode({'name':name}),body=json.dumps(body),headers={'Content-Type':'application/json'});response=conn.getresponse();result=json.loads(response.read());conn.close();assert response.status==201,'Docker Engine create refused (body suppressed)'
new=result['Id'];plan['new_container_id']=new;plan['expected_config_sha256']=hashlib.sha256(json.dumps({**config,'Env':sorted(config['Env'])},sort_keys=True).encode()).hexdigest();plan['expected_host_config']=host;receipt.write_text(json.dumps(plan,indent=2)+'\n');out('start',new)
m=json.loads(out('inspect',new))[0];assert m['Id']==new and m['Config']['Cmd']==[wrapper]and m['Config']['Entrypoint']==g['Config']['Entrypoint'];assert sorted(m['Mounts'],key=lambda m:m['Destination'])==sorted(g['Mounts'],key=lambda m:m['Destination']);assert sorted(m['Config']['Env'])==sorted(g['Config']['Env']),'Environment differs'
# Docker assigns hostname and may canonicalize Image/Labels; every remaining
# observed config/HostConfig field is compared, not inferred from CLI defaults.
for key,value in config.items():
 if key in ('Hostname','Image','Env'):continue
 assert m['Config'].get(key)==value,'New config differs: '+key
for key,value in host.items():assert m['HostConfig'].get(key)==value,'New HostConfig differs: '+key
assert set(m['NetworkSettings']['Networks'])=={staging} and m['NetworkSettings']['Networks'][staging]['NetworkID']==staging_id
ns=out('exec',new,'readlink','/proc/1/ns/net').strip();assert ns!=x['namespace'],'Fresh namespace must be distinct while old alive';assert all(name not in out('exec',new,'ps','-eo','comm').splitlines()for name in ['tunnex-node','charon','bgpd','zebra']);assert out('exec',new,'ip','xfrm','state').strip()==''
assert subprocess.run(d+['exec',new,'test','-e','/run/enrolled-restoration-release'],stdout=subprocess.DEVNULL).returncode==1
raw=out('exec',new,'sha256sum','/state/ipsec/journal.json').split()[0];assert raw==x['journal_sha256'],'Shared journal changed; refuse next phase'
plan.update(new_namespace=ns,actual_new_config=m['Config']['Cmd'],actual_hostname=m['Config']['Hostname'],preallocation_complete=True,environment_equality_sha256=x['environment_equality_sha256'],all_mounts=m['Mounts'],actual_config_without_env={k:v for k,v in m['Config'].items()if k!='Env'});receipt.write_text(json.dumps(plan,indent=2)+'\n');print('Fresh distinct sleeping namespace captured; exact metadata preserved; no worker or journal writes')
