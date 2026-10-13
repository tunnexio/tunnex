#!/usr/bin/env python3
"""Capture enrollment/volume identity, or explicitly rebind an accepted replacement."""
import argparse,hashlib,json,pathlib,subprocess,datetime,os
os.umask(0o077)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['capture','rebind']);p.add_argument('--expected-image');p.add_argument('--baseline',default='gateway-before-refresh.json');p.add_argument('--receipt',default='gateway-after-refresh.json');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parent;docker=[str(root/'docker-local.sh')];assert all(pathlib.Path(name).name==name and name.endswith('.json') for name in (a.baseline,a.receipt))
proof=root/'.runtime'/a.baseline;receipt=root/'.runtime'/a.receipt
subprocess.run([str(root/'ownership.py')],check=True)
def out(*args):return subprocess.check_output(docker+list(args),text=True).strip()
gw=json.loads(out('inspect','tunnexs2sbgplocal1007-gateway-1'))[0]
assert gw['Config']['Labels']['com.docker.compose.project.working_dir']==str(root)
mount=next(m for m in gw['Mounts']if m['Destination']=='/state');assert mount['Type']=='volume'
volume=json.loads(out('volume','inspect',mount['Name']))[0]
identity=json.loads(out('exec','tunnexs2sbgplocal1007-postgres-1','psql','-U','bgplocal','-d','bgplocal','-At','-c',"select json_build_object('id',id,'org_id',org_id,'cert_serial',cert_serial,'cert_key_fingerprint',cert_key_fingerprint,'cert_not_after',cert_not_after,'status',status,'heartbeat_fresh',last_seen_at>now()-interval '90 seconds','cert_live',cert_not_after>now()) from nodes where name='bgp-local-gateway';"))
assert identity['status']=='active'and identity['heartbeat_fresh']and identity['cert_live']
config={'entrypoint':gw['Config']['Entrypoint'],'cmd':gw['Config']['Cmd'],'tunnex_env':sorted(e for e in gw['Config']['Env']if e.startswith('TUNNEX_')),'mounts':gw['Mounts'],'cap_add':gw['HostConfig']['CapAdd'],'devices':gw['HostConfig']['Devices'],'sysctls':gw['HostConfig']['Sysctls'],'ports':gw['HostConfig']['PortBindings']}
# Keep private join token out of even the private evidence projection.
config['tunnex_env']=[hashlib.sha256(e.encode()).hexdigest()if e.startswith('TUNNEX_JOIN_TOKEN=')else e for e in config['tunnex_env']]
def canonical_config(value):
 # Docker inspect mount-array order is not runtime identity. Compare every
 # complete mount object, retaining source/volume/destination/type/mode fields.
 mounts=value['mounts'];assert len({m['Destination'] for m in mounts})==len(mounts),'Ambiguous mount destinations'
 return {**value,'mounts':sorted(mounts,key=lambda m:m['Destination'])}
config=canonical_config(config)
stable={k:v for k,v in identity.items()if k not in ['heartbeat_fresh','cert_live']}
current={'container_id':gw['Id'],'image':gw['Image'],'volume':volume,'node':stable,'config':config,'actual_executable_sha256':out('exec',gw['Id'],'sha256sum','/proc/1/exe').split()[0],'mounted_binary_sha256':out('exec',gw['Id'],'sha256sum','/binaries/tunnex-node').split()[0],'namespace':out('exec',gw['Id'],'readlink','/proc/1/ns/net'),'captured_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
if a.action=='capture':
 assert not proof.exists(),'Original proof already retained; refuse overwrite';proof.write_text(json.dumps(current,indent=2)+'\n');print('Captured exact gateway enrollment, state volume, image and fresh heartbeat; no mutation')
else:
 assert a.expected_image and a.expected_image.startswith('sha256:')and gw['Image']==a.expected_image,'Replacement image must be explicitly accepted exact digest'
 before=json.loads(proof.read_text());assert before['container_id']!=current['container_id'],'No replacement to rebind'
 assert before['volume']==current['volume']and before['node']==current['node']and canonical_config(before['config'])==current['config'],'Enrollment, volume, certificate or runtime configuration differs'
 assert subprocess.run(docker+['inspect',before['container_id']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0,'Old gateway still exists'
 assert not receipt.exists(),'Replacement receipt already retained; refuse overwrite'
 marker=root/'.runtime/integrated-topology.json';state=json.loads(marker.read_text());assert state['gateway_id']==before['container_id']
 state['gateway_id']=current['container_id'];marker.write_text(json.dumps(state,indent=2)+'\n')
 receipt.write_text(json.dumps(current,indent=2)+'\n')
 print('Explicit accepted image rebind proven; same state volume/enrollment/certificate/config; reconnect owned topology separately')
