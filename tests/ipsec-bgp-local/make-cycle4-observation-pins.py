#!/usr/bin/env python3
"""Local/offline pin assembly from genuine cycle4 receipts. No authority or cloud actions."""
import argparse,json,pathlib,os,stat,hashlib
p=argparse.ArgumentParser();p.add_argument('--preallocated',type=pathlib.Path,required=True);p.add_argument('--gate-published',type=pathlib.Path,required=True);p.add_argument('--gate-content',type=pathlib.Path,required=True);p.add_argument('--output-directory',type=pathlib.Path,required=True);p.add_argument('--root-reviewed',action='store_true');a=p.parse_args()
pre=json.loads(a.preallocated.read_text());gate=json.loads(a.gate_published.read_text());cid=pre['new'];ns=pre['namespace'];assert len(cid)==64 and all(c in '0123456789abcdef'for c in cid) and not cid.startswith('0faef89') and ns not in ['net:[4026532946]','net:[4026532807]']
identity=gate['identity'];assert identity['uid']==0 and identity['mode']==0o600 and identity['device']>0 and identity['inode']>0
content=a.gate_content.read_text();assert content=='owned enrolled restoration supervisor blocks Apply until genuine new namespace receipt durable\n'
base={'root_reviewed':a.root_reviewed,'gateway_id':cid,'namespace':ns,'node_sha256':'987d9c0a0fa170e34ebbec5bc7fa4ab56b6fe0026bf2577e1e0542b605967f3e','image':'sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2','cert_sha256':'eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d','input_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in [a.preallocated,a.gate_published,a.gate_content]}}
os.umask(0o077);a.output_directory.mkdir(mode=0o700)
outputs={'continuous-pins.json':base,'wire-pins.json':dict(base,run_name='vgw-wire-failover-peer2-cycle4-'+cid[:12]),'prerelease-pins.json':dict(base,gate_expected=True,node_path='/binaries/tunnex-node',gate_content=content,gate_identity={'dev':identity['device'],'inode':identity['inode'],'uid':0,'mode':384})}
for name,obj in outputs.items():
 with (a.output_directory/name).open('x')as f:json.dump(obj,f,indent=2);f.flush();os.fsync(f.fileno())
fd=os.open(a.output_directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'output_directory':str(a.output_directory),'reviewed':a.root_reviewed,'pins_are_observation_only':True}))
