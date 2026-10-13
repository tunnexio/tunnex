#!/usr/bin/env python3
"""Source-only default. Publish nonsecret observation pins on bastion16, no SSH/probe."""
import argparse,json,os,pathlib
p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
pin={'root_reviewed':True,'gateway_id':'3b3ed48ebbb3684fbc1ee00b9cf3f940b9376040d512d96bb7f0be0b5a3b6bf2','namespace':'net:[4026532813]','image':'sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2','node_sha256':'987d9c0a0fa170e34ebbec5bc7fa4ab56b6fe0026bf2577e1e0542b605967f3e','node_path':'/binaries/tunnex-node','cert_sha256':'eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d','gate_expected':True,'gate_content':'owned enrolled restoration supervisor blocks Apply until genuine new namespace receipt durable\n','gate_identity':{'dev':66305,'inode':313296,'uid':0,'mode':384},'source_receipts':['13:/home/ubuntu/tunnex-bgp-lab/cloud-enrolled-restart-21169a9f-cycle4/preallocated.json','13:/home/ubuntu/tunnex-bgp-lab/cloud-enrolled-restart-21169a9f-cycle4/gate-published.json']}
if not a.execute:print(json.dumps({'source_only':True,'new':pin['gateway_id'],'namespace':pin['namespace'],'output':str(a.output),'nonsecret_observation_pins_only':True}));raise SystemExit
assert os.geteuid()!=0 and a.output.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008') and a.output.name=='cycle4-prerelease-pins.json';os.umask(0o077)
with a.output.open('x')as f:json.dump(pin,f,indent=2);f.flush();os.fsync(f.fileno())
fd=os.open(a.output.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'output':str(a.output),'mode':'0600','authority_created':False}))
