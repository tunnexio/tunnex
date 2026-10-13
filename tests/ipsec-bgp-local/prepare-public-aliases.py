#!/usr/bin/env python3
"""Isolated virtual public endpoints; never sends packets to actual AWS peers."""
import json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parent;docker=[str(root/'docker-local.sh')];s=json.loads((root/'.runtime/integrated-topology.json').read_text())
subprocess.run([str(root/'ownership.py')],check=True)
def out(*args):return subprocess.check_output(docker+list(args),text=True).strip()
def run(cid,*args):return out('exec',cid,*args)
gateway=s['gateway_id'];peer=s['containers']['peer']
for role,cid in [('gateway',gateway),('peer',peer)]:
 m=json.loads(out('inspect',cid))[0];assert m['Id']==cid
 if role=='peer':assert m['Config']['Labels']['tunnex.bgp.integrated']==s['project']
for role,nid in s['networks'].items():
 n=json.loads(out('network','inspect',nid))[0];assert n['Id']==nid and n['Internal']and n['Labels']['tunnex.bgp.integrated']==s['project']
outer=s['project']+'-outer';gm=json.loads(out('inspect',gateway))[0];pm=json.loads(out('inspect',peer))[0]
assert gm['NetworkSettings']['Networks'][outer]['IPAddress']=='198.19.241.10'and pm['NetworkSettings']['Networks'][outer]['IPAddress']=='198.19.241.20'
# Product node's CP/default network is retained; public /32 traffic is forced onto
# this internal bridge with explicit sources. No host or Dockerdaemon changes.
run(gateway,'ip','address','replace','13.63.169.255/32','dev','eth1')
for public in ['13.50.7.159','51.20.220.141']:
 run(peer,'ip','address','replace',public+'/32','dev','eth0')
 run(gateway,'ip','route','replace',public+'/32','via','198.19.241.20','dev','eth1','src','13.63.169.255')
run(peer,'ip','route','replace','13.63.169.255/32','via','198.19.241.10','dev','eth0','src','13.50.7.159')
proof={'scope':'isolated virtual public simulation; separate from actual AWS VPN qualification','gateway_namespace':run(gateway,'readlink','/proc/self/ns/net'),'peer_namespace':run(peer,'readlink','/proc/self/ns/net'),'outer_network_id':s['networks']['outer'],'internal_bridge':True,'routes':{}}
for public in ['13.50.7.159','51.20.220.141']:
 r=json.loads(run(gateway,'ip','-j','-4','route','get',public));assert r[0]['dev']=='eth1'and r[0]['prefsrc']=='13.63.169.255'and r[0]['gateway']=='198.19.241.20';proof['routes'][public]=r
for public in ['13.50.7.159','51.20.220.141']:
 r=json.loads(run(peer,'ip','-j','-4','route','get','13.63.169.255','from',public));assert r[0]['dev']=='eth0'and r[0]['gateway']=='198.19.241.10';proof['routes']['reverse-from-'+public]=r
assert proof['gateway_namespace']!=proof['peer_namespace']
proof['activation_performed']=False;(root/'.runtime/integrated-public-aliases.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
