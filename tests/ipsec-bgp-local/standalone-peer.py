#!/usr/bin/env python3
"""Exact owned standalone simulator preparation and phases; never gateway authority."""
import argparse,hashlib,io,json,os,pathlib,subprocess,tarfile,time
os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--topology',type=pathlib.Path);p.add_argument('--peer-config',type=pathlib.Path);p.add_argument('--binary',type=pathlib.Path);p.add_argument('--binary-sha256');p.add_argument('phase',choices=['prepare','stage','initiate','serve']);a=p.parse_args();r=pathlib.Path(__file__).resolve().parent;rt=r/'.runtime';peerfile=a.peer_config or rt/'integrated-peer.json';s=json.loads((a.topology or rt/'integrated-topology.json').read_text());c=json.loads(peerfile.read_text());d=[str(r/'docker-local.sh')];cid=s['containers']['peer']
def run(*args,data=None):return subprocess.check_output(d+['exec']+(['-i']if data is not None else [])+[cid]+list(args),input=data)
m=json.loads(subprocess.check_output(d+['inspect',cid]))[0];assert m['Id']==cid and m['Config']['Labels']['tunnex.bgp.integrated']==s['project'] and m['State']['Running']
binary=(a.binary or rt/'bgp9-standalone-peer-arm64.test').read_bytes();expected=a.binary_sha256 or '0cee45c1092a4e22507c7fa1183e97bcc62d554c28bf24e7dc06cfae4aa2c03a';assert hashlib.sha256(binary).hexdigest()==expected
if a.topology or a.peer_config or a.binary:assert a.topology and a.peer_config and a.binary and a.binary_sha256 and s['project'] in ['tunnexs2sbgplimits1008','tunnexs2sbgpstatic1008'],'Independent fixture requires exact complete input ownership' 
if a.phase=='prepare':
 assert subprocess.run(d+['exec',cid,'test','-e','/run/standalone-peer.json'],stdout=subprocess.DEVNULL).returncode==1,'Existing private setup; refuse overwrite'
 run('mkdir','-m','700','/run/tunnex-ipsec')
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as t:
  for name,content,mode in [('standalone-peer.json',peerfile.read_bytes(),0o600),('standalone-peer.test',binary,0o700)]:
   e=tarfile.TarInfo(name);e.size=len(content);e.mode=mode;e.uid=e.gid=0;t.addfile(e,io.BytesIO(content))
 run('tar','-xf','-','-C','/run',data=stream.getvalue());run('mv','/run/standalone-peer.test','/test/standalone-peer.test')
 for f in c['Interfaces']:
  assert subprocess.run(d+['exec',cid,'ip','link','show','dev',f['name']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0,'Existing link refused'
  run('ip','link','add',f['name'],'type','xfrm','if_id',str(f['xfrm_id']));run('ip','link','set',f['name'],'addrgenmode','none');run('ip','link','set',f['name'],'alias',f['alias']);run('ip','addr','add',f['address'],'dev',f['name'],'noprefixroute');run('ip','link','set',f['name'],'mtu','1422','up');run('ip','route','add',f['remote_host_route'],'dev',f['name'],'proto',str(f['protocol']),'metric',str(f['metric']))
 conf=b'charon {\n load = random nonce openssl kdf kernel-netlink socket-default vici\n install_routes = no\n install_virtual_ip = no\n plugins {\n kernel-netlink { install_routes_xfrmi = no }\n vici { socket = unix:///run/tunnex-ipsec/charon.vici }\n }\n filelog { stderr { default = -1 } }\n}\n'
 run('sh','-ec','umask 077; cat > /run/tunnex-ipsec/strongswan.conf',data=conf)
 run('sh','-ec','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf /opt/tunnex-ipsec/libexec/ipsec/charon >/run/tunnex-ipsec/daemon.log 2>&1 & echo $! > /run/tunnex-ipsec/daemon.pid')
 for _ in range(30):
  if subprocess.run(d+['exec',cid,'test','-S','/run/tunnex-ipsec/charon.vici'],stdout=subprocess.DEVNULL).returncode==0:break
  time.sleep(.1)
 else:raise SystemExit('Owned peer charon socket absent')
 run('chmod','600','/run/tunnex-ipsec/charon.vici');print('Owned peer prepared; no gateway authority or provider enable')
else:
 args=['env','TUNNEX_BGP_STANDALONE_PEER_LAB=1','TUNNEX_BGP_STANDALONE_PEER_CONFIG=/run/standalone-peer.json','TUNNEX_BGP_STANDALONE_PEER_PHASE='+a.phase,'/test/standalone-peer.test','-test.run=^TestBGPStandalonePeerNative$','-test.v','-test.timeout=2h']
 if a.phase=='serve':
  run('sh','-ec','test ! -e /run/standalone-peer-serve.pid');subprocess.run(d+['exec','-d',cid,'sh','-ec',' '.join(args)+' >/run/standalone-peer-serve.log 2>&1 & echo $! >/run/standalone-peer-serve.pid; wait'],check=True);print('Owned peer serve launched; read exact private log for actual readiness')
 else:
  log=run(*args);peerfile.with_name(peerfile.stem+'-'+a.phase+'.log').write_bytes(log);print(log.decode())
