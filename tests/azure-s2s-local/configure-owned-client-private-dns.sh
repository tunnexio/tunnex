#!/usr/bin/env bash
# Owned qualification fixture only; preserves the host resolver and existing authority.
set -euo pipefail
[[ $(hostname) == tunnex-peer ]]
[[ $(sudo docker inspect -f '{{.Id}}' tunnex-azure-cloud-gateway) == 6cac022f7c21e144757c0679d998333d7d4fe952a734bdc802ff5a38b3416624 ]]
[[ $(sudo docker inspect -f '{{index .Config.Labels "tunnex.owner"}}' tunnex-azure-cloud-netns) == azure-s2s-01a12505 ]]
sudo python3 - <<'P'
from pathlib import Path
import hashlib,os,json,subprocess
host=Path('/etc/resolv.conf'); before=hashlib.sha256(host.read_bytes()).hexdigest()
rows=json.loads(subprocess.check_output(['ip','-n','azure-s2s-client','-j','address','show','dev','az-s2s-client']))
assert any(a.get('local')=='10.233.10.2' and a.get('prefixlen')==24 for r in rows for a in r.get('addr_info',[]))
p=Path('/etc/netns/azure-s2s-client/resolv.conf')
for parent in (Path('/etc/netns'),p.parent):
 assert not parent.is_symlink()
 if not parent.exists():parent.mkdir(mode=0o755)
 assert parent.is_dir() and parent.stat().st_uid==0
assert not p.exists() and not p.is_symlink()
fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o644)
with os.fdopen(fd,'w') as f:f.write('nameserver 10.231.2.4\nnameserver 10.231.2.20\noptions timeout:1 attempts:1\n');f.flush();os.fsync(f.fileno())
assert hashlib.sha256(host.read_bytes()).hexdigest()==before
print(json.dumps({'owned_namespace_resolver_configured':True,'host_resolver_unchanged':True,'nameservers':['10.231.2.4','10.231.2.20'],'scope':'Fixed owned LB client DNS fixture only; no suffix-isolation or product DNS proxy claim'}))
P
sudo ip netns exec azure-s2s-client python3 - <<'P'
import socket,json
answers={x[4][0] for x in socket.getaddrinfo('lbapp.azure-s2s.test',8080,0,socket.SOCK_STREAM)}
assert answers=={'10.231.1.10'}
print(json.dumps({'actual_libc_dns_expected_vip':True}))
P
