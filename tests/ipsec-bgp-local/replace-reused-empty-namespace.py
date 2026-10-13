"""Replace only an empty owned namespace conservatively rejected for inode reuse."""
import json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parent;evidence=root/'evidence';project='tunnexs2sbgptransport1007';label='tunnex.bgp.transport'
def command(args):return subprocess.check_output(['docker']+args,stderr=subprocess.STDOUT)
old=json.loads(command(['inspect',project+'-restoration']))[0];snapshot=json.loads((evidence/'snapshot.json').read_text())
assert old['Config']['Labels'][label]==project and old['Config']['Labels']['com.docker.compose.project']==project
assert command(['exec',old['Id'],'readlink','/proc/self/ns/net']).decode().strip()=='net:['+str(snapshot['namespace']['inode'])+']'
assert not command(['exec',old['Id'],'find','/run','-name','charon.vici']).strip()
assert all(link.get('linkinfo',{}).get('info_kind')!='xfrm' for link in json.loads(command(['exec',old['Id'],'ip','-j','link','show'])))
assert not command(['exec',old['Id'],'find','/test','-type','f']).strip()
mount=[m for m in old['Mounts'] if m['Destination']=='/state'];assert len(mount)==1 and mount[0]['Source']==snapshot['state_mount']['source']
journal=pathlib.Path(mount[0]['Source'])/'ipsec/journal.json';assert journal.read_bytes()==(evidence/'stopped-journal.json').read_bytes()
networks=list(old['NetworkSettings']['Networks']);assert len(networks)==1
newname=project+'-restoration-distinct'
assert subprocess.run(['docker','inspect',newname],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
new=command(['create','--name',newname,'--label',label+'='+project,'--label','com.docker.compose.project='+project,'--network',networks[0],'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','NET_BIND_SERVICE','--cap-add','SETUID','--cap-add','SETGID','--read-only','--tmpfs','/run:rw,nosuid,nodev,size=8m','--tmpfs','/test:rw,exec,nosuid,nodev,size=32m','--tmpfs','/var/tmp/frr:rw,nosuid,nodev,size=8m','--security-opt','no-new-privileges','--mount','type=volume,source='+mount[0]['Name']+',target=/state','--entrypoint','/bin/sh',old['Image'],'-c','sleep 3600']).decode().strip()
command(['start',new]);ns=command(['exec',new,'readlink','/proc/self/ns/net']).decode().strip();assert ns!='net:['+str(snapshot['namespace']['inode'])+']'
command(['rm','-f',old['Id']]);command(['rename',new,project+'-restoration'])
assert journal.read_bytes()==(evidence/'stopped-journal.json').read_bytes()
(evidence/'inode-reuse-refusal.json').write_text(json.dumps({'old_inode':snapshot['namespace']['inode'],'reused_empty_container_removed':old['Id'],'distinct_empty_container':new,'new_namespace':ns,'journal_unchanged':True,'serving_mutation':False},indent=2)+'\n')
print('Conservative inode reuse refusal preserved; second empty owned namespace is distinct.')
