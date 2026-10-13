#!/usr/bin/env python3
"""Reviewed peer-only child-stop/deferred-cleanup; no product gateway operations."""
import argparse,datetime,hashlib,io,json,os,pathlib,subprocess,tarfile,time
os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--new-binary',type=pathlib.Path);p.add_argument('--expected-sha');a=p.parse_args();r=pathlib.Path(__file__).resolve().parent;rt=r/'.runtime';before=json.loads((rt/'integrated-peer-before-simulator-fix.json').read_text());d=[str(r/'docker-local.sh')];cid=before['container_id'];report=rt/'integrated-peer-simulator-stop.json';assert not report.exists(),'Retain original stop receipt'
def out(*args):return subprocess.check_output(d+['exec',cid]+list(args),text=True)
def stat(pid):
 q=subprocess.run(d+['exec',cid,'cat','/proc/'+pid+'/stat'],capture_output=True,text=True)
 return q.stdout if q.returncode==0 else None
def identity(text):
 fields=text.rsplit(')',1)[1].split();return {'ppid':fields[1],'start_ticks':fields[19]}
m=json.loads(subprocess.check_output(d+['inspect',cid]))[0];assert m['Id']==cid and m['State']['Running'] and m['Config']['Labels']['tunnex.bgp.integrated']=='tunnexs2sbgpintegrated1007';assert out('readlink','/proc/1/ns/net')==before['namespace']
for pid in ['9808','9814','9838','9843']:
 old=before['process_identities'][pid];current=stat(pid);assert current and identity(current)==identity(old['stat']),'Process changed'
 assert out('readlink','/proc/'+pid+'/exe')==old['exe'] and out('sha256sum','/proc/'+pid+'/exe').split()[0]==old['exe_sha256'],'Executable changed'
assert identity(stat('9843'))['ppid']=='9814' and before['process_identities']['9843']['exe'].strip()=='/opt/tunnex-bgp/bgpd'
oldroute=[x for x in before['routes']if x['dst']=='10.10.0.0/24'];currentroute=[x for x in json.loads(out('ip','-j','-4','route','show','table','main'))if x['dst']=='10.10.0.0/24'];assert currentroute==oldroute and len(oldroute)==1
newbytes=None
if a.new_binary:
 assert a.expected_sha and len(a.expected_sha)==64;newbytes=a.new_binary.read_bytes();assert hashlib.sha256(newbytes).hexdigest()==a.expected_sha
 assert subprocess.run(d+['exec',cid,'test','-e','/test/standalone-peer-fixed.test'],stdout=subprocess.DEVNULL).returncode==1,'Do not overwrite new binary'
if not a.execute:print('Exact peer process/namespace/route read-only preflight verified; no signal or install');raise SystemExit(0)
proof={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'container_id':cid,'namespace':before['namespace'],'known_bgpd_pid':9843,'known_test_pid':9814,'old_binary_sha256':before['binary_sha256'],'before_receipt_sha256':hashlib.sha256((rt/'integrated-peer-before-simulator-fix.json').read_bytes()).hexdigest(),'cleanup_complete':False,'gateway_modified':False}
# Signal only the independently inspected exact known child. The old Go test
# observes managed-child death and runs its own refusal/route/process defers.
report.write_text(json.dumps(proof,indent=2)+'\n')
out('kill','-TERM','9843')
for _ in range(150):
 remaining=[]
 for pid in ['9808','9814','9838','9843']:
  current=stat(pid)
  if current:
   assert identity(current)==identity(before['process_identities'][pid]['stat']),'PID reused; refuse adoption';remaining.append(pid)
 if not remaining:break
 time.sleep(.2)
else:raise SystemExit('Old exact peer processes not absent; stop and retain evidence')
assert out('readlink','/proc/1/ns/net')==before['namespace']
routes=json.loads(out('ip','-j','-4','route','show','table','main'));assert not any(x['dst']=='10.10.0.0/24'for x in routes),'Owned return route retained or foreign replacement'
nft=json.loads(out('nft','-j','list','table','inet','tunnex_ipsec'));assert not any('18080'in json.dumps(o.get('rule',{}))for o in nft['nftables']),'Simulator forwarding permission retained'
def protected_drop(chain):
 for obj in nft['nftables']:
  rule=obj.get('rule',{})
  if rule.get('chain')!=chain:continue
  drop=any('drop' in expr for expr in rule.get('expr',[]))
  match=any(expr.get('match')=={'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':{'prefix':{'addr':'10.10.0.0','len':24}}} for expr in rule.get('expr',[]))
  if drop and match:return True
 return False
assert all(protected_drop(chain) for chain in ['forward_guard','postrouting_guard']),'Exact protected-prefix denial absent'
(rt/'integrated-peer-old-final-nft.json').write_text(json.dumps(nft,indent=2)+'\n')
files=out('find','/run/tunnex-bgp-peer','-mindepth','1','-maxdepth','1','-print');assert not files.strip(),'Peer process directory not empty; refuse foreign cleanup'
log=out('cat','/run/standalone-peer-serve.log');assert 'peer daemon stopped' in log and not any(text in log for text in ['cleanup refused','denial failed','cleanup failed','absence failed']),'Old owned cleanup log failed';(rt/'integrated-peer-old-serve-final.log').write_text(log);proof.update(cleanup_complete=True,processes_absent=['9808','9814','9838','9843'],return_route_absent=True,application_permission_absent=True,private_bgp_directory_empty=True,exact_protected_prefix_denial=True,final_nft_sha256=hashlib.sha256((rt/'integrated-peer-old-final-nft.json').read_bytes()).hexdigest(),old_log_sha256=hashlib.sha256(log.encode()).hexdigest())
if newbytes:
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as t:
  e=tarfile.TarInfo('standalone-peer-fixed.test');e.mode=0o700;e.size=len(newbytes);t.addfile(e,io.BytesIO(newbytes))
 subprocess.run(d+['exec','-i',cid,'tar','-xf','-','-C','/test'],input=stream.getvalue(),check=True);assert out('sha256sum','/test/standalone-peer-fixed.test').split()[0]==a.expected_sha;proof['new_binary_sha256']=a.expected_sha;proof['new_binary_path']='/test/standalone-peer-fixed.test';proof['new_process_launched']=False
report.write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
