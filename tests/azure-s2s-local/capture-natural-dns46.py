#!/usr/bin/env python3
"""Read-only natural DNS capture. Requires an independently reviewed private attestation.
No DNS probes, firewall edits, daemon commands, or authority claims are made.
"""
import argparse, datetime, hashlib, ipaddress, json, os, pathlib, re, signal, socket, struct, subprocess, threading, time
CID='6c7ce0e29e7a6f9f8756b2a19eb2074fa39b3da891802197b770ff9f822c3233'
IMAGE='sha256:2e2cd11f550d944af6052d1bddbb4c8e0a4252b7e73349497a487c83ad784361'
NODE='6022368cd6fb2b0483244021d7194a28dd2305f4a5ab2932b5b16fd882233dd9'
SOURCE='10.233.10.1'; ENDPOINTS={'10.231.2.4','10.231.2.20'}
PAIRS=sorted((v,p) for v in ENDPOINTS for p in ('tcp','udp'))

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def stamp(value): return datetime.datetime.fromisoformat(re.sub(r'(\.\d{6})\d+',r'\1',value).replace('Z','+00:00')).timestamp()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def command(args,timeout=10): return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout).stdout

def private(path,limit=8<<20):
 p=pathlib.Path(path)
 if not p.is_absolute() or str(p.resolve())!=str(p): raise ValueError('private_path')
 for parent in (p.parent,*p.parents):
  st=parent.stat()
  if st.st_uid!=0 or st.st_mode&0o022: raise ValueError('private_parent')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if st.st_uid!=0 or st.st_mode&0o777!=0o600 or st.st_size>limit: raise ValueError('private_file')
  with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(limit+1)
  if len(raw)>limit: raise ValueError('private_bound')
  return raw
 finally: os.close(fd)

def live_journal(path, device, inode):
 # Ubuntu ownership is explicitly tolerated ancestry, not protected ancestry.
 p=pathlib.Path(path)
 if not p.is_absolute() or str(p)!=os.path.normpath(str(p)): raise ValueError('live_path')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  walked=''
  for part in p.parts[1:-1]:
   walked+='/'+part
   next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   os.close(fd);fd=next_fd;st=os.fstat(fd)
   ubuntu=walked=='/home/ubuntu' or walked.startswith('/home/ubuntu/')
   if st.st_uid not in ({0,1000} if ubuntu else {0}) or st.st_mode&0o022: raise ValueError('live_ancestry')
  file_fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
  try:
   st=os.fstat(file_fd)
   if st.st_uid!=0 or st.st_mode&0o777!=0o600 or (st.st_dev,st.st_ino)!=(device,inode) or st.st_size>8<<20: raise ValueError('live_file')
   with os.fdopen(file_fd,'rb',closefd=False) as stream: raw=stream.read((8<<20)+1)
   if len(raw)>8<<20: raise ValueError('live_bound')
   return raw
  finally: os.close(file_fd)
 finally: os.close(fd)

def capture_health(log,returncode):
 captured=re.findall(rb'(?m)^(\d+) packets captured$',log)
 received=re.findall(rb'(?m)^(\d+) packets received by filter$',log)
 dropped=re.findall(rb'(?m)^(\d+) packets dropped by kernel$',log)
 if returncode!=0 or any(len(v)!=1 for v in (captured,received,dropped)): raise ValueError('capture_counters')
 return {'captured':int(captured[0]),'received':int(received[0]),'dropped':int(dropped[0])}

def save(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())

def identity():
 v=json.loads(command(['docker','inspect',CID]))[0]
 if v['Id']!=CID or v['Image']!=IMAGE or v['Name']!='/tunnex-azure-cloud-gateway' or v['Config']['Labels'].get('tunnex.owner')!='azure-s2s-01a12505' or not v['State']['Running']: raise ValueError('container_identity')
 pid=v['State']['Pid']
 if sha(pathlib.Path(f'/proc/{pid}/exe').read_bytes())!=NODE: raise ValueError('node_identity')
 ns=os.stat(f'/proc/{pid}/ns/net')
 return (pid,v['State']['StartedAt'],ns.st_dev,ns.st_ino)

def packets(raw):
 """Bounded classic PCAP reader; returns only private IPv4 transport header records."""
 if len(raw)<24: raise ValueError('pcap_header')
 magic=raw[:4]
 formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
 if magic not in formats: raise ValueError('pcap_format')
 endian,scale=formats[magic];link=struct.unpack(endian+'I',raw[20:24])[0];pos=24;out=[]
 while pos<len(raw):
  if pos+16>len(raw): raise ValueError('pcap_trailing')
  sec,fraction,size,_=struct.unpack(endian+'IIII',raw[pos:pos+16]);pos+=16
  if size>65535 or pos+size>len(raw): raise ValueError('pcap_record')
  data=raw[pos:pos+size];pos+=size
  offset={1:14,101:0,228:0,113:16,276:20}.get(link)
  if offset is None: raise ValueError('pcap_link')
  if link==1 and (len(data)<14 or data[12:14]!=b'\x08\x00'): continue
  data=data[offset:]
  if len(data)<20 or data[0]>>4!=4: continue
  ihl=(data[0]&15)*4
  if ihl<20 or len(data)<ihl+8 or struct.unpack('!H',data[6:8])[0]&0x3fff: continue
  src=str(ipaddress.ip_address(data[12:16]));dst=str(ipaddress.ip_address(data[16:20]));proto={6:'tcp',17:'udp'}.get(data[9])
  if proto is None: continue
  payload=data[ihl:];sport,dport=struct.unpack('!HH',payload[:4])
  outgoing=src==SOURCE and dst in ENDPOINTS and dport==53
  incoming=dst==SOURCE and src in ENDPOINTS and sport==53
  if not(outgoing or incoming): continue
  flow=(proto,dst if outgoing else src,sport if outgoing else dport)
  row={'t':sec+fraction/scale,'flow':flow,'out':outgoing}
  if proto=='tcp':
   if len(payload)<20: continue
   row['flags']=payload[13];row['seq'],row['ack']=struct.unpack('!II',payload[4:12])
  elif len(payload)>=20:
   row['dns_id'],flags=struct.unpack('!HH',payload[8:12]);row['response']=bool(flags&0x8000);row['rcode']=flags&15
  out.append(row)
 return out

def correlate(rows,diagnostics,rpcs,complete=False,coverage=None):
 result=[]
 for d in diagnostics:
  if d.get('operation')!='dns_exchange' or d.get('socket_ms')!=3000 or d.get('socket_stage') not in ('dial','body'): continue
  end=stamp(d['time']);start=end-3;proto='tcp' if d.get('stage','').startswith('dns_socket_tcp') else 'udp'
  windows=[r for r in rpcs if stamp(r['dispatch_utc'])<=start<=end<=stamp(r['dispatch_utc'])+r['handle_ms']/1000+.15]
  candidates={r['flow'] for r in rows if r['out'] and r['flow'][0]==proto and abs(r['t']-start)<=.15 and (proto=='udp' or r.get('flags',0)&2 and not r.get('flags',0)&16)}
  item={'observed_at':d['time'],'protocol':proto,'socket_stage':d['socket_stage'],'candidate_count':len(candidates),'rpc_window_count':len(windows),'classification':'indeterminate'}
  if len(candidates)==1 and len(windows)==1:
   flow=next(iter(candidates));records=[r for r in rows if r['flow']==flow and start-.15<=r['t']<=end+.15]
   sent=[r for r in records if r['out']];received=[r for r in records if not r['out']]
   if proto=='udp':
    ids={r['dns_id'] for r in sent if 'dns_id'in r and not r['response']}
    replies=[r for r in received if r.get('dns_id') in ids and r.get('response')]
    if len(ids)==1: item.update(classification='unique_flow_header_match',reply_observed=bool(replies),noerror_reply_observed=any(r['rcode']==0 for r in replies))
   else:
    syns=[r for r in sent if r.get('flags',0)&2 and not r.get('flags',0)&16]
    replies=[r for r in received if r.get('flags',0)&18==18 and any(r['ack']==(s['seq']+1)&0xffffffff for s in syns)]
    item.update(classification='unique_flow_header_match',reply_observed=bool(replies),syn_count=len(syns),handshake_ack_observed=any(r.get('flags',0)&16 and any(r['ack']==(s['seq']+1)&0xffffffff for s in replies) for r in sent))
  if item['classification']=='unique_flow_header_match':
   outgoing_indices={r.get('capture_index') for r in sent if r.get('capture_index') in (0,1)}
   reply_indices={r.get('capture_index') for r in replies if r.get('capture_index') in (0,1)}
   item['request_xfrm_count']=len(outgoing_indices)
   item['reply_xfrm_count']=len(reply_indices)
   item['same_tunnel_reply_observed']=bool(outgoing_indices & reply_indices)
   item['opposite_tunnel_reply_observed']=bool(reply_indices-outgoing_indices) and len(outgoing_indices)==1
   if not complete or coverage is not None and not (coverage[0]<=start and end<=coverage[1]): item['classification']='indeterminate'
  result.append(item)
 return result

def run(args):
 if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer': raise ValueError('owned_host')
 os.umask(0o077)
 baseline_raw=private(args.attestation,65536);b=json.loads(baseline_raw)
 # This independent producer prerequisite is not replaced by Python JSON decoding.
 required=('whole_journal_valid','normal_authority_matches','resolver_grants_match','routes_match','source_matches','profile_matches')
 if any(b.get(k)is not True for k in required) or b.get('revision')!=46 or b.get('preserved_grant_count')!=8 or b.get('preserved_grant_ids_match')is not True or sorted(map(tuple,b.get('endpoint_pairs',[])))!=PAIRS: raise ValueError('attestation')
 if abs(time.time()-stamp(b['observed_at']))>15: raise ValueError('attestation_age')
 initial=identity();interfaces=b['xfrm_interfaces']+['az-s2s-client']
 if len(set(interfaces))!=3 or any(not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',v) for v in interfaces): raise ValueError('interfaces')
 mounts=json.loads(command(['docker','inspect',CID]))[0]['Mounts']
 state=[v['Source'] for v in mounts if v['Destination']=='/var/lib/tunnex-node']
 if len(state)!=1 or b['live_journal_path']!=state[0]+'/ipsec/journal.json': raise ValueError('state_mount')
 live=live_journal(b['live_journal_path'],b['live_journal_device'],b['live_journal_inode'])
 snapshot=private(b['snapshot_journal_path'])
 if sha(live)!=b['journal_sha256'] or sha(snapshot)!=b['journal_sha256']: raise ValueError('journal_attestation')
 payload=json.loads(snapshot)['Payload']
 entries=[e for e in payload['Entries'] if e['Phase']=='applied' and e['Engines'][0]['Binding']['DesiredRevision']==46]
 if len(entries)!=1 or [t['Name'] for t in entries[0]['Allocation']['Tunnels']]!=b['xfrm_interfaces']: raise ValueError('snapshot_interfaces')
 for tool in ('tcpdump','ss','nsenter'): command(['sh','-c','command -v "$1"','sh',tool])
 conntrack_available=subprocess.run(['sh','-c','command -v conntrack'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode==0
 directory=pathlib.Path(args.evidence_dir);directory.mkdir(mode=0o700,exist_ok=False)
 if str(directory.resolve())!=str(directory) or directory.stat().st_uid!=0: raise ValueError('evidence_directory')
 save(directory/'attestation.json',baseline_raw);started=utc();processes=[];streams=[];capture_started=time.monotonic()
 try:
  for i,interface in enumerate(interfaces):
   log=open(directory/f'capture-{i}.log','xb');os.chmod(log.name,0o600);streams.append(log)
   proc=subprocess.Popen(['nsenter','-t',str(initial[0]),'-n','tcpdump','-U','-Z','root','-n','-i',interface,'-s','160','-C','8','-W','1','-w',str(directory/f'capture-{i}.pcap'),'host',SOURCE,'and','(','host','10.231.2.4','or','host','10.231.2.20',')','and','port','53'],stdout=subprocess.DEVNULL,stderr=log);processes.append(proc)
  capture_ready=time.time();capture_stopped=[]
  def end_capture():
   capture_stopped.append(time.time())
   for p in processes:
    if p.poll()is None:p.send_signal(signal.SIGINT)
  timer=threading.Timer(max(0,40-(time.monotonic()-capture_started)),end_capture);timer.daemon=True;timer.start()
  stop=capture_started+39;index=0
  while time.monotonic()<stop:
   if identity()!=initial or any(p.poll()is not None for p in processes): raise ValueError('capture_identity')
   socket_rows=command(['nsenter','-t',str(initial[0]),'-n','ss','-H','-ntup']).decode().splitlines()
   sample={'observed_at':utc(),'ss':'\n'.join(v for v in socket_rows if f'pid={initial[0]},' in v)}
   # Raw samples stay private; parsing does not claim they identify a timed-out socket.
   sample['conntrack']=[]
   for proto in (('udp','tcp') if conntrack_available else ()):
    for endpoint in sorted(ENDPOINTS):
     result=subprocess.run(['nsenter','-t',str(initial[0]),'-n','conntrack','-L','-p',proto,'--orig-src',SOURCE,'--orig-dst',endpoint,'--dport','53'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2)
     if result.returncode: raise ValueError('conntrack_read')
     sample['conntrack'].append(result.stdout.decode())
   save(directory/f'sockets-{index}.json',json.dumps(sample).encode());index+=1
   if stop-time.monotonic()>1: time.sleep(1)
 finally:
  if 'timer' in locals():timer.cancel()
  if 'capture_stopped' in locals() and not capture_stopped:capture_stopped.append(time.time())
  for p in processes:
   if p.poll()is None:p.send_signal(signal.SIGINT)
  for p in processes:
   try:p.wait(timeout=3)
   except subprocess.TimeoutExpired:p.kill();p.wait()
  for stream in streams:stream.close()
 if identity()!=initial: raise ValueError('final_identity')
 logged=subprocess.run(['docker','logs','--since',started,CID],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
 logs=logged.stdout+b'\n'+logged.stderr;save(directory/'node.log',logs)
 diagnostics=[];rpcs=[]
 for line in logs.splitlines():
  try:v=json.loads(line)
  except ValueError:continue
  if v.get('msg')=='ipsec_runtime_diagnostic_refused':diagnostics.append({k:v[k] for k in ('time','operation','stage','socket_ms','socket_stage') if k in v})
  if v.get('msg')=='fqdn_rpc_timing':rpcs.append({k:v[k] for k in ('dispatch_utc','handle_ms') if k in v})
 rows=[];hashes=[];health=[]
 for i in range(3):
  path=directory/f'capture-{i}.pcap';os.chmod(path,0o600);raw=private(str(path))
  if len(raw)>=8_000_000: raise ValueError('capture_rotation')
  hashes.append(sha(raw))
  parsed=packets(raw)
  for row in parsed: row['capture_index']=i
  rows+=parsed
  health.append(capture_health(private(str(directory/f'capture-{i}.log')),processes[i].returncode))
 result={'version':1,'started_at':started,'ended_at':utc(),'scope':'Read-only natural RPC header correlation; no authority or readiness claim','packet_header_count':len(rows),'socket_sample_count':index,'capture_sha256':hashes,'capture_health':health,'supporting_conntrack_available':conntrack_available,'correlations':correlate(rows,diagnostics,rpcs,all(v['dropped']==0 for v in health),(capture_ready,capture_stopped[0]))}
 save(directory/'summary.json',json.dumps(result,indent=2).encode());print(json.dumps(result))

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attestation',required=True);p.add_argument('--evidence-dir',required=True);a=p.parse_args()
 try:run(a)
 except Exception:print(json.dumps({'status':'refused','category':'owned_capture_refused'}));sys_exit=1;raise SystemExit(sys_exit)
