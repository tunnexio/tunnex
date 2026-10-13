#!/usr/bin/env python3
"""One explicitly executed owned TCP DNS diagnostic; source import performs no I/O."""
import argparse,copy,hashlib,importlib.util,json,os,pathlib,re,socket,stat,struct,subprocess,threading,time,types
HERE=pathlib.Path(__file__).parent
DEPENDENCIES={'gcp-classic-dns-tcp-trace-plan.py':'29f7bbad3e39eb9b9f63017e98cf663db12ad35056bc0f69f29e5ffae74dd4d2','gcp-cloud-dns-wire-probe.py':'b260ea4e8985926022411a2015e495c3fedbfc56238544af9e8528fef39740ba'}
def module(name,file):
 b=(HERE/file).read_bytes()
 if file not in DEPENDENCIES or hashlib.sha256(b).hexdigest()!=DEPENDENCIES[file]:raise ValueError('reviewed dependency identity')
 m=types.ModuleType(name);m.__file__=str(HERE/file);exec(compile(b,m.__file__,'exec'),m.__dict__);return m
def docker_identity(i,boot,namespace):
 out={'cid':i['Id'],'image':i['Image'],'source_commit':i.get('Config',{}).get('Labels',{}).get('org.opencontainers.image.revision'),'boot':boot,'namespace':namespace};trace.identity(out);return out
trace=module('trace','gcp-classic-dns-tcp-trace-plan.py');dns=module('wire','gcp-cloud-dns-wire-probe.py')
TUNNEL='8494b8ef-e6e8-4d8d-b964-fc6faec7cb72';OUTSIDE='34.131.214.202';NFT_SHA='7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f'
def run(*args):
 r=subprocess.run(args,capture_output=True,check=True,timeout=10)
 if len(r.stdout)>2*1024*1024:raise ValueError('bounded command output')
 return r.stdout.decode()
def ex(*args):return run('docker','exec',trace.CID,*args)
def semantic(value):
 if isinstance(value,list):return [semantic(x)for x in value]
 if isinstance(value,dict):return {k:semantic(v)for k,v in value.items()if k not in ('handle','packets','bytes','expires','timeout','metainfo')}
 return value
def selected_sa(text):
 lines=text.splitlines();starts=[n for n,l in enumerate(lines)if TUNNEL in l and re.search(r': #\d+, ESTABLISHED, IKEv2',l)]
 if len(starts)!=1:raise ValueError('exact selected Classic IKE')
 start=starts[0];end=next((n for n in range(start+1,len(lines))if re.match(r'^\S.*: #\d+,',lines[n])),len(lines));block=lines[start:end]
 ike=int(re.search(r': #(\d+),',block[0])[1]);children=[re.search(r'#(\d+), reqid (\d+), INSTALLED,',l)for l in block];children=[x for x in children if x]
 if len(children)!=1:raise ValueError('exact one installed child')
 out={'ike_id':ike,'child_id':int(children[0][1]),'reqid':int(children[0][2])}
 for direction in ['in','out']:
  candidates=[l for l in block if re.match(r'^\s*'+direction+r'\s+',l)]
  matches=[re.fullmatch(r'\s*'+direction+r'\s+([0-9a-fA-F]{8})(?: \(-\|0x([0-9a-fA-F]{1,8})\))?,\s*(\d+) bytes,\s*(\d+) packets\s*',l)for l in candidates]
  if len(candidates)!=1 or any(x is None for x in matches):raise ValueError('selected public SA counter format')
  if len(matches)!=1:raise ValueError('selected public SA counters')
  if matches[0][2] is not None and int(matches[0][2],16)!=out['reqid']:raise ValueError('selected SA interface ID')
  out[direction]={'spi':int(matches[0][1],16),'bytes':int(matches[0][3]),'packets':int(matches[0][4])}
 return out
def dns_ready(rules,name):
 def match(expr,left,right):return any(x.get('match',{}).get('left')==left and x['match'].get('right')==right and x['match'].get('op')=='=='for x in expr)
 for proto in ['tcp','udp']:
  for direction in ['output','input']:
   found=False
   for r in rules:
    if r['chain']!=direction+'_guard':continue
    e=r['expr'];out=direction=='output';src,dst=(trace.SOURCE,trace.RESOLVER)if out else(trace.RESOLVER,trace.SOURCE);key='oif'if out else'iif';lease='@lease_'if out else'@reply_lease_'
    expected=[({'payload':{'protocol':'ip','field':'saddr'}},src),({'payload':{'protocol':'ip','field':'daddr'}},dst),({'payload':{'protocol':proto,'field':'dport'if out else'sport'}},53),({'meta':{'key':key}},name),({'meta':{'key':key}},lease+'b79d7edafafe41cfaf2c4115d4ef32c6'),({'ct':{'key':'direction'}},'original'if out else'reply')]
    if all(match(e,left,right)for left,right in expected)and any('accept'in x for x in e):
     if out or any(x.get('match',{}).get('left')=={'ct':{'key':'state'}}and x['match'].get('right')=='established'for x in e):found=True
   if not found:return False
 return True
def snapshot():
 i=json.loads(run('docker','inspect',trace.CID))[0];identity=docker_identity(i,pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),run('readlink','/proc/self/ns/net').strip())
 if not i['State']['Running']or ex('readlink','/proc/self/ns/net').strip()!=trace.NS or ex('sha256sum','/usr/sbin/nft').split()[0]!=NFT_SHA:raise ValueError('running qualified namespace/reader')
 addresses=json.loads(ex('/sbin/ip','-j','-4','addr','show'))
 if not any(a.get('local')==trace.SOURCE for l in addresses if l.get('ifname')=='ens4'for a in l.get('addr_info',[])):raise ValueError('assigned source')
 p=pathlib.Path('/var/lib/tunnex-gcp-s2s-cloud-20261010/ipsec/journal.json')
 if p.stat().st_size>16*1024*1024:raise ValueError('bounded journal')
 j=json.loads(p.read_text())['Payload'];entries=[e for e in j['Entries']if e['Allocation']['ConnectionID']==trace.CONNECTION]
 if len(entries)!=1 or len(j['Guards'])!=1:raise ValueError('exact current journal projection')
 e=entries[0];a=e['Allocation'];t=a['Tunnels'][0]
 if e['Phase']!='applied'or e['ContractVersion']!=4 or a['Namespace']!=trace.NS or t['TunnelID']!=TUNNEL:raise ValueError('applied Classic identity')
 if any(a['Tunnels'][1].get(k)not in (None,'',0,False,'00000000-0000-0000-0000-000000000000')for k in ['TunnelID','Slot','Name','Alias','XFRMID','InsideAddress','Selected'])or a['Tunnels'][1].get('RemotePrefixes'):raise ValueError('inactive slot zero')
 links=json.loads(ex('/sbin/ip','-j','-d','link','show'));owned=[l for l in links if l.get('ifname')==t['Name']];physical=[l for l in links if l.get('ifname')=='ens4']
 if len(owned)!=1 or len(physical)!=1 or owned[0].get('ifalias')!=t['Alias']:raise ValueError('owned interfaces')
 route=json.loads(ex('/sbin/ip','-j','-4','route','get',trace.RESOLVER,'from',trace.SOURCE))
 if len(route)!=1 or route[0].get('dev')!=t['Name']:raise ValueError('exact assigned source route')
 table=json.loads(ex('/usr/sbin/nft','-j','list','table','inet','tunnex_ipsec'));leases=[];rules=[]
 for x in table['nftables']:
  s=x.get('set',{})
  if 'b79d7edafafe41cfaf2c4115d4ef32c6'in s.get('name',''):leases.append(s)
  r=x.get('rule',{});expr=r.get('expr',[])
  if r.get('chain')in ['output_guard','input_guard']and trace.RESOLVER in json.dumps(expr)and any('accept'in z for z in expr):rules.append({'chain':r['chain'],'expr':expr})
 if not dns_ready(rules,t['Name'])or len(leases)!=3 or any(not s.get('elem')or s['elem'][0]['elem'].get('expires',0)<=8 for s in leases):raise ValueError('native HostOrigin lease readiness')
 sa=selected_sa(run('docker','exec','-e','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf',trace.CID,'/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici'))
 if sa['reqid']!=t['XFRMID']:raise ValueError('selected reqid')
 guard={k:j['Guards'][0][k]for k in ['Revision','Digest','Namespace']}
 if guard['Namespace']!=trace.NS:raise ValueError('guard namespace')
 return {'identity':identity,'pid':i['State']['Pid'],'started_at':i['State']['StartedAt'],'delivery_id':e['DeliveryID'],'interfaces':{'physical':{'name':'ens4','index':physical[0]['ifindex']},'xfrm':{'name':t['Name'],'index':owned[0]['ifindex'],'alias':t['Alias'],'xfrm_id':t['XFRMID']}},'route':route,'guard':guard,'native_semantic_sha256':hashlib.sha256(json.dumps(semantic(table),sort_keys=True).encode()).hexdigest(),'dns_rules':rules,'leases':leases,'sa':sa}
def stable(before,after):
 fields=['identity','pid','started_at','delivery_id','interfaces','route','native_semantic_sha256']
 if any(before[k]!=after[k]for k in fields):return False
 a,b=before['sa'],after['sa']
 return all(a[k]==b[k]for k in ['ike_id','child_id','reqid'])and all(a[d]['spi']==b[d]['spi']for d in ['in','out'])
def encapsulation(data,sa):
 if len(data)<36 or data[0]>>4!=4:return None
 h=(data[0]&15)*4;total=struct.unpack('!H',data[2:4])[0]
 if h<20 or total>len(data)or total<h+16 or data[9]!=17 or struct.unpack('!H',data[6:8])[0]&0xbfff:return None
 src=socket.inet_ntoa(data[12:16]);dst=socket.inet_ntoa(data[16:20]);sport,dport=struct.unpack('!HH',data[h:h+4])
 if sport!=4500 or dport!=4500:return None
 spi,seq=struct.unpack('!II',data[h+8:h+16]);direction='out'if(src,dst)==(trace.SOURCE,OUTSIDE)else'in'if(src,dst)==(OUTSIDE,trace.SOURCE)else None
 if direction is None or spi!=sa[direction]['spi']:return None
 return {'direction':direction,'spi':spi,'sequence':seq,'ip_length':total}
class Observer:
 def __init__(self,name,port,sa):
  self.name=name;self.port=port;self.sa=sa;self.ready=threading.Event();self.stop=threading.Event();self.result={'interface':name,'events':[],'total_frames':0,'drops':None,'stopped':False};self.thread=threading.Thread(target=self.loop)
 def loop(self):
  try:
   with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0800))as s:
    s.bind((self.name,0x0800));s.settimeout(.1);self.ready.set();deadline=time.monotonic()+12
    while time.monotonic()<deadline and not self.stop.is_set():
     try:data,address=s.recvfrom(65535)
     except socket.timeout:continue
     self.consume(data,address)
    s.setblocking(False)
    for _ in range(10000):
     try:data,address=s.recvfrom(65535)
     except BlockingIOError:break
     self.consume(data,address)
    else:self.result['drain_limit_reached']=True
    packets,drops=struct.unpack('II',s.getsockopt(263,6,8));self.result.update(kernel_packets=packets,drops=drops,stopped=True)
  except Exception as e:self.result['error_type']=type(e).__name__;self.ready.set()
 def consume(self,data,address):
  self.result['total_frames']+=1;e=trace.ipv4_tcp(data,self.port);kind='inner_tcp'
  if e is None:e=encapsulation(data,self.sa);kind='outer_spi'
  if e is not None:
   if len(self.result['events'])>=10000:self.result['event_limit_reached']=True;return
   self.result['events'].append({'kind':kind,'packet_type':address[2],'metadata':e})
def tcp_case(sock,record):
 name='app.classic.gcp.s2s-qa.tunnex.app.';ident=int.from_bytes(os.urandom(2),'big');wire=struct.pack('!6H',ident,0x100,1,0,0,0)+dns.question(name);deadline=time.monotonic()+4
 last_stage=[None]
 def stage(value):
  last_stage[0]=value;record({'stage':value,'id':ident,'name':name,'source_port':sock.getsockname()[1]})
 def remaining():
  t=deadline-time.monotonic()
  if t<=0:raise TimeoutError('total deadline')
  sock.settimeout(t)
 try:
  stage('tcp_connect');remaining();sock.connect((trace.RESOLVER,53));stage('tcp_write');remaining();sock.sendall(struct.pack('!H',len(wire))+wire)
  def exact(n):
   b=b''
   while len(b)<n:
    remaining();part=sock.recv(n-len(b))
    if not part:raise ValueError('short frame')
    b+=part
   return b
  stage('tcp_read_length');n=struct.unpack('!H',exact(2))[0]
  if n<12:raise ValueError('bounded frame')
  stage('tcp_read_body');result=dns.response(exact(n),ident,name,True);return {'accepted':dns.validate_answers(result,'classic','app'),'full':result}
 except Exception as e:record({'stage':last_stage[0],'failed':True,'error_type':type(e).__name__,'errno':getattr(e,'errno',None)});raise
def main():
 p=argparse.ArgumentParser();p.add_argument('--receipt',required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:raise ValueError('explicit reviewed execution required')
 parent=pathlib.Path(a.receipt).parent;s=os.lstat(parent)
 if os.geteuid()!=0 or not stat.S_ISDIR(s.st_mode)or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('root private evidence')
 fd=os.open(a.receipt,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);r={'started':True,'completed':False,'stages':[],'scope':'one directTCP app case with observers; XFRM absence/SPI counters alone never causal proof'};observers=[]
 def save():
  data=json.dumps(r).encode();os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0)
  while data:
   n=os.write(fd,data)
   if n<=0:raise OSError('receipt write refused')
   data=data[n:]
  os.fsync(fd)
 def record(value):r['stages'].append(value);save()
 try:
  r['before']=snapshot();save()
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as sock:
   sock.bind((trace.SOURCE,0));r['source_port']=sock.getsockname()[1];record({'stage':'tcp_bound','source_port':r['source_port']})
   for name in ['ens4',r['before']['interfaces']['xfrm']['name']]:
    o=Observer(name,r['source_port'],r['before']['sa']);observers.append(o);o.thread.start()
   if not all(o.ready.wait(2)and'error_type'not in o.result for o in observers):raise ValueError('all observers READY')
   record({'stage':'all_observers_ready'})
   try:r['query']=tcp_case(sock,record)
   except Exception as e:r['query_error_type']=type(e).__name__
  for o in observers:o.stop.set()
  for o in observers:o.thread.join(2)
  r['capture']=[copy.deepcopy(o.result)for o in observers];save()
  try:r['after']=snapshot();r['stable_native_identity']=stable(r['before'],r['after'])
  except Exception as e:r['after_error_type']=type(e).__name__;r['stable_native_identity']=False
  r['capture_complete']=all(o.result.get('stopped')and o.result.get('drops')==0 and not o.result.get('drain_limit_reached')and not o.result.get('event_limit_reached') for o in observers)
  if 'after'in r:
   old,new=r['before']['sa'],r['after']['sa'];same=all(old[k]==new[k]for k in ['ike_id','child_id','reqid'])and all(old[d]['spi']==new[d]['spi']for d in ['in','out']);r['sa_counter_same_identity']=same
   r['sa_counter_deltas']={d:{k:new[d][k]-old[d][k]for k in ['packets','bytes']}for d in ['in','out']}if same else None
  r.update(completed=True,causal_drop_proven=False);save()
 except Exception as e:r['error_type']=type(e).__name__;save();raise
 finally:
  for o in observers:o.stop.set();o.thread.join(2)
  if observers:r['capture']=[copy.deepcopy(o.result)for o in observers]
  save();os.close(fd)
 print(json.dumps({'completed':r['completed'],'query_accepted':r.get('query',{}).get('accepted',False),'stable_native_identity':r.get('stable_native_identity',False),'capture_complete':r.get('capture_complete',False)}))
if __name__=='__main__':
 try:main()
 except Exception as e:raise SystemExit('Owned TCP diagnostic refused: '+type(e).__name__)
