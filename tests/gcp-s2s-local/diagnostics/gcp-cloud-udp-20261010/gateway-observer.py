import json,os,pathlib,re,select,socket,struct,subprocess,sys,time
CID='dc81baef1c4924007b39224fd4f9b14bef94e734c2138257b12bfdc46abd8294'
IMAGE='sha256:ccde530ca3e815ee169ed258ab6a95ad20de4089f8e4abf6b0f20440a7d62102'
BOOT='9617762e-19db-4a21-bdee-909dfb31e501'
NFT_SHA='7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f'
CONNECTION='b79d7eda-fafe-41cf-af2c-4115d4ef32c6';TUNNEL='8494b8ef-e6e8-4d8d-b964-fc6faec7cb72'
def command(*args):
 p=subprocess.run(args,capture_output=True,timeout=10,check=True)
 if len(p.stdout)>2*1024*1024:raise ValueError('bounded output')
 return p.stdout.decode().strip()
def cexec(*args):return command('docker','exec',CID,*args)
def counters():
 data=json.loads(cexec('/usr/sbin/nft','-j','list','ruleset'));out=[]
 for row in data['nftables']:
  r=row.get('rule');text=json.dumps(r)
  if not r:continue
  if r.get('table') not in ['tunnex_ipsec','tunnex']:continue
  if not (r.get('table')=='tunnex' and 'forward' in r.get('chain','').lower()) and '9000' not in text and not ('invalid' in text and 'drop' in text) and not ('3912688814' in text):continue
  out.append({'family':r['family'],'table':r['table'],'chain':r['chain'],'handle':r.get('handle'),'expression_without_counters':[e for e in r['expr'] if 'counter'not in e],'counters':[e['counter'] for e in r['expr'] if 'counter'in e]})
 return out

def snapshot():
 inspect=json.loads(command('docker','inspect',CID))[0]
 if inspect['Id']!=CID or inspect['Image']!=IMAGE or inspect['State']['Running'] is not True:raise ValueError('owned gateway')
 if command('cat','/proc/sys/kernel/random/boot_id')!=BOOT:raise ValueError('exact deployed boot')
 if cexec('sha256sum','/usr/sbin/nft').split()[0]!=NFT_SHA:raise ValueError('qualified nft reader identity')
 ns=command('readlink','/proc/self/ns/net');childns=cexec('readlink','/proc/self/ns/net')
 if ns!=childns or ns!='net:[4026531840]':raise ValueError('exact namespace')
 p=pathlib.Path('/var/lib/tunnex-gcp-s2s-cloud-20261010/ipsec/journal.json')
 if p.stat().st_size>16*1024*1024:raise ValueError('bounded journal')
 payload=json.loads(p.read_text())['Payload'];entries=[e for e in payload['Entries'] if e['Allocation']['ConnectionID']==CONNECTION]
 if len(entries)!=1 or len(payload['Guards'])!=1:raise ValueError('exact entry/guard')
 e=entries[0];a=e['Allocation'];t=a['Tunnels'][0];inactive=a['Tunnels'][1]
 if e['ContractVersion']!=4 or e['Phase']!='applied' or a['Namespace']!=ns or t['TunnelID']!=TUNNEL or t['Slot']!=1 or not t['Selected'] or t['XFRMID']!=3912688814 or any(inactive.get(k)not in [None,'',0,False,'00000000-0000-0000-0000-000000000000'] for k in ['TunnelID','Slot','Name','Alias','XFRMID','InsideAddress','Selected']) or inactive.get('RemotePrefixes'):raise ValueError('Classic cardinality')
 links=json.loads(cexec('/sbin/ip','-j','-d','link','show'));selected=[i for i in links if i['ifname']in ['ens4',t['Name']]]
 if len(selected)!=2:raise ValueError('exact interfaces')
 x=next(i for i in selected if i['ifname']==t['Name'])
 if x['ifindex']!=e['Observed'][0]['InterfaceIndex'] or x.get('ifalias')!=t['Alias'] or x.get('linkinfo',{}).get('info_kind')!='xfrm' or int(str(x.get('linkinfo',{}).get('info_data',{}).get('if_id')),0)!=t['XFRMID']:raise ValueError('owned XFRM')
 route=json.loads(cexec('/sbin/ip','-j','-4','route','get','10.81.0.10'))
 if len(route)!=1 or route[0].get('dev')!=t['Name']:raise ValueError('selected route')
 text=command('docker','exec','-e','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf',CID,'/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici')
 name='tnx-ipsec-'+TUNNEL+'-d2-c1-s1';ike=re.findall(r'^'+re.escape(name)+r': #(\d+), ESTABLISHED, IKEv2',text,re.M);child=re.findall(r'^  '+re.escape(name)+r': #(\d+), reqid 3912688814, INSTALLED,',text,re.M)
 if len(ike)!=1 or len(child)!=1:raise ValueError('exact installed SA')
 g=payload['Guards'][0]
 return {'boot_id':command('cat','/proc/sys/kernel/random/boot_id'),'container_id':CID,'image_id':IMAGE,'pid':inspect['State']['Pid'],'started_at':inspect['State']['StartedAt'],'namespace':ns,'delivery_id':e['DeliveryID'],'contract_version':4,'phase':e['Phase'],'ownership_digest':e['OwnershipDigest'],'generation':a['Generation'],'links':selected,'route':route,'guard':{k:g[k] for k in ['Revision','Digest','Namespace']},'sa_identity':{'ike_id':ike[0],'child_id':child[0],'reqid':3912688814},'counters':counters()}
def match_packet(ip,nonce):
 if len(ip)<28 or ip[0]>>4!=4:return None
 h=(ip[0]&15)*4;total=struct.unpack('!H',ip[2:4])[0]
 if h<20 or total>len(ip) or total<h+8:return None
 if socket.inet_ntoa(ip[12:16])!='10.70.0.10' or socket.inet_ntoa(ip[16:20])!='10.81.0.10' or ip[9]!=17:return None
 if struct.unpack('!H',ip[6:8])[0]&0x3fff:return 'unsupported_fragment'
 udp=ip[h:total];length=struct.unpack('!H',udp[4:6])[0]
 if struct.unpack('!H',udp[2:4])[0]!=9000:return None
 if length!=len(udp) or length<8:return 'invalid_udp_length'
 return 'exact_nonce' if udp[8:]==('tnx-gcp-packet-'+nonce).encode() else 'other_tuple'

def finish_result(before,counts,stats,stopped):
 result={'counts':counts,'stats':stats,'stopped_by_request':stopped,'transport_identity_stable':False,'guard_identity_stable':False,'stable_gate':False}
 try:after=snapshot()
 except Exception as e:
  result['snapshot_after_error_type']=type(e).__name__
  return result
 fields=['boot_id','container_id','image_id','pid','started_at','namespace','delivery_id','contract_version','phase','ownership_digest','generation','links','route','sa_identity']
 stable=all(before[k]==after[k] for k in fields);guard_stable=before['guard']==after['guard']
 result.update(snapshot_after=after,transport_identity_stable=stable,guard_identity_stable=guard_stable,stable_gate=stable and guard_stable and stopped and all(v['drops']==0 for v in stats.values()))
 return result

def gateway_observe(nonce):
 before=snapshot();names=['ens4',next(i['ifname'] for i in before['links'] if i['ifname']!='ens4')];sockets=[];counts={n:{'incoming_exact':0,'outgoing_exact':0,'other_tuple':0,'unsupported_fragment':0,'invalid_udp_length':0} for n in names}
 try:
  for n in names:
   s=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0800));s.bind((n,0x0800));s.setblocking(False);sockets.append(s)
  print(json.dumps({'ready':True,'snapshot':before,'interfaces':names,'observer':'AF_PACKET SOCK_DGRAM IPv4 offset0'}),flush=True)
  stopped=False;deadline=time.monotonic()+20
  def consume(s):
   ip,address=s.recvfrom(65535);kind=match_packet(ip,nonce)
   if kind:
    n=names[sockets.index(s)];key=('outgoing_exact' if address[2]==socket.PACKET_OUTGOING else 'incoming_exact') if kind=='exact_nonce' else kind;counts[n][key]+=1
  while time.monotonic()<deadline:
   ready,_,_=select.select(sockets+[sys.stdin],[],[],max(0,deadline-time.monotonic()))
   if sys.stdin in ready:
    if sys.stdin.readline()!='STOP\n':raise ValueError('exact STOP')
    for s in sockets:
     while True:
      try:consume(s)
      except BlockingIOError:break
    stopped=True;break
   for s in sockets:
    if s in ready:consume(s)
  stats={n:dict(zip(['packets','drops'],struct.unpack('II',s.getsockopt(263,6,8)))) for n,s in zip(names,sockets)}
  print(json.dumps({'capture_complete':True,'counts':counts,'stats':stats,'stopped_by_request':stopped}),flush=True)
  result=finish_result(before,counts,stats,stopped)
  print(json.dumps(result),flush=True)
 finally:
  for s in sockets:s.close()
