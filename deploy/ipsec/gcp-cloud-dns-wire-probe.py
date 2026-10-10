#!/usr/bin/env python3
"""Fixed owned gateway DNS probe; source preparation performs no I/O."""
import argparse,json,os,pathlib,secrets,socket,stat,struct,time
PROFILES={'ha':('10.80.0.2','ha.gcp.s2s-qa.tunnex.app.', '10.80.0.10','10.80.0.'),'classic':('10.81.0.2','classic.gcp.s2s-qa.tunnex.app.','10.81.0.10','10.81.0.')}
SOURCE='10.70.0.2'
def question(name):
 labels=name.rstrip('.').split('.')
 if any(not x or len(x)>63 for x in labels):raise ValueError('bounded DNS name')
 return b''.join(bytes([len(x)])+x.encode('ascii') for x in labels)+b'\0'+struct.pack('!HH',1,1)
def decode_name(data,pos):
 labels=[];end=None;seen=set()
 for _ in range(128):
  if pos>=len(data)or pos in seen:raise ValueError('DNS name bounds/loop')
  seen.add(pos);n=data[pos]
  if n&0xc0==0xc0:
   if pos+1>=len(data):raise ValueError('DNS pointer bounds')
   if end is None:end=pos+2
   pos=((n&63)<<8)|data[pos+1];continue
  if n&0xc0 or n>63 or pos+1+n>len(data):raise ValueError('DNS label bounds')
  pos+=1
  if n==0:return '.'.join(labels).lower()+'.',end if end is not None else pos
  labels.append(data[pos:pos+n].decode('ascii'));pos+=n
 raise ValueError('DNS name length')
def response(data,id,name,full):
 if len(data)<12:raise ValueError('DNS header')
 rid,flags,qd,an,ns,ar=struct.unpack('!6H',data[:12])
 if rid!=id or not flags&0x8000 or flags&0x7800 or qd!=1:raise ValueError('DNS response identity/opcode')
 q,p=decode_name(data,12)
 if q!=name.lower()or p+4>len(data)or data[p:p+4]!=struct.pack('!HH',1,1):raise ValueError('DNS exact question')
 out={'id':rid,'question':q,'rcode':flags&15,'tc':bool(flags&0x200),'answer_count':an,'a':[],'cname':[],'other_answers':[]};p+=4
 if not full:return out
 if out['tc']:raise ValueError('full response truncated')
 for index in range(an+ns+ar):
  owner,p=decode_name(data,p)
  if p+10>len(data):raise ValueError('DNS RR header')
  kind,cls,ttl,size=struct.unpack('!HHIH',data[p:p+10]);p+=10;end=p+size
  if end>len(data):raise ValueError('DNS RR data')
  if index<an and cls==1:
   if kind==1:
    if size!=4:raise ValueError('DNS A size')
    out['a'].append({'owner':owner,'address':socket.inet_ntoa(data[p:end])})
   elif kind==5:
    target,nextpos=decode_name(data,p)
    if nextpos!=end:raise ValueError('DNS CNAME length')
    out['cname'].append({'owner':owner,'target':target})
   else:out['other_answers'].append({'owner':owner,'type':kind})
  p=end
 if p!=len(data):raise ValueError('DNS trailing bytes')
 return out
def tcp_query(resolver,wire):
 deadline=time.monotonic()+4
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as s:
  def remaining():
   value=deadline-time.monotonic()
   if value<=0:raise TimeoutError('DNS TCP total deadline')
   s.settimeout(value)
  s.bind((SOURCE,0));remaining();s.connect((resolver,53));remaining();s.sendall(struct.pack('!H',len(wire))+wire)
  def exact(n):
   b=b''
   while len(b)<n:
    remaining();part=s.recv(n-len(b))
    if not part:raise ValueError('DNS TCP short frame')
    b+=part
   return b
  n=struct.unpack('!H',exact(2))[0]
  if n<12:raise ValueError('DNS TCP bounded frame')
  return exact(n)
def validate_answers(full,profile,label):
 _,zone,target,prefix=PROFILES[profile];name=label+'.'+zone;addresses={x['address']for x in full['a']}
 if full['other_answers']:return False
 if label=='nx-qualification':return full['rcode']==3 and full['answer_count']==0 and not full['a']and not full['cname']
 if full['rcode']!=0:return False
 if label=='alias':return full['answer_count']==2 and full['cname']==[{'owner':name,'target':'app.'+zone}]and full['a']==[{'owner':'app.'+zone,'address':target}]
 expected={prefix+str(n)for n in range(100,140)}if label=='large'else{target}
 return addresses==expected and not full['cname']and all(x['owner']==name for x in full['a'])and full['answer_count']==len(expected)
def probe(profile,label):
 resolver,zone,target,prefix=PROFILES[profile];name=label+'.'+zone;id=secrets.randbelow(65536);wire=struct.pack('!6H',id,0x100,1,0,0,0)+question(name)
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM)as s:
  s.settimeout(4);s.bind((SOURCE,0));s.sendto(wire,(resolver,53));data,peer=s.recvfrom(65535)
 if peer!=(resolver,53):raise ValueError('DNS exact resolver response')
 udp=response(data,id,name,False);fallback=udp['tc'];full=response(tcp_query(resolver,wire),id,name,True)if fallback else response(data,id,name,True)
 ok=validate_answers(full,profile,label)
 if fallback:ok=ok and udp['rcode']==full['rcode']
 if label=='large':ok=ok and fallback and udp['rcode']==full['rcode']and full['answer_count']==40
 return {'profile':profile,'source':SOURCE,'resolver':resolver,'name':name,'query_has_edns':False,'udp':udp,'tcp_fallback_used':fallback,'full':full,'accepted':ok,'scope':'ordinary fixed wire DNS only; separate API lease/guard/FQDN evidence required'}
def main():
 p=argparse.ArgumentParser();p.add_argument('--profile',choices=PROFILES,required=True);p.add_argument('--receipt',required=True);a=p.parse_args()
 parent=pathlib.Path(a.receipt).parent;s=os.lstat(parent)
 if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.getuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('private receipt parent')
 fd=os.open(a.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);r={'started':True,'profile':a.profile,'completed':False,'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'results':[]}
 try:
  for name in ['app','alias','nx-qualification','large']:r['results'].append(probe(a.profile,name))
  r.update(completed=True,accepted=all(x['accepted']for x in r['results']))
 except Exception as e:r.update(accepted=False,error_type=type(e).__name__);raise
 finally:
  with os.fdopen(fd,'w')as f:json.dump(r,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
if __name__=='__main__':
 try:main()
 except Exception as e:raise SystemExit('Owned DNS wire probe refused: '+type(e).__name__)
