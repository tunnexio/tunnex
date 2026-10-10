#!/usr/bin/env python3
"""Read-only classic PCAP decoder; exact owned Azure IPv4 BGP candidate evidence only."""
import argparse
from datetime import datetime,timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import stat
import struct

PEERS={'169.254.21.2','169.254.22.2'}
LOCAL='169.254.10.1'
CANDIDATE='10.235.77.0/24'
MAX_FILE=4*1024*1024
MAX_PACKETS=8192
MAX_STREAM=262144
MAX_EVENTS=128


def timestamp(seconds,fraction,nano):
 limit=1000000000 if nano else 1000000
 if not 946684800<=seconds<=4102444800 or not 0<=fraction<limit:raise ValueError('timestamp bounds')
 return datetime.fromtimestamp(seconds,timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')+'.'+str(fraction*(1 if nano else 1000)).zfill(9)+'Z'


def nlri(raw):
 result=[];offset=0
 while offset<len(raw):
  bits=raw[offset];offset+=1
  if bits>32:raise ValueError('IPv4 NLRI length')
  size=(bits+7)//8
  if offset+size>len(raw):raise ValueError('truncated NLRI')
  address=raw[offset:offset+size]+bytes(4-size);offset+=size
  network=ipaddress.ip_network(str(ipaddress.IPv4Address(address))+'/'+str(bits),strict=True)
  result.append(str(network))
 return result


def aspath_shape(raw):
 if not raw:return True
 for width in (2,4):
  offset=0
  while offset<len(raw):
   if offset+2>len(raw) or raw[offset] not in (1,2,3,4) or raw[offset+1]==0:break
   offset+=2+width*raw[offset+1]
  if offset==len(raw):return True
 return False


def update(raw):
 if len(raw)<4:raise ValueError('UPDATE length')
 withdrawn_len=struct.unpack('!H',raw[:2])[0]
 if withdrawn_len+4>len(raw):raise ValueError('withdrawn length')
 withdrawals=nlri(raw[2:2+withdrawn_len]);offset=2+withdrawn_len
 attributes_len=struct.unpack('!H',raw[offset:offset+2])[0];offset+=2
 end=offset+attributes_len
 if end>len(raw):raise ValueError('attribute length')
 advertisements=nlri(raw[end:]);seen=set()
 while offset<end:
  if offset+3>end:raise ValueError('attribute header')
  flags,kind=raw[offset:offset+2];offset+=2
  if flags&0x0f:raise ValueError('reserved attribute flags')
  extended=bool(flags&0x10);size_bytes=2 if extended else 1
  if offset+size_bytes>end:raise ValueError('attribute size')
  size=int.from_bytes(raw[offset:offset+size_bytes],'big');offset+=size_bytes
  if offset+size>end or kind==0 or kind in seen:raise ValueError('attribute shape')
  seen.add(kind);value=raw[offset:offset+size];offset+=size
  if kind in (1,2,3) and flags&0xe0!=0x40:raise ValueError('mandatory attribute flags')
  if kind==1 and (len(value)!=1 or value[0]>2):raise ValueError('ORIGIN shape')
  if kind==2 and not aspath_shape(value):raise ValueError('AS_PATH shape')
  if kind==3 and len(value)!=4:raise ValueError('NEXT_HOP shape')
  if kind in (4,5) and len(value)!=4:raise ValueError('integer attribute shape')
  if kind==6 and value:raise ValueError('ATOMIC_AGGREGATE shape')
  if kind==8 and len(value)%4:raise ValueError('community shape')
  if kind in (14,15):
   if len(value)<3:raise ValueError('MP attribute header')
   afi=int.from_bytes(value[:2],'big');safi=value[2]
   if afi==1 and safi==1:
    if kind==15:withdrawals.extend(nlri(value[3:]));continue
    if len(value)<5:raise ValueError('MP reach header')
    hop=value[3]
    if hop not in (4,16,32) or len(value)<5+hop or value[4+hop]!=0:raise ValueError('MP reach shape')
    advertisements.extend(nlri(value[5+hop:]))
 if advertisements and not {1,2}.issubset(seen):raise ValueError('missing mandatory attributes')
 if nlri(raw[end:]) and 3 not in seen:raise ValueError('missing NEXT_HOP')
 if CANDIDATE in advertisements and CANDIDATE in withdrawals:raise ValueError('ambiguous same UPDATE')
 return advertisements,withdrawals


def frame(raw,link):
 if link==1:
  if len(raw)<14:raise ValueError('Ethernet header')
  protocol=int.from_bytes(raw[12:14],'big');offset=14
  # Bound ordinary802.1Q/QinQ encapsulation; never guess an unknown framing.
  for unused in range(2):
   if protocol not in (0x8100,0x88a8):break
   if len(raw)<offset+4:raise ValueError('VLAN header')
   protocol=int.from_bytes(raw[offset+2:offset+4],'big');offset+=4
 elif link==113:
  if len(raw)<16:raise ValueError('SLL header')
  protocol=int.from_bytes(raw[14:16],'big');offset=16
 elif link==276:
  if len(raw)<20:raise ValueError('SLL2 header')
  protocol=int.from_bytes(raw[:2],'big');offset=20
 else:raise ValueError('unsupported link type')
 if protocol!=0x0800:return None
 raw=raw[offset:]
 if len(raw)<20 or raw[0]>>4!=4:raise ValueError('IPv4 header')
 header=(raw[0]&15)*4;total=int.from_bytes(raw[2:4],'big')
 if header<20 or total<header or total>len(raw):raise ValueError('IPv4 bounds')
 source=str(ipaddress.IPv4Address(raw[12:16]));destination=str(ipaddress.IPv4Address(raw[16:20]))
 if source not in PEERS or destination!=LOCAL:return None
 if int.from_bytes(raw[6:8],'big')&0x3fff:raise ValueError('fragmented owned IPv4')
 if raw[9]!=6:return None
 tcp=raw[header:total]
 if len(tcp)<20:raise ValueError('TCP header')
 sport,dport,seq=struct.unpack('!HHI',tcp[:8]);length=(tcp[12]>>4)*4
 if length<20 or length>len(tcp):raise ValueError('TCP bounds')
 if 179 not in (sport,dport):return None
 if sport==0 or dport==0 or tcp[13]&0x24:raise ValueError('TCP reset/port')
 payload=tcp[length:];syn=bool(tcp[13]&2)
 if seq+int(syn)+len(payload)>0xffffffff:raise ValueError('sequence wrap unsupported')
 return (source,sport,dport),seq+int(syn),payload,syn


def decode(data):
 if not isinstance(data,bytes) or len(data)<24 or len(data)>MAX_FILE:raise ValueError('capture bounds')
 formats={b'\xd4\xc3\xb2\xa1':('<',False),b'\xa1\xb2\xc3\xd4':('>',False),b'\x4d\x3c\xb2\xa1':('<',True),b'\xa1\xb2\x3c\x4d':('>',True)}
 if data[:4] not in formats:raise ValueError('classic PCAP required')
 endian,nano=formats[data[:4]];major,minor,zone,sigfigs,snaplen,link=struct.unpack(endian+'HHiIII',data[4:24])
 if (major,minor)!=(2,4) or zone!=0 or link not in (1,113,276) or not 64<=snaplen<=262144:raise ValueError('PCAP header')
 offset=24;count=0;streams={};times=[]
 while offset<len(data):
  if offset+16>len(data):raise ValueError('packet header')
  seconds,fraction,included,original=struct.unpack(endian+'IIII',data[offset:offset+16]);offset+=16
  count+=1
  if count>MAX_PACKETS or included!=original or included>snaplen or included<1 or offset+included>len(data):raise ValueError('packet bounds/truncation')
  stamp=timestamp(seconds,fraction,nano);times.append(stamp)
  parsed=frame(data[offset:offset+included],link);offset+=included
  if parsed is None:continue
  key,seq,payload,syn=parsed
  if key not in streams:
   if len(streams)>=8:raise ValueError('flow bounds')
   streams[key]={'segments':[],'syn':None}
  stream=streams[key]
  if syn:
   if stream['syn'] is not None and stream['syn']!=seq:raise ValueError('tuple reuse')
   stream['syn']=seq
  if payload:stream['segments'].append((seq,payload,stamp))
 events=[];messages=0;payload_streams=0;duplicates=0
 for key,stream in streams.items():
  segments=stream['segments']
  if not segments:continue
  payload_streams+=1;start=min(v[0] for v in segments);end=max(v[0]+len(v[1]) for v in segments)
  if end-start>MAX_STREAM:raise ValueError('stream bounds')
  if stream['syn'] is not None and stream['syn']!=start:raise ValueError('SYN stream gap')
  content=bytearray(end-start);present=bytearray(end-start);observed=[None]*(end-start)
  for seq,payload,stamp in segments:
   for index,value in enumerate(payload,seq-start):
    if present[index]:
     if content[index]!=value:raise ValueError('conflicting retransmission')
     duplicates+=1;observed[index]=min(observed[index],stamp)
    else:content[index]=value;present[index]=1;observed[index]=stamp
  if not all(present):raise ValueError('TCP gap')
  offset=0
  while offset<len(content):
   if len(content)-offset<19 or content[offset:offset+16]!=bytes([255])*16:raise ValueError('midstream/incomplete BGP alignment')
   length=int.from_bytes(content[offset+16:offset+18],'big');kind=content[offset+18]
   if not 19<=length<=4096 or offset+length>len(content) or kind not in (1,2,3,4,5):raise ValueError('BGP bounds/type')
   if (kind==4 and length!=19) or (kind==1 and length<29) or (kind==3 and length<21) or (kind==5 and length!=23):raise ValueError('BGP control length')
   messages+=1
   if kind==1:
    body=content[offset+19:offset+length]
    if body[0]!=4 or body[9]==255 or len(body)!=10+body[9]:raise ValueError('OPEN shape/extended options unsupported')
    option=10
    while option<len(body):
     if option+2>len(body) or option+2+body[option+1]>len(body):raise ValueError('OPEN option bounds')
     option+=2+body[option+1]
   if kind==2:
    advertisements,withdrawals=update(bytes(content[offset+19:offset+length]))
    for action,prefixes in [('advertisement',advertisements),('withdrawal',withdrawals)]:
     if CANDIDATE in prefixes:
      events.append({'peer':key[0],'candidate':CANDIDATE,'action':action,'observed_at':max(observed[offset:offset+length])})
      if len(events)>MAX_EVENTS:raise ValueError('event bounds')
   offset+=length
 return {'version':1,'kind':'owned_bgp_candidate_capture','capture_sha256':hashlib.sha256(data).hexdigest(),'link_type':link,'capture_first_packet_at':min(times) if times else None,'capture_last_packet_at':max(times) if times else None,'packet_count':count,'payload_stream_count':payload_streams,'bgp_message_count':messages,'duplicate_byte_count':duplicates,'candidate':CANDIDATE,'events':sorted(events,key=lambda event:(event['observed_at'],event['peer'],event['action'])),'scope':'observed wire NLRI only; not peer authentication, policy rejection or native authority'}


def private_parent(path):
 path=Path(path).absolute();info=path.parent.lstat()
 if path.parent!=path.parent.resolve() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private parent')
 return path

def private_input(path):
 path=private_parent(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>MAX_FILE:raise ValueError('capture file metadata')
  data=stream.read(MAX_FILE+1)
 if len(data)>MAX_FILE:raise ValueError('capture file bounds')
 return data

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--capture',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 output=private_parent(args.output)
 if output.exists() or output.is_symlink():raise ValueError('new output required')
 result=decode(private_input(args.capture))
 fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as stream:json.dump(result,stream);stream.flush();os.fsync(stream.fileno())
 print('{"version":1,"capture_projection_written":true}')

if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,struct.error):
  print('{"version":1,"capture_projection":"refused"}');raise SystemExit(1)
