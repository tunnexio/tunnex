#!/usr/bin/env python3
"""Bounded actual-packet observation, run by root inside the owned client namespace."""
import argparse
import errno
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time

TARGET='10.231.1.4'
LARGE_BODY=b'0123456789abcdef'*4096

def udp_payload(size,nonce):
 prefix=('azure-owned-probe-'+str(nonce)+':').encode()
 if size not in (64,1200,1362,2000,4096) or len(prefix)>size:raise ValueError('Bounded UDP payload required')
 padding=(b'0123456789abcdef'*((size+15)//16))[:size-len(prefix)]
 return prefix+padding

def udp_echo(connection,payload):
 # Only fixed categories and explicitly allowed errno values enter receipts.
 stage='send'
 try:
  sent=connection.send(payload)
  stage='receive'
  answer=connection.recv(4097)
  return {'success':answer==payload,'sent_bytes':sent,'echo_bytes':len(answer),'echo_exact_match':answer==payload,'local_port':connection.getsockname()[1]}
 except OSError as error:
  result={'success':False,'udp_error_stage':stage,'error_code':'udp_socket_error'}
  if isinstance(error,TimeoutError):result['error_code']='udp_timeout'
  elif error.errno==errno.EMSGSIZE:result.update(error_code='udp_message_too_large',socket_errno=errno.EMSGSIZE)
  elif error.errno in (errno.ECONNREFUSED,errno.ENETUNREACH,errno.EHOSTUNREACH):result['socket_errno']=error.errno
  if stage=='receive':result['sent_bytes']=sent
  return result

def stamp():return datetime.now(timezone.utc).isoformat()
def receipt(path,value):
 if path.is_symlink() or path.parent.is_symlink():raise ValueError('Symlink receipt refused')
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 with os.fdopen(fd,'w') as out:json.dump(value,out,indent=2)
 path.chmod(0o600)

def observed_http_identity(body, expected_source, expected_service="azure-s2s-owned-app"):
 result={'owned_service_confirmed':False,'source_preservation':'diagnostic_unknown'}
 try:
  if len(body)>16384: return result
  value=json.loads(body)
  if not isinstance(value,dict) or value.get('service')!=expected_service:return result
  result['owned_service_confirmed']=True
  raw=value.get('client_ip')
  if not isinstance(raw,str):return result
  address=ipaddress.ip_address(raw)
  if address.version!=4 or str(address)!=raw:return result
  # The response is untrusted: retain only bounded owned/LAN/Docker addresses.
  if address in ipaddress.ip_network('10.233.10.0/24') or raw=='10.231.1.4':
   result['server_observed_client_ip']=raw
   result['source_preservation']='preserved' if raw==expected_source else 'owned_lan_source_mismatch'
  elif raw=='10.232.1.4' or address in ipaddress.ip_network('172.16.0.0/12'):
   result['server_observed_client_ip']=raw
   result['source_preservation']='nat_source_mismatch'
  else:result['source_preservation']='unrecognized_source_mismatch'
 except (ValueError,UnicodeError):pass
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--direction',choices=['forward','reverse'],default='forward')
 p.add_argument('--source',choices=['10.233.10.2','10.233.10.3','10.231.1.4'],required=True)
 p.add_argument('--receipt',type=Path,required=True)
 p.add_argument('--seconds',type=int,default=60)
 p.add_argument('--interval',type=float,default=1.0)
 p.add_argument('--timeout',type=float,default=1.0)
 p.add_argument('--udp-bytes',type=int,choices=[64,1200,1362,2000,4096],default=64)
 p.add_argument('--tcp-large',action='store_true',help='Verify owned identity then exact64KiB /large on the same TCP socket')
 p.add_argument('--dns-resolver',action='append',default=[],help='Explicit actual proxy/resolver IPv4; repeat for each boundary')
 a=p.parse_args()
 if not 1<=a.seconds<=60 or not .2<=a.interval<=5 or not .2<=a.timeout<=2:raise ValueError('Bounded duration/interval/timeout required')
 if (a.direction=='reverse') != (a.source=='10.231.1.4'):raise ValueError('Direction requires actual bounded source')
 target,tcp_port,udp_port,service=(TARGET,8080,8081,'azure-s2s-owned-app') if a.direction=='forward' else ('10.233.10.2',8082,8083,'azure-s2s-owned-lan-app')
 if a.direction=='reverse' and a.dns_resolver:raise ValueError('Reverse probe has no DNS context')
 for resolver in a.dns_resolver:
  if resolver not in ('10.231.2.4','10.231.2.20','10.233.10.1'):raise ValueError('Unrelated DNS resolver refused')
 # Fail early if the actual namespace does not own the selected source.
 check=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);check.bind((a.source,0));check.close()
 start=time.monotonic();end=start+a.seconds
 output={'started_at':stamp(),'source_address':a.source,'direction':a.direction,'udp_payload_bytes':a.udp_bytes,'tcp_large_requested':a.tcp_large,'service':{'address':target,'tcp_port':tcp_port,'udp_port':udp_port},'packet_duration_bound_seconds':a.seconds,'dns_queries_run_after_packet_window':True,'scope':'Actual packet observations only; no capability, policy, health or cloud readiness inference','samples':[],'dns':[]}
 tcp=None;udp=None
 counters={key:{'success':0,'failure':0,'last_success_monotonic':None,'maximum_observed_success_gap_seconds':0} for key in ('fresh_tcp','existing_tcp','fresh_udp','existing_udp')}
 def observe(key,operation):
  before=time.monotonic();entry={'kind':key,'observed_at':stamp(),'monotonic_elapsed_seconds':round(before-start,6)}
  try:
   details=operation();entry.update(details);entry.setdefault('success',True)
  except (OSError,http.client.HTTPException,ValueError):entry.update(success=False,error_code='packet_failed')
  entry['elapsed_seconds']=round(time.monotonic()-before,6);output['samples'].append(entry)
  counter=counters[key];counter['success' if entry['success'] else 'failure']+=1
  if entry['success']:
   previous=counter['last_success_monotonic']
   if previous is not None:counter['maximum_observed_success_gap_seconds']=max(counter['maximum_observed_success_gap_seconds'],before-previous)
   counter['last_success_monotonic']=before
 def new_tcp():return http.client.HTTPConnection(target,tcp_port,timeout=a.timeout,source_address=(a.source,0))
 def request(connection):
  connection.request('GET','/',headers={'Connection':'keep-alive'})
  local_port=connection.sock.getsockname()[1] if connection.sock else None
  response=connection.getresponse();status=response.status;version=response.version;will_close=response.will_close;body=response.read(16385)
  identity=observed_http_identity(body,a.source,service)
  result={**identity,'success':200<=status<400 and identity['owned_service_confirmed'] and identity['source_preservation']=='preserved','http_response_success':200<=status<400,'http_status':status,'http_version':version,'local_port':local_port,'server_closes_connection':will_close}
  if a.tcp_large:
   connection.request('GET','/large',headers={'Connection':'keep-alive'})
   large_port=connection.sock.getsockname()[1] if connection.sock else None
   large=connection.getresponse();data=large.read(65537)
   matched=data==LARGE_BODY and large.getheader('Content-Length')=='65536'
   result.update(large_http_status=large.status,large_received_bytes=len(data),large_exact_match=matched,large_same_socket=(large_port==local_port and not will_close))
   result['success']=result['success'] and large.status==200 and matched and result['large_same_socket']
  return result
 def fresh_tcp():
  connection=new_tcp()
  try:return request(connection)
  finally:connection.close()
 def existing_tcp():
  nonlocal tcp
  reused=tcp is not None and tcp.sock is not None
  if tcp is None:tcp=new_tcp()
  try:
   result=request(tcp);result['reused_existing_socket']=reused;return result
  except (OSError,http.client.HTTPException,ValueError):
   tcp.close();tcp=None;raise
 def new_udp():
  connection=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);connection.settimeout(a.timeout);connection.bind((a.source,0));connection.connect((target,udp_port));return connection
 def echo(connection):
  return udp_echo(connection,udp_payload(a.udp_bytes,time.monotonic_ns()))
 def fresh_udp():
  connection=new_udp()
  try:return echo(connection)
  finally:connection.close()
 def existing_udp():
  nonlocal udp
  reused=udp is not None
  if udp is None:udp=new_udp()
  result=echo(udp);result['reused_existing_socket']=reused;return result
 try:
  while time.monotonic()<end:
   tick=time.monotonic()
   for key,operation in [('fresh_tcp',fresh_tcp),('existing_tcp',existing_tcp),('fresh_udp',fresh_udp),('existing_udp',existing_udp)]:
    if time.monotonic()>=end:break
    observe(key,operation)
   time.sleep(min(max(0,a.interval-(time.monotonic()-tick)),max(0,end-time.monotonic())))
 finally:
  if tcp:tcp.close()
  if udp:udp.close()
  for key,counter in counters.items():
   last=counter.pop('last_success_monotonic')
   counter['seconds_since_last_success_at_run_end']=None if last is None else round(time.monotonic()-last,6)
   counter['maximum_observed_success_gap_seconds']=round(counter['maximum_observed_success_gap_seconds'],6)
  output['counters']=counters;output['packet_finished_at']=stamp();output['packet_run_elapsed_seconds']=round(time.monotonic()-start,6)
  receipt(a.receipt,output)
 for resolver in a.dns_resolver:
  for name,qtype in [('app.azure-s2s.test','A'),('service.azure-s2s.test','A'),('service.azure-s2s.test','CNAME'),('absent-owned.azure-s2s.test','A'),('large.azure-s2s.test','TXT')]:
   for transport in ('udp','tcp'):
    entry={'observed_at':stamp(),'source_address':a.source,'resolver':resolver,'name':name,'query_type':qtype,'requested_transport':transport}
    command=['dig','-b',a.source,'@'+resolver,name,qtype,'+time=1','+tries=1','+noall','+comments','+answer']
    if transport=='tcp':command.append('+tcp')
    elif qtype=='TXT':command.append('+bufsize=512')
    before=time.monotonic()
    try:
     run=subprocess.run(command,capture_output=True,text=True,timeout=4,check=False)
     text=run.stdout;match=re.search(r'status: ([A-Z]+)',text)
     entry.update(exit_code=run.returncode,rcode=match.group(1) if match else None,tcp_fallback_observed=('retrying in TCP mode' in text),truncated_flag_observed=bool(re.search(r'flags:[^;]*\btc\b',text)))
     lines=[line for line in text.splitlines() if line and not line.startswith(';')]
     entry['answer_count']=len(lines)
     # Record only expected nonsecret A/CNAME facts and TXT byte count, never TXT text.
     entry['answers']=[{'type':parts[3],'value':parts[4]} for line in lines if len(parts:=line.split())>=5 and parts[3] in ('A','CNAME')]
     entry['txt_payload_bytes']=sum(sum(len(piece.encode()) for piece in shlex.split(line.split('TXT',1)[1])) for line in lines if '\tTXT\t' in line or ' TXT ' in line)
    except (OSError,subprocess.TimeoutExpired):entry.update(error_code='dns_probe_unavailable')
    entry['elapsed_seconds']=round(time.monotonic()-before,6);output['dns'].append(entry);receipt(a.receipt,output)
 output['finished_at']=stamp();receipt(a.receipt,output)
 print(json.dumps({'receipt':str(a.receipt),'source_address':a.source,'counters':counters,'dns_queries':len(output['dns'])}))

if __name__=='__main__':
 try:main()
 except (OSError,ValueError):raise SystemExit('Probe prerequisite/input failed; no packet success claim')
