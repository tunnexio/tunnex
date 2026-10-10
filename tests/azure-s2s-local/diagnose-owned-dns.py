#!/usr/bin/env python3
"""Read-only key-free owned gateway DNS configuration and header census."""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
from datetime import datetime,timezone
spec=importlib.util.spec_from_file_location('gated',Path(__file__).with_name('assemble-gated-restoration.py'))
gated=importlib.util.module_from_spec(spec);spec.loader.exec_module(gated)
SOURCE='10.233.10.1';RESOLVERS=('10.231.2.4','10.231.2.20')

def project(material,desired):
 policy=material['policy'];manifest=material['manifest'];grants=policy.get('dns_resolver_grants',[]);profiles=policy.get('dns_resolver_profiles',[])
 if not isinstance(grants,list) or len(grants)>64 or not isinstance(profiles,list) or len(profiles)>64:raise ValueError('bounded DNS policy')
 output={'dns_grant_count':len(grants),'dns_profile_count':len(profiles),'known_source_endpoint_grant_counts':{address:sum(g.get('source_address')==SOURCE and g.get('resolver_address')==address and g.get('connection_id')==manifest['connection_id'] and g.get('configuration_revision')==manifest['configuration_revision'] for g in grants) for address in RESOLVERS}}
 request=desired.get('dns_resolve_request')
 output['pending_request_present']=isinstance(request,dict)
 if not isinstance(request,dict):return output
 path=request.get('resolver_ipsec_path') or {}
 output['request_source_matches']=path.get('source_address')==SOURCE
 output['request_connection_revision_matches']=path.get('connection_id')==manifest['connection_id'] and path.get('configuration_revision')==manifest['configuration_revision']
 deadline=datetime.fromisoformat(request['deadline'].replace('Z','+00:00'));output['request_deadline_remaining']=deadline>datetime.now(timezone.utc)
 endpoints=request.get('resolver_endpoints',[])
 output['request_known_endpoint_count']=sum(e.get('address') in RESOLVERS and e.get('port')==53 and e.get('transport') in ('udp','tcp') for e in endpoints)
 output['request_exact_bound_grant_counts']={address:sum(g.get('source_address')==SOURCE and g.get('resolver_address')==address and g.get('context_config_id')==request.get('resolver_config_id') and g.get('context_config_version')==request.get('resolver_config_version') and g.get('profile_id')==request.get('resolver_profile_id') and g.get('connection_id')==path.get('connection_id') and g.get('configuration_revision')==path.get('configuration_revision') for g in grants) for address in RESOLVERS}
 return output

def header_counts(raw):
 counts={address:{'requests':0,'responses':0} for address in RESOLVERS}
 for line in raw.decode(errors='replace').splitlines():
  for address in RESOLVERS:
   if re.search(r'\b'+re.escape(SOURCE)+r'\.\d+ > '+re.escape(address)+r'\.53: UDP',line):counts[address]['requests']+=1
   if re.search(r'\b'+re.escape(address)+r'\.53 > '+re.escape(SOURCE)+r'\.\d+: UDP',line):counts[address]['responses']+=1
 return counts

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--container',required=True)
 p.add_argument('--material-file',type=Path,required=True);p.add_argument('--desired-file',type=Path,required=True)
 p.add_argument('--journal',type=Path,required=True);p.add_argument('--capture-seconds',type=int,default=0)
 p.add_argument('--node-log',type=Path)
 a=p.parse_args();stage='private_inputs'
 try:
  if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer' or not 0<=a.capture_seconds<=30:raise ValueError('owned bounded root host')
  material=json.loads(gated.private_bytes(a.material_file,2<<20));desired=json.loads(gated.private_bytes(a.desired_file,2<<20));journal=json.loads(gated.private_bytes(a.journal,16<<20))
  output={'stage':'owned_dns_read_only','observed_at':gated.stamp(),'configuration':project(material,desired)}
  def command(*args):return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout
  cid=command('docker','inspect','--format','{{.Id}}',a.container).decode().strip()
  if not re.fullmatch('[0-9a-f]{64}',cid) or command('docker','inspect','--format','{{index .Config.Labels "tunnex.owner"}}',cid).decode().strip()!=gated.OWNER:raise ValueError('owned container')
  pid=int(command('docker','inspect','--format','{{.State.Pid}}',cid))
  if pid<=0:raise ValueError('running namespace')
  ns=os.readlink('/proc/%d/ns/net'%pid)
  entries=[e for e in journal['Payload']['Entries'] if e['DeliveryID']==material['id'] and e['Phase']=='applied']
  if len(entries)!=1 or entries[0]['Allocation']['Namespace']!=ns:raise ValueError('exact applied namespace')
  entry=entries[0]
  def native(*args):return command('nsenter','-t',str(pid),'-n',*args)
  stage='source_route_observation'
  addresses=json.loads(native('ip','-j','address','show'))
  sources=[link for link in addresses if any(item.get('local')==SOURCE for item in link.get('addr_info',[]))]
  output['source_assigned_once']=len(sources)==1
  output['source_on_owned_lan_or_loopback']=len(sources)==1 and sources[0]['ifname'] in ('az-s2s-lan','lo')
  output['route_matches_recorded_slot']={}
  for address in RESOLVERS:
   routes=json.loads(native('ip','-j','-4','route','get',address,'from',SOURCE))
   owned=[r for r in (entry.get('BGPRoutes') or {}).get('Owned',[]) if ipaddress.ip_address(address) in ipaddress.ip_network(r['Prefix'])]
   owned.sort(key=lambda r:ipaddress.ip_network(r['Prefix']).prefixlen,reverse=True)
   expected=entry['Observed'][owned[0]['Slot']-1]['InterfaceName'] if owned else None
   output['route_matches_recorded_slot'][address]=len(routes)==1 and expected is not None and routes[0].get('dev')==expected and routes[0].get('from')==SOURCE and routes[0].get('prefsrc',SOURCE)==SOURCE and routes[0].get('dst')==address and 'gateway' not in routes[0]
  if a.node_log:
   logs=gated.private_bytes(a.node_log,8<<20).splitlines();count=0
   for line in logs:
    try:value=json.loads(line)
    except (ValueError,TypeError):continue
    if isinstance(value,dict) and value.get('msg')=='fqdn_resolution_response_delivery_failed':count+=1
   output['known_response_delivery_failure_count']=count
  if a.capture_seconds:
   stage='bounded_header_census'
   predicate='udp port 53 and host 10.233.10.1 and (host 10.231.2.4 or host 10.231.2.20)'
   result=subprocess.run(['nsenter','-t',str(pid),'-n','timeout',str(a.capture_seconds),'tcpdump','-nn','-q','-l','-i','any','-c','120',predicate],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=a.capture_seconds+5,check=False)
   if result.returncode not in (0,124):raise ValueError('header census unavailable')
   output['udp53_header_counts']=header_counts(result.stdout);output['capture_seconds_bound']=a.capture_seconds
  if int(command('docker','inspect','--format','{{.State.Pid}}',cid))!=pid or os.readlink('/proc/%d/ns/net'%pid)!=ns:raise ValueError('namespace changed')
  output['scope']='observations only; no runtime grant, mailbox delivery, DNS authority or acceptance inferred'
  print(json.dumps(output,sort_keys=True));return 0
 except (OSError,ValueError,KeyError,TypeError,IndexError,subprocess.SubprocessError):
  print(json.dumps({'stage':stage,'error_code':'owned_dns_diagnostic_refused','observed_at':gated.stamp()}));return 1
if __name__=='__main__':raise SystemExit(main())
