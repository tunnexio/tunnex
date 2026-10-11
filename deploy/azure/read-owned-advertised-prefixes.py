#!/usr/bin/env python3
"""Bounded bastion-only Azure advertised-route read. No mutation or native proof."""
from datetime import datetime,timezone
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import subprocess

spec=importlib.util.spec_from_file_location('advertised_shared',Path(__file__).with_name('convert-owned-standby.py'))
shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)
lab=shared.lab

def parse(raw):
 if not isinstance(raw,bytes) or not 1<=len(raw)<=262144:raise ValueError('response bounds')
 def unique(items):
  result={}
  for key,value in items:
   if key in result:raise ValueError('duplicate JSON member')
   result[key]=value
  return result
 value=json.loads(raw,object_pairs_hook=unique)
 if isinstance(value,dict):
  if set(value)-{'value','nextLink'} or value.get('nextLink') or not isinstance(value.get('value'),list):raise ValueError('complete documented route result required')
  rows=value['value'];schema='sdk_value_list'
 elif isinstance(value,list):rows=value;schema='cli_flattened_list'
 else:raise ValueError('route response shape')
 if len(rows)>64:raise ValueError('route row bound')
 prefixes=[]
 for row in rows:
  if not isinstance(row,dict) or set(row)-{'network','localAddress','nextHop','sourcePeer','origin','asPath','weight'} or not isinstance(row.get('network'),str):raise ValueError('documented route row required')
  prefix=ipaddress.ip_network(row['network'],strict=True)
  if prefix.version!=4 or str(prefix)!=row['network']:raise ValueError('canonical IPv4 route required')
  prefixes.append(str(prefix))
 return {'response_schema':schema,'route_count':len(rows),'prefixes':sorted(set(prefixes))}

def read():
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 discovery=lab.discover(lab.SUBSCRIPTION,shared.CONNECTION)
 view=lab.az('network','vpn-connection','show','--ids',shared.CONNECTION,'--subscription',lab.SUBSCRIPTION,'--query',shared.helpers.QUERY)
 if shared.helpers.projection(view,discovery)['mode']!='Default' or not discovery['enable_bgp']:raise ValueError('owned Default BGP connection required')
 peer=str(ipaddress.IPv4Address(discovery['customer_bgp_address']))
 if peer!='169.254.10.1':raise ValueError('exact owned customer peer')
 # Do not assume CLI flattening: retain bounded response privately in memory,
 # then accept only the documented value[] or independently explicit list shape.
 result=subprocess.run(['az','network','vnet-gateway','list-advertised-routes','-g',lab.RG,'-n','azure-vpn','--subscription',lab.SUBSCRIPTION,'--peer',peer,'--only-show-errors','-o','json'],capture_output=True,timeout=65)
 if result.returncode:raise ValueError('advertised CLI read failed')
 if len(result.stdout)+len(result.stderr)>262144:raise ValueError('advertised output bounds')
 projection=parse(result.stdout)
 return {'version':1,'kind':'owned_azure_advertised_routes','observed_at':datetime.now(timezone.utc).isoformat(),'subscription':lab.SUBSCRIPTION,'resource_group':lab.RG,'owner':lab.OWNER,'gateway_id':discovery['gateway_id'],'query_peer':peer,**projection,'scope':'Azure control-plane advertised-route read only; no received NLRI, native BGP acceptance, installed route, maximum-prefix or packet authority'}

if __name__=='__main__':
 try:print(json.dumps(read(),sort_keys=True))
 except subprocess.TimeoutExpired:print('{"version":1,"category":"advertised_read_unavailable","stage":"read_timeout"}');raise SystemExit(1)
 except (ValueError,KeyError,TypeError,OSError):print('{"version":1,"category":"advertised_read_unavailable","stage":"ownership_command_or_schema_refused"}');raise SystemExit(1)
