#!/usr/bin/env python3
"""Root-reviewed bastion-only owned discovery/AA-static update. Never prints keys."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import socket
import stat
import uuid

RG='tunnex-azure-s2s-20261010'
OWNER='azure-s2s-01a12505'
SUBSCRIPTION='34e2f259-b462-40bf-8f4a-06a3930d99e6'


def resource_id(value,subscription,kind):
 pattern='/subscriptions/'+re.escape(subscription)+'/resourceGroups/'+RG+'/providers/Microsoft.Network/'+kind+'/[A-Za-z0-9_.-]+'
 if not isinstance(value,str) or not re.fullmatch(pattern,value,re.IGNORECASE):raise ValueError('exact owned resource ID')
 return value


def az(*args):
 run=subprocess.run(['az',*args,'--only-show-errors','-o','json'],capture_output=True,text=True,timeout=180)
 if run.returncode or len(run.stdout)>262144:raise ValueError('Azure CLI operation refused')
 return json.loads(run.stdout) if run.stdout.strip() else None


def owned(value,expected):
 if value.get('id','').lower()!=expected.lower() or value.get('owner')!=OWNER:raise ValueError('resource ownership')
 return value


def discover(subscription,connection_id):
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 if subscription!=SUBSCRIPTION:raise ValueError('authorized subscription required')
 if az('account','show','--query','id')!=subscription:raise ValueError('subscription mismatch')
 group=az('group','show','-n',RG,'--subscription',subscription,'--query','{id:id,owner:tags.owner}')
 owned(group,'/subscriptions/'+subscription+'/resourceGroups/'+RG)
 connection_id=resource_id(connection_id,subscription,'connections')
 connection=owned(az('network','vpn-connection','show','--ids',connection_id,'--query','{id:id,owner:tags.owner,gateway:virtualNetworkGateway1.id,lng:localNetworkGateway2.id,bgp:enableBgp,protocol:connectionProtocol,type:connectionType,selectors:usePolicyBasedTrafficSelectors,ingress:ingressNatRules,egress:egressNatRules,policies:ipsecPolicies,state:provisioningState}'),connection_id)
 gateway_id=resource_id(connection['gateway'],subscription,'virtualNetworkGateways');lng_id=resource_id(connection['lng'],subscription,'localNetworkGateways')
 gateway=owned(az('network','vnet-gateway','show','--ids',gateway_id,'--query','{id:id,owner:tags.owner,active:activeActive,sku:sku.name,vpn: vpnType,asn:bgpSettings.asn,peers:bgpSettings.bgpPeeringAddresses,configs:ipConfigurations,state:provisioningState}'),gateway_id)
 lng=owned(az('network','local-gateway','show','--ids',lng_id,'--query','{id:id,owner:tags.owner,outside:gatewayIpAddress,asn:bgpSettings.asn,bgp:bgpSettings.bgpPeeringAddress,prefixes:localNetworkAddressSpace.addressPrefixes,state:provisioningState}'),lng_id)
 if any(value.get('state')!='Succeeded' for value in (connection,gateway,lng)):raise ValueError('provisioning incomplete')
 if gateway['vpn']!='RouteBased' or gateway['sku'] not in ['VpnGw'+str(n)+suffix for n in range(1,6) for suffix in ('','AZ')]:raise ValueError('gateway contract')
 if connection['type']!='IPsec' or connection['protocol']!='IKEv2' or connection['selectors'] is not False or connection.get('ingress') or connection.get('egress'):raise ValueError('connection contract')
 policies=connection['policies']
 required={'ikeEncryption':'AES256','ikeIntegrity':'SHA256','dhGroup':'DHGroup14','ipsecEncryption':'AES256','ipsecIntegrity':'SHA256','pfsGroup':'PFS2048'}
 if len(policies)!=1 or any(policies[0].get(key)!=value for key,value in required.items()):raise ValueError('custom policy contract')
 configs=gateway['configs']
 if type(gateway['active'])!=bool or len(configs)!=(2 if gateway['active'] else 1):raise ValueError('actual gateway topology')
 endpoints=[]
 for config in configs:
  subnet=config['subnet']['id']
  expected='/subscriptions/'+subscription+'/resourceGroups/'+RG+'/providers/Microsoft.Network/virtualNetworks/azure-vnet/subnets/GatewaySubnet'
  if subnet.lower()!=expected.lower():raise ValueError('gateway subnet binding')
  pip_id=resource_id(config['publicIPAddress']['id'],subscription,'publicIPAddresses')
  pip=owned(az('network','public-ip','show','--ids',pip_id,'--query','{id:id,owner:tags.owner,address:ipAddress}'),pip_id)
  outside=str(ipaddress.IPv4Address(pip['address']))
  if not ipaddress.IPv4Address(outside).is_global:raise ValueError('public endpoint')
  matches=[peer for peer in gateway.get('peers') or [] if peer.get('ipconfigurationId','').lower()==config['id'].lower()]
  endpoint={'outside_address':outside}
  if matches:
   custom=matches[0].get('customBgpIpAddresses') or []
   if len(matches)!=1 or len(custom)!=1:raise ValueError('APIPA cardinality')
   endpoint['cloud_inside_address']=str(ipaddress.IPv4Address(custom[0]))
  endpoints.append(endpoint)
 if len(set(value['outside_address'] for value in endpoints))!=len(endpoints):raise ValueError('public endpoint duplicate')
 return {'version':1,'observed_at':datetime.now(timezone.utc).isoformat(),'subscription':subscription,'resource_group':RG,'owner':OWNER,'connection_id':connection_id,'gateway_id':gateway_id,'local_gateway_id':lng_id,'active_active':gateway['active'],'sku':gateway['sku'],'vpn_type':gateway['vpn'],'enable_bgp':connection['bgp'],'customer_outside_address':str(ipaddress.IPv4Address(lng['outside'])),'local_asn':lng.get('asn'),'customer_bgp_address':lng.get('bgp'),'remote_asn':gateway.get('asn'),'public_endpoints':endpoints,'local_prefixes':lng['prefixes']}


def output_preflight(path):
 parent=path.parent
 info=parent.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700 or parent.absolute()!=parent.resolve():raise ValueError('private output parent')
 if path.exists() or path.is_symlink():raise ValueError('new private output required')


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('phase',choices=['discover','aa-static'])
 parser.add_argument('--subscription',required=True)
 parser.add_argument('--connection-id',required=True)
 parser.add_argument('--output',required=True,type=Path)
 args=parser.parse_args()
 if args.subscription!=SUBSCRIPTION:raise ValueError('authorized subscription required')
 if args.phase=='aa-static':raise ValueError('Use configure-owned-static.py with durable baseline and independent cleanup evidence')
 output_preflight(args.output)
 before=discover(args.subscription,args.connection_id)
 # Output metadata only. No shared-key call, unfiltered object, logs or response bodies.
 fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as stream:json.dump(before,stream,indent=2);stream.write('\n')
 print('Owned topology projection saved privately; no tunnel or packet readiness claim.')


if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):raise SystemExit('Owned discovery/update refused: contract or ownership check failed')
