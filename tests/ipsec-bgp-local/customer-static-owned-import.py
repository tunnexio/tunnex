#!/usr/bin/env python3
"""Source-only default; prepare private normal disabled create payload from ONLY owned central VPN response. No AWS/API calls."""
import argparse,hashlib,ipaddress,json,os,pathlib,stat,uuid,xml.etree.ElementTree as ET
OWNER='tunnex-static-central-customer-20261008'
PINS={'vgw':{'vpn':'vpn-0258233b8ff311088','outside':['3.67.173.125','52.58.98.231'],'inside':['169.254.124.0/30','169.254.124.4/30'],'remote':'10.87.1.0/24'},'tgw':{'vpn':'vpn-072d2b1161be22d4f','outside':['3.65.241.160','63.189.108.24'],'inside':['169.254.124.8/30','169.254.124.12/30'],'remote':'10.87.2.0/24'}}
SITE='01a119e8-fb58-72d9-bbd2-8de0fe7bfd1e';GW='01a1161a-9529-7478-b62f-a27f25222aa0'
def prepare(response,ledger,profile):
 pin=PINS[profile];rows=response['VpnConnections'];assert len(rows)==1;v=rows[0]
 assert v['VpnConnectionId']==pin['vpn'] and ledger['VpnConnection']['VpnConnectionId']==pin['vpn'] and v['State']=='available'and v['Type']=='ipsec.1'
 assert {t['Key']:t['Value']for t in v['Tags']}['TunnexLab']==OWNER
 opts=v['Options'];assert opts['StaticRoutesOnly']is True and opts['LocalIpv4NetworkCidr']=='10.84.2.0/24'and opts['RemoteIpv4NetworkCidr']==pin['remote']and opts['TunnelInsideIpVersion']=='ipv4'
 tunnels=opts['TunnelOptions'];assert len(tunnels)==2 and [x['OutsideIpAddress']for x in tunnels]==pin['outside']and [x['TunnelInsideCidr']for x in tunnels]==pin['inside']
 for x in tunnels:
  for key,value in [('Phase1EncryptionAlgorithms','AES256'),('Phase2EncryptionAlgorithms','AES256'),('Phase1IntegrityAlgorithms','SHA2-256'),('Phase2IntegrityAlgorithms','SHA2-256'),('Phase1DHGroupNumbers',14),('Phase2DHGroupNumbers',14),('IKEVersions','ikev2')]:assert x[key]==[{'Value':value}]
 xml=v['CustomerGatewayConfiguration'];assert '<!DOCTYPE'not in xml.upper()and '<!ENTITY'not in xml.upper();tree=ET.fromstring(xml);aws=tree.findall('ipsec_tunnel');assert len(aws)==2
 config={'mode':'ipv4-static','customer_outside_address':'13.63.169.255','local_prefixes':['10.84.2.0/24'],'remote_prefixes':[pin['remote']],'tunnels':[]}
 for i,x in enumerate(aws):
  value=lambda p:x.findtext(p)
  prefix=ipaddress.ip_network(pin['inside'][i]);customer=value('customer_gateway/tunnel_inside_address/ip_address');cloud=value('vpn_gateway/tunnel_inside_address/ip_address')
  assert value('customer_gateway/tunnel_outside_address/ip_address')=='13.63.169.255'and value('vpn_gateway/tunnel_outside_address/ip_address')==pin['outside'][i]
  assert customer==str(prefix.network_address+2)and cloud==str(prefix.network_address+1)
  psk=value('ike/pre_shared_key');assert isinstance(psk,str)and 8<=len(psk)<=64 and psk[0]!='0'and psk.isascii()and not any(c.isspace()for c in psk)
  if 'PreSharedKey'in tunnels[i]:assert psk==tunnels[i]['PreSharedKey']
  config['tunnels'].append({'outside_address':pin['outside'][i],'inside_cidr':str(prefix),'cloud_inside_address':cloud,'customer_inside_address':customer,'psk':psk})
 return {'id':str(uuid.uuid4()),'name':'Customer static '+profile+' central owned','site_id':SITE,'gateway_node_id':GW,'tunnel_ids':[str(uuid.uuid4()),str(uuid.uuid4())],'configuration':config}
def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 with os.fdopen(fd,'rb')as f:raw=f.read(1048577)
 assert len(raw)<=1048576;return json.loads(raw),hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--profile',choices=PINS,required=True);p.add_argument('--describe',type=pathlib.Path);p.add_argument('--ledger-result',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path);p.add_argument('--prepare',action='store_true');a=p.parse_args()
 if not a.prepare:print(json.dumps({'source_only':True,'profile':a.profile,'vpn':PINS[a.profile]['vpn'],'normal_disabled_create_only':True}));return
 assert os.getuid()==0 and a.describe and a.ledger_result and a.out;os.umask(0o077);response,sha=private(a.describe);ledger,ledger_sha=private(a.ledger_result);body=prepare(response,ledger,a.profile);parent=a.out.parent;assert parent.is_dir()and not parent.is_symlink()and parent.stat().st_uid==0 and stat.S_IMODE(parent.stat().st_mode)==0o700
 raw=json.dumps(body,indent=2).encode();fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 print(json.dumps({'provider_id':body['id'],'tunnel_ids':body['tunnel_ids'],'profile':a.profile,'aws_vpn':PINS[a.profile]['vpn'],'describe_sha256':sha,'ledger_sha256':ledger_sha,'body_sha256':hashlib.sha256(raw).hexdigest(),'output':str(a.out),'api_calls':False,'psks_printed':False}))
if __name__=='__main__':main()
