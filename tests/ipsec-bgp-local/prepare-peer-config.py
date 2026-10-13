#!/usr/bin/env python3
"""Generate inactive standalone AWS-peer material from a legal CP provider fixture."""
import argparse,hashlib,json,os,pathlib,stat,uuid
os.umask(0o077)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scenario',choices=['integrated','limits','static'],default='integrated');p.add_argument('--private-config',type=pathlib.Path,required=True);p.add_argument('--state',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
assert stat.S_IMODE(a.private_config.stat().st_mode)&0o077==0
c=json.loads(a.private_config.read_text());s=json.loads(a.state.read_text());assert s['connection_id']and len(s['tunnel_ids'])==2
provider=pathlib.Path(c['provider_config_file']);assert stat.S_IMODE(provider.stat().st_mode)&0o077==0
config=json.loads(provider.read_text());assert config['mode']==('ipv4-static' if a.scenario=='static' else 'ipv4-bgp')
expected={'integrated':['10.20.0.0/24'],'limits':['10.30.0.0/24','10.31.0.0/24'],'static':['10.32.0.0/24']}[a.scenario]
assert config['local_prefixes']==['10.10.0.0/24']and config['remote_prefixes']==expected,'Only exact owned scenario prefixes supported'
assert config['customer_outside_address']=='13.63.169.255'
outside={'integrated':['13.50.7.159','51.20.220.141'],'limits':['13.50.7.160','51.20.220.142'],'static':['13.50.7.161','51.20.220.143']}[a.scenario]
assert [t['outside_address']for t in config['tunnels']]==outside
assert not a.output.exists(),'Retain original peer material; no implicit overwrite'
peer_gateway=str(uuid.uuid4());generation=str(uuid.uuid4());binding={'OrgID':c['organization_id'],'GatewayID':peer_gateway,'ConnectionID':s['connection_id'],'DesiredRevision':s['desired_revision'],'ConfigurationRevision':1,'PolicyRevision':1}
tunnels=[];peers=[];interfaces=[];psks=[]
for slot,(tid,t)in enumerate(zip(s['tunnel_ids'],config['tunnels']),1):
 digest=hashlib.sha256(uuid.UUID(tid).bytes).digest();xid=int.from_bytes(digest[:4],'big')|0x80000000;link='tx'+digest[:6].hex()
 tunnels.append({'BGP':a.scenario!='static','Binding':binding,'TunnelID':tid,'SecretRevision':1,'XFRMID':xid,'ReqID':xid,'LocalAddress':t['outside_address'],'RemoteAddress':config['customer_outside_address'],'LocalIdentity':t['outside_address'],'RemoteIdentity':config['customer_outside_address'],'LocalPrefixes':config['remote_prefixes'],'RemotePrefixes':config['local_prefixes']})
 peers.append({'Slot':slot,'LinkName':link,'XFRMID':xid,'Local':t['cloud_inside_address'],'Remote':t['customer_inside_address']})
 interfaces.append({'name':link,'xfrm_id':xid,'alias':'tunnex-ipsec:'+generation+':'+tid,'address':t['cloud_inside_address']+'/30','remote_host_route':t['customer_inside_address']+'/32','protocol':242,'metric':50000+slot})
 psks.append(t['psk'])
b=config.get('bgp',{'remote_asn':64512,'local_asn':65000,'maximum_prefixes':1});peer={'CustomTunnels':tunnels,'BGPConfig':{'LocalASN':b['remote_asn'],'RemoteASN':b['local_asn'],'RouterID':{'integrated':'10.20.0.1','limits':'10.30.0.1','static':'10.32.0.1'}[a.scenario],'MaximumPrefixes':b['maximum_prefixes'],'LocalPrefixes':config['remote_prefixes'],'RemotePrefixes':config['local_prefixes'],'Peers':peers},'PSKs':psks,'Interfaces':interfaces,'PeerGatewayID':peer_gateway,'Generation':generation,'GatewayCPAuthority':'real CP only; this standalone peer cannot acknowledge deliveries','ActivationPerformed':False}
if a.scenario!='integrated':peer['Scenario']=a.scenario
a.output.write_text(json.dumps(peer,indent=2)+'\n');os.chmod(a.output,0o600)
print('Prepared private inactive standalone peer config; no daemon started, no CP acknowledgement or gateway authority supplied')
