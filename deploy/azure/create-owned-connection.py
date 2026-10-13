#!/usr/bin/env python3
"""Bastion-only owned one-LNG Azure connection; secret output forbidden."""
import json,os,pathlib,socket,subprocess,secrets
if socket.gethostname()!='bastion-host':raise SystemExit('Designated bastion required')
rg='tunnex-azure-s2s-20261010';owner='azure-s2s-01a12505'
def call(*args):
    return subprocess.check_output(['az',*args,'--only-show-errors'],text=True)
if call('group','show','-n',rg,'--query','tags.owner','-o','tsv').strip()!=owner:raise SystemExit('Foreign group refused')
gw=json.loads(call('network','vnet-gateway','show','-g',rg,'-n','azure-vpn','-o','json'))
if gw['provisioningState']!='Succeeded':raise SystemExit('Gateway provisioning pending')
call('network','vnet-gateway','update','-g',rg,'-n','azure-vpn','--enable-bgp','true','--set','bgpSettings.bgpPeeringAddresses[0].customBgpIpAddresses=["169.254.21.2"]','bgpSettings.bgpPeeringAddresses[1].customBgpIpAddresses=["169.254.22.2"]','-o','none')
peer=call('network','public-ip','show','-g',rg,'-n','peer-ip','--query','ipAddress','-o','tsv').strip()
call('network','local-gateway','create','-g',rg,'-n','tunnex-local','-l','southindia','--gateway-ip-address',peer,'--asn','65000','--bgp-peering-address','169.254.10.1','--tags','owner='+owner,'purpose=owned-s2s-test','-o','none')
lng=call('network','local-gateway','show','-g',rg,'-n','tunnex-local','--query','id','-o','tsv').strip()
state=pathlib.Path.home()/'.tunnex-azure-s2s-01a12505';state.mkdir(mode=0o700,exist_ok=True)
key=state/'lab-psk'
if not key.exists():key.write_text(secrets.token_hex(16));key.chmod(0o600)
props={'connectionType':'IPsec','connectionProtocol':'IKEv2','virtualNetworkGateway1':{'id':gw['id']},'localNetworkGateway2':{'id':lng},'enableBgp':True,'sharedKey':key.read_text().strip(),'usePolicyBasedTrafficSelectors':False,'routingWeight':10,'ipsecPolicies':[{'saLifeTimeSeconds':3600,'saDataSizeKilobytes':102400000,'ipsecEncryption':'AES256','ipsecIntegrity':'SHA256','ikeEncryption':'AES256','ikeIntegrity':'SHA256','dhGroup':'DHGroup14','pfsGroup':'PFS2048'}]}
body=state/'connection-properties.json';body.write_text(json.dumps({'location':'southindia','tags':{'owner':owner,'purpose':'owned-s2s-test'},'properties':props}));body.chmod(0o600)
# Private output files prevent unexpected provider errors from echoing credential bodies.
with (state/'connection-result.log').open('w') as out:
    outpath=state/'connection-result.log';outpath.chmod(0o600)
    result=subprocess.run(['az','resource','create','-g',rg,'-n','tunnex-connection','--resource-type','Microsoft.Network/connections','--api-version','2024-05-01','-l','southindia','--is-full-object','--properties','@'+str(body),'-o','none','--only-show-errors'],stdout=out,stderr=out)
if result.returncode:raise SystemExit('Owned connection creation refused; inspect private error category without exposing secrets')
print('Owned one-LNG shared-key BGP connection created; live tunnel acceptance pending')
