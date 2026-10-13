import copy,importlib.util,pathlib,unittest,ipaddress
s=importlib.util.spec_from_file_location('importer',pathlib.Path(__file__).with_name('customer-static-owned-import-v3.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Tests(unittest.TestCase):
 def fixture(self,profile):
  p=m.PINS[profile];tunnels=[];xml=[]
  for i,inside in enumerate(p['inside']):
   net=ipaddress.ip_network(inside);opts={'OutsideIpAddress':p['outside'][i],'TunnelInsideCidr':inside,'PreSharedKey':'S'+('b'*32)}
   for key,val in [('Phase1EncryptionAlgorithms','AES256'),('Phase2EncryptionAlgorithms','AES256'),('Phase1IntegrityAlgorithms','SHA2-256'),('Phase2IntegrityAlgorithms','SHA2-256'),('Phase1DHGroupNumbers',14),('Phase2DHGroupNumbers',14),('IkeVersions','ikev2')]:opts[key]=[{'Value':val}]
   tunnels.append(opts);xml.append('<ipsec_tunnel><customer_gateway><tunnel_outside_address><ip_address>13.63.169.255</ip_address></tunnel_outside_address><tunnel_inside_address><ip_address>'+str(net.network_address+2)+'</ip_address></tunnel_inside_address></customer_gateway><vpn_gateway><tunnel_outside_address><ip_address>'+p['outside'][i]+'</ip_address></tunnel_outside_address><tunnel_inside_address><ip_address>'+str(net.network_address+1)+'</ip_address></tunnel_inside_address></vpn_gateway><ike><pre_shared_key>'+opts['PreSharedKey']+'</pre_shared_key></ike></ipsec_tunnel>')
  gateway={'CustomerGatewayId':'cgw-owned','VpnGatewayId':'vgw-owned'}if profile=='vgw'else{'CustomerGatewayId':'cgw-owned','TransitGatewayId':'tgw-owned'}
  v={**gateway,'VpnConnectionId':p['vpn'],'State':'available','Type':'ipsec.1','Tags':[{'Key':'TunnexLab','Value':m.OWNER}],'Options':{'StaticRoutesOnly':True,'LocalIpv4NetworkCidr':'10.84.2.0/24','RemoteIpv4NetworkCidr':p['remote'],'TunnelInsideIpVersion':'ipv4','TunnelOptions':tunnels},'CustomerGatewayConfiguration':'<vpn_connection>'+''.join(xml)+'</vpn_connection>'}
  return {'VpnConnections':[v]},{'VpnConnection':{**gateway,'VpnConnectionId':p['vpn']}}
 def test_both_real_profile_shapes(self):
  for profile in m.PINS:
   r,l=self.fixture(profile);body=m.prepare(r,l,profile);self.assertEqual(body['configuration']['mode'],'ipv4-static');self.assertNotIn('bgp',body['configuration']);self.assertEqual(body['configuration']['remote_prefixes'],[m.PINS[profile]['remote']])
 def test_foreign_id_or_tag_refused(self):
  for key in ['id','tag']:
   r,l=self.fixture('vgw')
   if key=='id':l['VpnConnection']['VpnConnectionId']='vpn-foreign'
   else:r['VpnConnections'][0]['Tags'][0]['Value']='foreign'
   with self.assertRaises(AssertionError):m.prepare(r,l,'vgw')
 def test_foreign_gateway_cgw_and_wrong_attachment_type(self):
  for profile in m.PINS:
   for key in ['cgw','gateway','other','missing']:
    r,l=self.fixture(profile);v=r['VpnConnections'][0];own='VpnGatewayId'if profile=='vgw'else'TransitGatewayId';other='TransitGatewayId'if profile=='vgw'else'VpnGatewayId'
    if key=='cgw':v['CustomerGatewayId']='cgw-foreign'
    elif key=='gateway':v[own]='gateway-foreign'
    elif key=='other':v[other]='gateway-other'
    else:v.pop(own)
    with self.assertRaises(AssertionError):m.prepare(r,l,profile)
 def test_request_spelling_not_accepted_as_response(self):
  r,l=self.fixture('vgw');t=r['VpnConnections'][0]['Options']['TunnelOptions'][0];t['IKEVersions']=t.pop('IkeVersions')
  with self.assertRaises(KeyError):m.prepare(r,l,'vgw')
 def test_broad_selector_and_wrong_suite_refused(self):
  for key in ['selector','suite']:
   r,l=self.fixture('tgw')
   if key=='selector':r['VpnConnections'][0]['Options']['RemoteIpv4NetworkCidr']='0.0.0.0/0'
   else:r['VpnConnections'][0]['Options']['TunnelOptions'][0]['Phase2EncryptionAlgorithms']=[{'Value':'AES128'}]
   with self.assertRaises(AssertionError):m.prepare(r,l,'tgw')
if __name__=='__main__':unittest.main()
