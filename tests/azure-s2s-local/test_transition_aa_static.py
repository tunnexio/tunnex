import importlib.util
from pathlib import Path
import unittest
import io
import json
import tempfile
from datetime import datetime,timezone
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('static_transition',Path(__file__).with_name('transition-aa-static.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


class TransitionContractTests(unittest.TestCase):
 def previous(self):
  return {'profile_id':'azure-active-active-bgp-ipv4-v1','configuration_revision':1,'configuration':{'azure':{'gateway_sku':'VpnGw1AZ','vpn_type':'RouteBased','ike_version':2,'custom_policy':'aes256-sha256-dh14-pfs2048','use_policy_based_traffic_selectors':False,'nat_enabled':False},'customer_outside_address':'20.219.28.146','local_prefixes':['10.233.10.0/24'],'remote_prefixes':['10.231.0.0/16'],'tunnels':[{'outside_address':'52.140.60.21'},{'outside_address':'20.219.125.34'}],'bgp':{'local_asn':65000}}}

 def discovery(self,active=True,bgp=False):
  subscription='34e2f259-b462-40bf-8f4a-06a3930d99e6'
  prefix='/subscriptions/'+subscription+'/resourceGroups/tunnex-azure-s2s-20261010/providers/Microsoft.Network/'
  return {'version':1,'observed_at':datetime.now(timezone.utc).isoformat(),'subscription':subscription,'connection_id':prefix+'connections/owned','gateway_id':prefix+'virtualNetworkGateways/owned','local_gateway_id':prefix+'localNetworkGateways/owned','owner':'azure-s2s-01a12505','resource_group':'tunnex-azure-s2s-20261010','active_active':active,'enable_bgp':bgp,'vpn_type':'RouteBased','sku':'VpnGw1AZ','customer_outside_address':'20.219.28.146','local_asn':65000,'remote_asn':65515,'customer_bgp_address':'169.254.10.1','public_endpoints':[{'outside_address':'52.140.60.21','cloud_inside_address':'169.254.21.2'}]+([{'outside_address':'20.219.125.34','cloud_inside_address':'169.254.22.2'}] if active else [])}

 def test_standby_requires_real_single_endpoint_and_bgp_selection(self):
  for bgp,profile in [(True,'azure-active-standby-bgp-ipv4-v1'),(False,'azure-active-standby-static-ipv4-v1')]:
   config=helper.profile_configuration(self.previous(),'private.synthetic.key',profile,self.discovery(False,bgp))
   self.assertEqual(len(config['tunnels']),1)
   self.assertEqual('bgp' in config,bgp)
   self.assertEqual(config['tunnels'][0]['inside_cidr'],'169.254.10.1/32' if bgp else '169.254.70.0/30')
   with self.assertRaises(ValueError):helper.profile_configuration(self.previous(),'private.synthetic.key',profile,self.discovery(True,bgp))
  value=self.discovery(False,True);value['public_endpoints'].append(value['public_endpoints'][0])
  with self.assertRaises(ValueError):helper.profile_configuration(self.previous(),'private.synthetic.key','azure-active-standby-bgp-ipv4-v1',value)

 def test_discovery_owner_ids_and_freshness_refused(self):
  for key,value in [('subscription','00000000-0000-4000-8000-000000000007'),('owner','other'),('connection_id','/unowned'),('observed_at','2020-01-01T00:00:00Z')]:
   discovery=self.discovery();discovery[key]=value
   with self.assertRaises(ValueError):helper.profile_configuration(self.previous(),'private.synthetic.key',helper.PROFILES[0],discovery)

 def test_actual_envelope_static_two_tunnels_same_psk(self):
  config=helper.static_configuration(self.previous(),'private.synthetic.key')
  self.assertEqual(config['profile_id'],'azure-active-active-static-ipv4-v1')
  self.assertEqual(config['azure']['gateway_sku'],'VpnGw1AZ')
  self.assertNotIn('bgp',config)
  self.assertEqual([value['inside_cidr'] for value in config['tunnels']],['169.254.70.0/30','169.254.71.0/30'])
  self.assertEqual([value['psk'] for value in config['tunnels']],['private.synthetic.key']*2)
  self.assertNotIn('transport_version',config)

 def test_other_profile_topology_or_prefix_refused(self):
  for mutate in (lambda value:value.update(profile_id='aws-static-ipv4-v1'),lambda value:value['configuration'].update(tunnels=[]),lambda value:value['configuration'].update(local_prefixes=['0.0.0.0/0'])):
   value=self.previous();mutate(value)
   with self.assertRaises(ValueError):helper.static_configuration(value,'private.synthetic.key')

 def test_main_create_requires_finalization_and_saves_new_ids(self):
  setup={'org_id':'00000000-0000-4000-8000-000000000001','site_id':'00000000-0000-4000-8000-000000000002','gateway_id':'00000000-0000-4000-8000-000000000003'}
  prior_id='00000000-0000-4000-8000-000000000004'
  for finalized in (False,True):
   with self.subTest(finalized=finalized),tempfile.TemporaryDirectory() as directory:
    root=Path(directory);root.chmod(0o700);(root/'azure-static-transition.json').touch()
    state={'prior':{'id':prior_id,'tunnel_ids':['00000000-0000-4000-8000-000000000005','00000000-0000-4000-8000-000000000006']},'prior_configuration':self.previous()}
    values={'api-setup.json':setup,'ui-accounts.json':[{'email':'browser-owner@azure-s2s.local','password':'PRIVATE'}],'azure-static-transition.json':state,'discovery.json':self.discovery()}
    calls=[];created={}
    def raw(identity):return {'id':identity,**setup,'gateway_node_id':setup['gateway_id'],'desired_revision':1,'desired_intent':'disabled','application_state':'not_applied','cleanup_state':'not_required','deleted_at':None}
    def call(method,path,body=None,revision=None):
     calls.append((method,path,body))
     if path=='/api/v1/organizations':return [{'id':setup['org_id'],'slug':'azure-s2s-local'}]
     if path.endswith('/connections/'+prior_id):return {**raw(prior_id),'desired_intent':'deleted','site_id':None,'gateway_node_id':None,'deleted_at':'2026-10-10T00:00:00Z','finalized_at':'2026-10-10T00:00:01Z' if finalized else None,'historical_site_id':setup['site_id'],'historical_gateway_node_id':setup['gateway_id']}
     if method=='POST' and path.endswith('/connections'):created.update(body);return raw(body['id'])
     if method=='GET' and created and path.endswith('/connections/'+created['id']):return raw(created['id'])
     if path.endswith('/status'):return {'tunnels':[{'id':identity,'slot':index+1,'status':'unknown','selected':False} for index,identity in enumerate(created['tunnel_ids'])]}
     return {}
    args=['transition-aa-static.py','create-static','--private-root',directory,'--psk-file',directory+'/psk','--gateway-discovery-file',directory+'/discovery.json']
    def read(path):return b'private.synthetic.key' if Path(path).name=='psk' else json.dumps(values[Path(path).name]).encode()
    with patch('sys.argv',args),patch.object(helper.api,'private_read',side_effect=read),patch.object(helper.api,'private_write') as writes,patch.object(helper.api,'Client') as client,patch('sys.stdout',new=io.StringIO()) as output:
     client.return_value.call.side_effect=call
     if finalized:
      helper.main();self.assertNotEqual(created['id'],prior_id);self.assertEqual(len(created['tunnel_ids']),2)
      self.assertNotIn('private.synthetic.key',output.getvalue());self.assertTrue(writes.called)
     else:
      with self.assertRaisesRegex(ValueError,'finalization required'):helper.main()
      self.assertFalse(any(method=='POST' and path.endswith('/connections') for method,path,body in calls))

 def test_real_deleted_projection_is_prior_only_and_creation_fail_closed(self):
  setup={'org_id':'00000000-0000-4000-8000-000000000001','site_id':'00000000-0000-4000-8000-000000000002','gateway_id':'00000000-0000-4000-8000-000000000003'}
  identity='00000000-0000-4000-8000-000000000004'
  raw={'id':identity,'org_id':setup['org_id'],'site_id':None,'gateway_node_id':None,'historical_site_id':setup['site_id'],'historical_gateway_node_id':setup['gateway_id'],'desired_revision':3,'desired_intent':'deleted','application_state':'not_applied','cleanup_state':'retained_guard','deleted_at':'2026-10-10T00:00:00Z','finalized_at':'2026-10-10T00:00:01Z'}
  projected=helper.prior_projection(raw,setup,identity)
  self.assertTrue(helper.finalized_prior(raw,projected))
  with self.assertRaises(ValueError):helper.life.connection_projection(raw,setup,identity)
  for field,value in [('historical_site_id',identity),('historical_gateway_node_id',identity),('org_id',identity),('deleted_at',None)]:
   with self.subTest(field=field),self.assertRaises(ValueError):helper.prior_projection({**raw,field:value},setup,identity)
  for field,value in [('finalized_at',None),('cleanup_state','pending'),('application_state','applied')]:
   changed={**raw,field:value};self.assertFalse(helper.finalized_prior(changed,helper.prior_projection(changed,setup,identity)))

 def test_cleanup_requires_disabled_and_real_settled_state(self):
  for intent,cleanup,expected in [('disabled','retained_guard',True),('disabled','not_required',True),('disabled','pending',False),('enabled','not_required',False)]:
   self.assertEqual(helper.settled({'desired_intent':intent,'cleanup_state':cleanup}),expected)


if __name__=='__main__':unittest.main()
