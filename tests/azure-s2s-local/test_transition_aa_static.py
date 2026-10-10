import importlib.util
from pathlib import Path
import unittest
import io
import json
import tempfile
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('static_transition',Path(__file__).with_name('transition-aa-static.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


class TransitionContractTests(unittest.TestCase):
 def previous(self):
  return {'profile_id':'azure-active-active-bgp-ipv4-v1','configuration_revision':1,'configuration':{'azure':{'gateway_sku':'VpnGw1AZ','vpn_type':'RouteBased','ike_version':2,'custom_policy':'aes256-sha256-dh14-pfs2048','use_policy_based_traffic_selectors':False,'nat_enabled':False},'customer_outside_address':'20.219.28.146','local_prefixes':['10.233.10.0/24'],'remote_prefixes':['10.231.0.0/16'],'tunnels':[{'outside_address':'52.140.60.21'},{'outside_address':'20.219.125.34'}],'bgp':{'local_asn':65000}}}

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
    values={'api-setup.json':setup,'ui-accounts.json':[{'email':'browser-owner@azure-s2s.local','password':'PRIVATE'}],'azure-static-transition.json':state}
    calls=[];created={}
    def raw(identity):return {'id':identity,**setup,'gateway_node_id':setup['gateway_id'],'desired_revision':1,'desired_intent':'disabled','application_state':'not_applied','cleanup_state':'not_required','deleted_at':None}
    def call(method,path,body=None,revision=None):
     calls.append((method,path,body))
     if path=='/api/v1/organizations':return [{'id':setup['org_id'],'slug':'azure-s2s-local'}]
     if path.endswith('/connections/'+prior_id):return {**raw(prior_id),'deleted_at':'2026-10-10T00:00:00Z','finalized_at':'2026-10-10T00:00:01Z' if finalized else None,'historical_site_id':setup['site_id'],'historical_gateway_node_id':setup['gateway_id']}
     if method=='POST' and path.endswith('/connections'):created.update(body);return raw(body['id'])
     if method=='GET' and created and path.endswith('/connections/'+created['id']):return raw(created['id'])
     if path.endswith('/status'):return {'tunnels':[{'id':identity,'slot':index+1,'status':'unknown','selected':False} for index,identity in enumerate(created['tunnel_ids'])]}
     return {}
    args=['transition-aa-static.py','create-static','--private-root',directory,'--psk-file',directory+'/psk']
    def read(path):return b'private.synthetic.key' if Path(path).name=='psk' else json.dumps(values[Path(path).name]).encode()
    with patch('sys.argv',args),patch.object(helper.api,'private_read',side_effect=read),patch.object(helper.api,'private_write') as writes,patch.object(helper.api,'Client') as client,patch('sys.stdout',new=io.StringIO()) as output:
     client.return_value.call.side_effect=call
     if finalized:
      helper.main();self.assertNotEqual(created['id'],prior_id);self.assertEqual(len(created['tunnel_ids']),2)
      self.assertNotIn('private.synthetic.key',output.getvalue());self.assertTrue(writes.called)
     else:
      with self.assertRaisesRegex(ValueError,'finalization required'):helper.main()
      self.assertFalse(any(method=='POST' and path.endswith('/connections') for method,path,body in calls))

 def test_cleanup_requires_disabled_and_real_settled_state(self):
  for intent,cleanup,expected in [('disabled','retained_guard',True),('disabled','not_required',True),('disabled','pending',False),('enabled','not_required',False)]:
   self.assertEqual(helper.settled({'desired_intent':intent,'cleanup_state':cleanup}),expected)


if __name__=='__main__':unittest.main()
