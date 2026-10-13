import copy
from datetime import datetime,timedelta,timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('standby',Path(__file__).parents[2]/'deploy/azure/convert-owned-standby.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def baseline():
 configs=[];peers=[]
 for i,name in enumerate(m.NAMES):
  cid=m.GATEWAY+'/ipConfigurations/'+name
  configs.append({'id':cid,'name':name,'subnet':{'id':m.SUBNET},'publicIPAddress':{'id':m.PIPS[i]},'privateIPAllocationMethod':'Dynamic','etag':'original','provisioningState':'Succeeded'})
  peers.append({'ipconfigurationId':cid,'customBgpIpAddresses':[m.CUSTOM[i]],'defaultBgpIpAddresses':['10.231.255.'+str(4+i)],'tunnelIpAddresses':['52.140.60.21' if i==0 else '20.219.125.34']})
 return {'id':m.GATEWAY,'tags':{'owner':m.lab.OWNER,'preserve':'yes'},'activeActive':True,'gatewayType':'Vpn','vpnType':'RouteBased','vpnGatewayGeneration':'Generation1','sku':{'name':'VpnGw1AZ','tier':'VpnGw1AZ','capacity':2},'location':'centralindia','ipConfigurations':configs,'bgpSettings':{'asn':65515,'peerWeight':0,'bgpPeeringAddress':'unchanged','bgpPeeringAddresses':peers},'provisioningState':'Succeeded','etag':'original','vpnClientConfiguration':None,'natRules':[],'unknownPreserve':{'value':42,'provisioningState':'preserve nested arbitrary value'}}


def expected():return {'org_id':'11111111-1111-4111-8111-111111111111','site_id':'22222222-2222-4222-8222-222222222222','gateway_id':'33333333-3333-4333-8333-333333333333','connection_id':m.common.CP,'namespace_device':4,'namespace_inode':9}

def receipts():
 stamp=datetime.now(timezone.utc).isoformat();binding=expected()
 cleanup={'phase':'read','observed_at':stamp,'cleanup_readback_settled':True,'connection':{'id':binding['connection_id'],'desired_revision':35,'desired_intent':'disabled','application_state':'not_applied','cleanup_state':'retained_guard'}}
 native=dict(binding,version=1,kind='owned_native_cleanup_absence',observed_at=stamp,desired_revision=35,azure_connection_id=m.CONNECTION,guard_retained=True)
 for key in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes'):native[key]=0
 raw=json.dumps(native).encode();return cleanup,native,raw,m.hashlib.sha256(raw).hexdigest()

class Conversion(unittest.TestCase):
 def test_target_resolves_names_and_peer_ids_when_reordered(self):
  raw=baseline();raw['ipConfigurations'].reverse()
  result=m.target(raw)
  self.assertEqual(result['ipConfigurations'][0]['name'],m.NAMES[0]);self.assertEqual(result['bgpSettings']['bgpPeeringAddresses'][0]['customBgpIpAddresses'],[m.CUSTOM[0]])
  self.assertEqual(result['unknownPreserve'],raw['unknownPreserve']);self.assertEqual(result['tags'],raw['tags'])
  self.assertEqual(m.gateway(raw,True)[0][m.NAMES[1]],0)
 def test_unknown_mapping_foreign_pip_or_subnet_and_client_refused(self):
  for key in ('mapping','pip','subnet','feature','sku'):
   raw=baseline()
   if key=='mapping':raw['bgpSettings']['bgpPeeringAddresses'][1]['unknown']=1
   if key=='pip':raw['ipConfigurations'][1]['publicIPAddress']['id']='foreign'
   if key=='subnet':raw['ipConfigurations'][0]['subnet']['id']='foreign'
   if key=='feature':raw['vpnClientConfiguration']={'enabled':True}
   if key=='sku':raw['sku']['name']='Basic'
   with self.subTest(key=key),self.assertRaises(ValueError):m.target(raw)
 def test_preservation_classification_masks_only_known_server_fields(self):
  raw=baseline();actual=m.target(raw);actual['etag']='updated';actual['bgpSettings']['bgpPeeringAddresses'][0]['defaultBgpIpAddresses']=['10.231.255.254']
  self.assertEqual(m.classify(actual,raw),'preserved_as')
  for key in ('unknownPreserve','location','bgpPeeringAddress'):
   changed=copy.deepcopy(actual)
   if key=='bgpPeeringAddress':changed['bgpSettings'][key]='changed'
   else:changed[key]='changed'
   self.assertEqual(m.classify(changed,raw),'unexpected_properties_or_topology')
  actual['provisioningState']='Updating';self.assertEqual(m.classify(actual,raw),'provisioning_pending')
 def test_receipts_stale_digest_revision_namespace_and_objects_refused(self):
  good=receipts();self.assertEqual(m.evidence(*good,expected(),datetime.now(timezone.utc)),35)
  for kind in ('stale','digest','revision','namespace','objects','binding'):
   cleanup,native,raw,sha=receipts()
   if kind=='stale':cleanup['observed_at']=(datetime.now(timezone.utc)-timedelta(seconds=61)).isoformat()
   if kind=='digest':sha='0'*64
   if kind=='revision':native['desired_revision']=36
   if kind=='namespace':native['namespace_inode']=10
   if kind=='objects':native['owned_sad']=1
   if kind=='binding':native['site_id']='foreign'
   if kind not in ('digest','stale'):raw=json.dumps(native).encode();sha=m.hashlib.sha256(raw).hexdigest()
   with self.subTest(kind=kind),self.assertRaises(ValueError):m.evidence(cleanup,native,raw,sha,expected(),datetime.now(timezone.utc))
 def test_wrong_host_precedes_requests_and_private_writes(self):
  with patch.object(m.socket,'gethostname',return_value='other'),patch.object(m.lab,'az') as request:
   with self.assertRaises(ValueError):m.run('prepare',Path('/not/a/path'),expected())
   request.assert_not_called()
 def test_public_state_parent_refuses_before_azure_and_cli_version_guard(self):
  with tempfile.TemporaryDirectory() as folder:
   folder=Path(folder).resolve();folder.chmod(0o755)
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m.lab,'az') as request:
    with self.assertRaises(ValueError):m.run('prepare',folder/'state',expected())
    request.assert_not_called()
   folder.chmod(0o700)
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m.lab,'az',return_value={'azure-cli':'different'}) as request,patch.object(m,'bindings') as binding:
    with self.assertRaisesRegex(ValueError,'CLI version'):m.run('prepare',folder/'state',expected())
    self.assertEqual(request.call_count,1);binding.assert_not_called()
 def test_durable_one_update_timeout_reconcile_never_repeats(self):
  raw=baseline();original=json.dumps(raw,indent=2).encode();connection={'owned':'binding'}
  with tempfile.TemporaryDirectory() as folder:
   state=Path(folder).resolve()/'state.json'
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m,'bindings',return_value=connection),patch.object(m,'raw_read_gateway',return_value=(original,raw)):
    with patch.object(m.lab,'az',return_value={'azure-cli':'2.91.0'}):m.run('prepare',state,expected())
    self.assertEqual((state.parent/(state.name+'.gateway-original.json')).read_bytes(),original)
    def timeout(*args):
     if args==('version',):return {'azure-cli':'2.91.0'}
     self.assertEqual(json.loads(state.read_text())['stage'],'apply_sent')
     self.assertEqual(args[0:3],('network','vnet-gateway','update'))
     self.assertIn('bgpSettings.bgpPeeringAddresses=[{"ipconfigurationId":',str(args))
     raise m.subprocess.TimeoutExpired('az',180)
    cleanup,native,wire,sha=receipts()
    with patch.object(m.lab,'az',side_effect=timeout) as mutation:
     with self.assertRaises(m.subprocess.TimeoutExpired):m.run('apply',state,None,cleanup,native,wire,sha)
     self.assertEqual(mutation.call_count,2)
    with patch.object(m.lab,'az') as mutation:
     result=m.run('reconcile',state,None);self.assertEqual(result['stage'],'apply_sent');self.assertEqual(result['gateway_classification'],'original_aa');mutation.assert_not_called()
     with self.assertRaises(ValueError):m.run('apply',state,None,cleanup,native,wire,sha)
     mutation.assert_not_called()
 def test_exclusive_reservation_refuses_second_prepared_process(self):
  raw=baseline();original=json.dumps(raw).encode();connection={'owned':'binding'}
  with tempfile.TemporaryDirectory() as folder:
   state=Path(folder).resolve()/'state.json'
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m,'bindings',return_value=connection),patch.object(m,'raw_read_gateway',return_value=(original,raw)),patch.object(m.lab,'az',return_value={'azure-cli':'2.91.0'}) as request:
    m.run('prepare',state,expected())
    marker=state.with_name(state.name+'.mutation-reserved');marker.write_text('{}');marker.chmod(0o600)
    with self.assertRaises(ValueError):m.run('apply',state,None,*receipts())
    self.assertTrue(all(call.args==('version',) for call in request.call_args_list))
    self.assertEqual(json.loads(state.read_text())['stage'],'prepared')
 def test_single_apply_completes_only_after_exact_preserved_readback(self):
  raw=baseline();original=json.dumps(raw).encode();actual=m.target(raw);connection={'owned':'binding'}
  with tempfile.TemporaryDirectory() as folder:
   state=Path(folder).resolve()/'state.json'
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m,'bindings',return_value=connection),patch.object(m,'raw_read_gateway',return_value=(original,raw)),patch.object(m.lab,'az',return_value={'azure-cli':'2.91.0'}):m.run('prepare',state,expected())
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m,'bindings',return_value=connection),patch.object(m,'raw_read_gateway',side_effect=[(original,raw),(json.dumps(actual).encode(),actual)]),patch.object(m.lab,'az',side_effect=[{'azure-cli':'2.91.0'},None]) as mutation:
    result=m.run('apply',state,None,*receipts());self.assertEqual(result['stage'],'converted');self.assertEqual(mutation.call_count,2)

if __name__=='__main__':unittest.main()
