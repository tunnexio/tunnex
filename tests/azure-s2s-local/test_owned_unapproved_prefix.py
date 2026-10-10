import copy
from datetime import datetime,timezone,timedelta
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('prefix_qualification',Path(__file__).resolve().parents[2]/'deploy/azure/qualify-owned-unapproved-prefix.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)


class PrefixExperiment(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700);self.state=self.root/'state.json'
  self.vnet={'id':h.VNET,'tags':{'owner':h.lab.OWNER},'provisioningState':'Succeeded','etag':'before','addressSpace':{'addressPrefixes':['10.231.0.0/16']},'subnets':[{'id':h.VNET+'/subnets/workload','addressPrefix':'10.231.1.0/24','delegations':[],'networkSecurityGroup':{'id':'exact-nsg'}}],'dhcpOptions':{'dnsServers':[]},'unknownProtectedProperty':{'must':'remain'}}
  self.discovery={'gateway_id':h.BASE+'virtualNetworkGateways/azure-vpn','local_gateway_id':h.BASE+'localNetworkGateways/tunnex-local','active_active':True,'sku':'VpnGw1AZ','vpn_type':'RouteBased','enable_bgp':True,'public_endpoints':[{},{}],'local_prefixes':['10.233.10.0/24']}
  self.review={'version':1,'kind':'owned_prefix_range_review','observed_at':datetime.now(timezone.utc).isoformat(),'subscription':h.lab.SUBSCRIPTION,'resource_group':h.lab.RG,'owner':h.lab.OWNER,'vnet_id':h.VNET,'candidate':'10.235.77.0/24','ranges':['10.231.0.0/16','10.232.0.0/16','10.233.10.0/24','10.244.0.0/16'],'normal_connection':{'id':h.CP,'desired_revision':30,'desired_intent':'enabled','application_state':'applied','profile_id':'azure-active-active-bgp-ipv4-v1','remote_prefixes':['10.231.0.0/16'],'maximum_prefixes':8}}
  self.external={'dns':'preserved','lb':'preserved','resolver':'preserved'};self.updates=[];self.inject_failure=False
  outer=self
  def azure(*args):
   if args[:3]!=('network','vnet','update'):raise AssertionError('unexpected CLI command')
   saved=json.loads(outer.state.read_text());assert saved['stage'].endswith('_sent')
   outer.updates.append(args)
   if outer.inject_failure:raise ValueError('ambiguous fixture failure')
   start=args.index('--address-prefixes')+1;end=args.index('--query')
   outer.vnet['addressSpace']['addressPrefixes']=list(args[start:end]);outer.vnet['etag']='changed'
   return h.VNET
  self.patches=[patch.object(h.socket,'gethostname',return_value='bastion-host'),patch.object(h,'cloud_binding',side_effect=lambda:copy.deepcopy(self.discovery)),patch.object(h,'cloud_ranges'),patch.object(h,'read_vnet',side_effect=lambda:copy.deepcopy(self.vnet)),patch.object(h,'external_properties',side_effect=lambda:copy.deepcopy(self.external)),patch.object(h.lab,'az',side_effect=azure)]
  for p in self.patches:p.start()
 def tearDown(self):
  for p in self.patches:p.stop()
  self.temp.cleanup()
 def run_phase(self,phase):return h.run(phase,self.state,self.review)
 def test_add_restore_preserve_all_original_and_external_properties(self):
  self.run_phase('prepare');self.assertEqual(self.state.stat().st_mode&0o777,0o600)
  result=self.run_phase('add');self.assertEqual(result['saved_stage'],'added')
  self.assertEqual(self.vnet['addressSpace']['addressPrefixes'],['10.231.0.0/16','10.235.77.0/24'])
  self.run_phase('restore');self.assertEqual(self.vnet['addressSpace']['addressPrefixes'],['10.231.0.0/16'])
  self.assertEqual(self.vnet['unknownProtectedProperty'],{'must':'remain'});self.assertEqual(len(self.updates),2)
  self.assertTrue(all(call[:3]==('network','vnet','update') for call in self.updates))
 def test_wrong_host_refuses_before_any_cloud_read(self):
  with patch.object(h.socket,'gethostname',return_value='wrong'),patch.object(h,'cloud_binding') as cloud:
   with self.assertRaises(ValueError):self.run_phase('prepare')
   cloud.assert_not_called()
 def test_fresh_review_and_overlap_are_required_before_cloud(self):
  for change in [lambda:self.review.update(observed_at=(datetime.now(timezone.utc)-timedelta(seconds=61)).isoformat()),lambda:self.review['ranges'].append('10.235.0.0/16'),lambda:self.review['normal_connection'].update(maximum_prefixes=1)]:
   previous=copy.deepcopy(self.review);change()
   with patch.object(h,'cloud_binding') as cloud:
    with self.assertRaises(ValueError):self.run_phase('prepare')
    cloud.assert_not_called()
   self.review=previous
 def test_unknown_vnet_property_subnet_dns_lb_changes_refuse_mutation(self):
  self.run_phase('prepare')
  for change in [lambda:self.vnet['unknownProtectedProperty'].update(must='changed'),lambda:self.vnet['subnets'][0].update(addressPrefix='10.231.9.0/24'),lambda:self.external.update(dns='changed'),lambda:self.external.update(lb='changed')]:
   v=copy.deepcopy(self.vnet);e=copy.deepcopy(self.external);change()
   with self.assertRaises(ValueError):self.run_phase('add')
   self.vnet=v;self.external=e
  self.assertEqual(self.updates,[])
 def test_ambiguous_add_never_repeats_and_can_reconcile(self):
  self.run_phase('prepare');self.inject_failure=True
  with self.assertRaises(ValueError):self.run_phase('add')
  self.assertEqual(json.loads(self.state.read_text())['stage'],'add_sent')
  with self.assertRaises(ValueError):self.run_phase('add')
  self.assertEqual(len(self.updates),1)
  self.assertEqual(self.run_phase('reconcile')['current_prefix_state'],'original')
  self.inject_failure=False;self.run_phase('restore');self.assertEqual(len(self.updates),1)
 def test_ambiguous_restore_does_not_repeat_mutation(self):
  self.run_phase('prepare');self.run_phase('add');self.inject_failure=True
  with self.assertRaises(ValueError):self.run_phase('restore')
  with self.assertRaises(ValueError):self.run_phase('restore')
  self.assertEqual(len(self.updates),2)
 def test_cloud_inventory_rejects_foreign_owner_and_overlap(self):
  self.patches[2].stop()
  for value in [{'id':h.VNET,'owner':'foreign','prefixes':[]},{'id':h.VNET,'owner':h.lab.OWNER,'prefixes':['10.235.77.0/24']}]:
   with patch.object(h.lab,'az',return_value=[value]):
    with self.assertRaises(ValueError):h.cloud_ranges('10.235.77.0/24')
  self.patches[2].start()
 def test_summarization_and_wrong_resource_are_refused(self):
  for key,value in [('id',h.VNET+'-other'),('summarizedGatewayPrefixes',['10.0.0.0/8']),('provisioningState','Updating')]:
   raw=copy.deepcopy(self.vnet);raw[key]=value
   with self.assertRaises(ValueError):h.vnet(raw)


if __name__=='__main__':unittest.main()
