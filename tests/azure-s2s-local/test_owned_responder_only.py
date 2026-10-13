import copy
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('owned_mode',Path(__file__).resolve().parents[2]/'deploy/azure/set-owned-responder-only.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)


class OwnedMode(unittest.TestCase):
 def setUp(self):
  self.now=datetime.now(timezone.utc)
  base='/subscriptions/'+h.lab.SUBSCRIPTION+'/resourceGroups/'+h.lab.RG+'/providers/Microsoft.Network/'
  self.discovery={'version':1,'subscription':h.lab.SUBSCRIPTION,'resource_group':h.lab.RG,'owner':h.lab.OWNER,'connection_id':base+'connections/tunnex-connection','gateway_id':base+'virtualNetworkGateways/azure-vpn','local_gateway_id':base+'localNetworkGateways/tunnex-local','active_active':True,'sku':'VpnGw1AZ','vpn_type':'RouteBased','enable_bgp':True,'public_endpoints':[],'local_prefixes':['10.233.10.0/24']}
  self.cleanup={'observed_at':self.now.isoformat(),'phase':'read','cleanup_readback_settled':True,'connection':{'id':'9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99','desired_revision':15,'desired_intent':'disabled','application_state':'not_applied','cleanup_state':'retained_guard'}}
  self.native={'version':1,'kind':'owned_native_cleanup_absence','observed_at':self.now.isoformat(),'connection_id':self.cleanup['connection']['id'],'desired_revision':15,'guard_retained':True,'azure_connection_id':self.discovery['connection_id']}
  for key in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes'):self.native[key]=0
  self.view={'id':self.discovery['connection_id'],'owner':h.lab.OWNER,'mode':'Default','state':'Succeeded','gateway':self.discovery['gateway_id'],'lng':self.discovery['local_gateway_id'],'selectors':False,'trafficSelectors':[]}
 def call(self):
  raw=json.dumps(self.native).encode();return h.configure(self.discovery,self.cleanup,self.native,hashlib.sha256(raw).hexdigest(),raw,self.now)
 def test_bad_host_refuses_before_az(self):
  with patch.object(h.socket,'gethostname',return_value='other'),patch.object(h.lab,'az') as az:
   with self.assertRaises(ValueError):self.call()
   az.assert_not_called()
 def test_stale_or_pending_cleanup_and_native_residue_refuse_before_az(self):
  cases=[lambda:self.cleanup.update(observed_at=(self.now-timedelta(seconds=61)).isoformat()),lambda:self.cleanup['connection'].update(cleanup_state='pending'),lambda:self.cleanup['connection'].update(desired_revision=16),lambda:self.native.update(owned_spd=1),lambda:self.native.update(owned_sad=False),lambda:self.native.update(azure_connection_id=self.discovery['gateway_id']),lambda:self.discovery.update(subscription='other')]
  for change in cases:
   self.setUp();change()
   with patch.object(h.socket,'gethostname',return_value='bastion-host'),patch.object(h.lab,'az') as az:
    with self.assertRaises(ValueError):self.call()
    az.assert_not_called()
 def test_projection_rejects_owner_binding_mode_selectors_and_pending(self):
  for key,value in [('owner','other'),('gateway',self.discovery['local_gateway_id']),('mode','InitiatorOnly'),('mode',None),('state','Updating'),('selectors',True),('trafficSelectors',[{}])]:
   bad=copy.deepcopy(self.view);bad[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):h.projection(bad,self.discovery)
 def test_noop_only_reads_and_returns_verified_mode(self):
  self.view['mode']='ResponderOnly'
  with patch.object(h.socket,'gethostname',return_value='bastion-host'),patch.object(h.lab,'discover',return_value=self.discovery),patch.object(h.lab,'az',return_value=self.view) as az:
   result=self.call()
   self.assertFalse(result['mutation_sent']);self.assertEqual(result['after']['mode'],'ResponderOnly')
   self.assertTrue(all(call.args[:3]==('network','vpn-connection','show') for call in az.call_args_list))
 def test_single_mutation_exact_shape_and_complete_readback(self):
  views=[self.view,self.view,self.discovery['connection_id'],dict(self.view,mode='ResponderOnly')]
  with patch.object(h.socket,'gethostname',return_value='bastion-host'),patch.object(h.lab,'discover',return_value=self.discovery),patch.object(h.lab,'az',side_effect=views) as az:
   result=self.call();self.assertTrue(result['mutation_sent'])
   mutations=[call.args for call in az.call_args_list if call.args[2]=='update']
   self.assertEqual(len(mutations),1);self.assertIn('connectionMode=ResponderOnly',mutations[0]);self.assertIn(h.lab.SUBSCRIPTION,mutations[0])
 def test_changed_binding_and_ambiguous_update_never_retry(self):
  bad=dict(self.discovery,gateway_id=self.discovery['local_gateway_id'])
  with patch.object(h.socket,'gethostname',return_value='bastion-host'),patch.object(h.lab,'discover',return_value=bad),patch.object(h.lab,'az') as az:
   with self.assertRaises(ValueError):self.call()
   az.assert_not_called()
  with patch.object(h.socket,'gethostname',return_value='bastion-host'),patch.object(h.lab,'discover',return_value=self.discovery),patch.object(h.lab,'az',side_effect=[self.view,self.view,ValueError('refused')]) as az:
   with self.assertRaises(ValueError):self.call()
   self.assertEqual(sum(call.args[2]=='update' for call in az.call_args_list),1)
 def test_digest_binds_exact_private_bytes(self):
  with self.assertRaises(ValueError):h.evidence(self.discovery,self.cleanup,self.native,'0'*64,b'other',self.now)


if __name__=='__main__':unittest.main()
