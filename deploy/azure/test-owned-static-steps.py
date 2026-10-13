import copy,hashlib,importlib.util,json,tempfile,unittest,uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch
p=Path(__file__).parent/'configure-owned-static.py';spec=importlib.util.spec_from_file_location('s',p);s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
class Steps(unittest.TestCase):
 def setup_fixture(self,folder):
  folder=folder.resolve()
  self.clock=datetime.now(timezone.utc);self.writes=[]
  self.value={'connection':{'enableBgp':True,'provisioningState':'Succeeded'},'lng':{'localNetworkAddressSpace':{'addressPrefixes':[]},'provisioningState':'Succeeded'},'gateway':{'ipConfigurations':[],'bgpSettings':{'bgpPeeringAddresses':[]},'provisioningState':'Succeeded'},'pips':[],'vnet':{'id':s.common.VNET,'tags':{'owner':s.lab.OWNER},'provisioningState':'Succeeded','addressSpace':{'addressPrefixes':['10.231.0.0/16']}},'external':{}}
  self.binding={k:str(uuid.uuid4())for k in ('org_id','site_id','gateway_id','connection_id')};self.binding.update(namespace_device=4,namespace_inode=42)
  self.state=folder/'state.json'
 def observed(self):
  self.clock+=timedelta(seconds=15.5);v=copy.deepcopy(self.value);return v,{k:json.dumps(v[k]).encode()for k in ('connection','lng','gateway')}
 def az(self,*a):
  if a==('version',):return {'azure-cli':'2.91.0'}
  self.writes.append(a)
  if a[1]=='local-gateway':self.value['lng']['localNetworkAddressSpace']['addressPrefixes']=s.STATIC_PREFIXES;return s.LNG
  if a[1]=='vpn-connection':self.value['connection']['enableBgp']=False;return s.shared.CONNECTION
  raise AssertionError('unexpected mocked command')
 def receipt(self):
  cp={'id':self.binding['connection_id'],'desired_revision':3,'desired_intent':'disabled','application_state':'not_applied','cleanup_state':'retained_guard'};cleanup={'phase':'read','observed_at':self.clock.isoformat(),'connection':cp,'cleanup_readback_settled':True};n={'version':1,'kind':'owned_native_cleanup_absence','observed_at':self.clock.isoformat(),'desired_revision':3,'azure_connection_id':s.shared.CONNECTION,'guard_retained':True,**self.binding}
  n.update({k:0for k in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes')});wire=json.dumps(n).encode();return cleanup,n,wire,hashlib.sha256(wire).hexdigest()
 def mocks(self):return (patch.object(s.socket,'gethostname',return_value='bastion-host'),patch.object(s,'observed',side_effect=self.observed),patch.object(s.lab,'az',side_effect=self.az),patch.object(s.shared,'now',side_effect=lambda:self.clock))
 def test_aged_second_step_never_reserved_then_fresh_continuation(self):
  with tempfile.TemporaryDirectory()as td:
   self.setup_fixture(Path(td));a,b,c,d=self.mocks()
   with a,b,c,d:
    s.run('prepare',self.state,self.binding)
    with self.assertRaises(ValueError):s.run('apply',self.state,None,*self.receipt())
    self.assertEqual(len(self.writes),1);self.assertTrue(self.state.with_name('state.json.apply-lng-reserved').exists());self.assertFalse(self.state.with_name('state.json.apply-connection-reserved').exists())
    result=s.run('continue-apply',self.state,None,*self.receipt());self.assertEqual(result['stage'],'static');self.assertEqual(len(self.writes),2)
    with self.assertRaises(ValueError):s.run('continue-apply',self.state,None,*self.receipt())
    self.assertEqual(len(self.writes),2)
 def test_explicit_single_step_pauses_without_second_write(self):
  with tempfile.TemporaryDirectory()as td:
   self.setup_fixture(Path(td));a,b,c,d=self.mocks()
   with a,b,c,d:
    s.run('prepare',self.state,self.binding);r=s.run('apply-step',self.state,None,*self.receipt());self.assertEqual(r['classification'],'owned_partial');self.assertEqual(r['stage'],'apply_sent');self.assertEqual(len(self.writes),1)
    r=s.run('continue-apply',self.state,None,*self.receipt());self.assertEqual(r['stage'],'static');self.assertEqual(len(self.writes),2)
 def test_pending_or_reserved_unknown_never_replayed(self):
  with tempfile.TemporaryDirectory()as td:
   self.setup_fixture(Path(td));a,b,c,d=self.mocks()
   with a,b,c,d:
    s.run('prepare',self.state,self.binding);s.run('apply-step',self.state,None,*self.receipt());self.value['lng']['provisioningState']='Updating'
    with self.assertRaises(ValueError):s.run('continue-apply',self.state,None,*self.receipt())
    self.value['lng']['provisioningState']='Succeeded';marker=self.state.with_name('state.json.apply-connection-reserved');marker.write_bytes(b'{}');marker.chmod(0o600)
    with self.assertRaises(ValueError):s.run('continue-apply',self.state,None,*self.receipt())
    self.assertEqual(len(self.writes),1)
 def test_drift_and_wrong_marker_refuse_without_second_write(self):
  for fault in ('marker','protected','expired'):
   with self.subTest(fault=fault),tempfile.TemporaryDirectory()as td:
    self.setup_fixture(Path(td));a,b,c,d=self.mocks()
    with a,b,c,d:
     s.run('prepare',self.state,self.binding);s.run('apply-step',self.state,None,*self.receipt());receipt=self.receipt()
     if fault=='marker':
      marker=self.state.with_name('state.json.apply-lng-reserved');v=json.loads(marker.read_bytes());v['current_connection_id']=str(uuid.uuid4());marker.write_text(json.dumps(v))
     elif fault=='protected':self.value['vnet']['addressSpace']['addressPrefixes']=['10.232.0.0/16']
     else:self.clock+=timedelta(seconds=61)
     with self.assertRaises(ValueError):s.run('continue-apply',self.state,None,*receipt)
     self.assertEqual(len(self.writes),1);self.assertFalse(self.state.with_name('state.json.apply-connection-reserved').exists())
if __name__=='__main__':unittest.main()
