import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_owned_standby_conversion as fixture

def load(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).parents[2]/'deploy/azure'/file)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
s=load('static_test','configure-owned-static.py')
a=load('advertised_test','read-owned-advertised-prefixes.py')
m=fixture.m

def bundle():
 return {'connection':{'id':m.CONNECTION,'enableBgp':True,'provisioningState':'Succeeded','connectionMode':'Default','policy':{'exact':True}},'lng':{'id':s.LNG,'bgpSettings':{'asn':65000},'localNetworkAddressSpace':{'addressPrefixes':[]},'provisioningState':'Succeeded'},'gateway':fixture.baseline(),'pips':[{'id':x} for x in m.PIPS],'vnet':{'saved':True},'external':{'dns':'unchanged'}}

def binding():return dict(fixture.expected(),original_connection_id=fixture.expected()['connection_id'])

class Restoration(unittest.TestCase):
 def test_restore_payload_reordered_arrays_excludes_only_server_fields(self):
  value=fixture.baseline();value['ipConfigurations'].reverse()
  payload=m.restore_payload(value)
  self.assertEqual(len(payload[0]),2)
  self.assertEqual({x['name'] for x in payload[0]},set(m.NAMES))
  self.assertTrue(all(set(x)=={'name','subnet','publicIPAddress','privateIPAllocationMethod'} for x in payload[0]))
  self.assertEqual({x['customBgpIpAddresses'][0] for x in payload[1]},set(m.CUSTOM))
  value['ipConfigurations'][0]['unreviewed']=True
  with self.assertRaises(ValueError):m.restore_payload(value)
 def test_restoration_binding_rejects_foreign_lineage_and_namespace(self):
  self.assertEqual(m.restoration_binding(binding(),fixture.expected()),fixture.expected())
  for key in ('original_connection_id','org_id','namespace_inode'):
   value=binding();value[key]='foreign'
   with self.subTest(key=key),self.assertRaises(ValueError):m.restoration_binding(value,fixture.expected())
 def test_static_actual_empty_original_prefix_roundtrip_and_timeout_no_replay(self):
  current=bundle();raw={k:json.dumps(current[k]).encode() for k in ('connection','lng','gateway')}
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder).resolve();root.chmod(0o700);state=root/'state.json'
   def observe():return copy.deepcopy(current),raw
   def command(*args):
    if args==('version',):return {'azure-cli':'2.91.0'}
    if args[:3]==('network','local-gateway','update'):
     current['lng']['localNetworkAddressSpace']['addressPrefixes']=json.loads(args[args.index('--set')+1].split('=',1)[1]);return s.LNG
    if args[:3]==('network','vpn-connection','update'):
     current['connection']['enableBgp']=args[args.index('--enable-bgp')+1]=='true';return m.CONNECTION
    self.fail('unexpected command')
   with patch.object(s.socket,'gethostname',return_value='bastion-host'),patch.object(s,'observed',side_effect=observe),patch.object(s.common,'protected',side_effect=lambda x:x),patch.object(s.common,'vnet',return_value=['10.231.0.0/16']),patch.object(s.lab,'az',side_effect=command):
    s.run('prepare',state,fixture.expected())
    with patch.object(s.lab,'az',side_effect=lambda *args: {'azure-cli':'2.91.0'} if args==('version',) else (_ for _ in ()).throw(s.subprocess.TimeoutExpired('az',180))):
     with self.assertRaises(s.subprocess.TimeoutExpired):s.run('apply',state,None,*fixture.receipts())
    self.assertEqual(json.loads(state.read_text())['stage'],'apply_sent')
    self.assertTrue(state.with_name(state.name+'.apply-lng-reserved').exists())
    with self.assertRaises(ValueError):s.run('apply',state,None,*fixture.receipts())
    # Actual later cloud read proves first write happened; restore original []
    # with a different one-time restoration reservation, never repeat apply.
    current['lng']['localNetworkAddressSpace']['addressPrefixes']=s.STATIC_PREFIXES[:]
    self.assertEqual(s.run('restore',state,binding(),*fixture.receipts())['stage'],'restored')
    self.assertEqual(current['lng']['localNetworkAddressSpace']['addressPrefixes'],[])
    self.assertTrue(current['connection']['enableBgp'])
    with self.assertRaises(ValueError):s.run('restore',state,binding(),*fixture.receipts())
 def test_foreign_protected_property_refuses_before_mutation(self):
  original=bundle()
  with patch.object(s.common,'protected',side_effect=lambda x:x),patch.object(s.common,'vnet',return_value=['10.231.0.0/16']):
   for component in ('connection','pips','external','gateway'):
    changed=copy.deepcopy(original)
    if component=='pips':changed[component][0]['id']='foreign'
    else:changed[component]['foreign']=True
    with self.subTest(component=component),self.assertRaises(ValueError):s.classify(changed,original)
 def test_wrong_host_no_cloud_calls(self):
  with patch.object(s.socket,'gethostname',return_value='other'),patch.object(s.lab,'az') as az:
   with self.assertRaises(ValueError):s.run('prepare',Path('/missing'),fixture.expected())
   az.assert_not_called()
 def test_standby_restore_timeout_reservation_and_reconcile(self):
  original=fixture.baseline();wire=json.dumps(original).encode();actual=m.target(original)
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder).resolve();root.chmod(0o700);state=root/'state.json'
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m,'bindings',return_value={'owned':'binding'}),patch.object(m,'raw_read_gateway',return_value=(wire,original)),patch.object(m.lab,'az',return_value={'azure-cli':'2.91.0'}):
    m.run('prepare',state,fixture.expected())
   data=json.loads(state.read_text());data['stage']='converted';m.common.private_write(state,data)
   def command(*args):
    if args==('version',):return {'azure-cli':'2.91.0'}
    self.assertIn('activeActive=true',args)
    self.assertTrue(any(x.startswith('ipConfigurations=') for x in args))
    self.assertEqual(json.loads(state.read_text())['stage'],'restore_sent')
    raise m.subprocess.TimeoutExpired('az',180)
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m,'bindings',return_value={'owned':'binding'}),patch.object(m,'raw_read_gateway',return_value=(json.dumps(actual).encode(),actual)),patch.object(m.lab,'az',side_effect=command):
    with self.assertRaises(m.subprocess.TimeoutExpired):m.run('restore',state,binding(),*fixture.receipts())
    self.assertTrue(state.with_name(state.name+'.restore-reserved').exists())
    with self.assertRaises(ValueError):m.run('restore',state,binding(),*fixture.receipts())
   with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m,'bindings',return_value={'owned':'binding'}),patch.object(m,'raw_read_gateway',return_value=(wire,original)),patch.object(m.lab,'az') as az:
    self.assertEqual(m.run('reconcile',state,None)['stage'],'restored');az.assert_not_called()
 def test_nanosecond_timestamp_and_expiry(self):
  from datetime import datetime,timezone
  clock=datetime(2026,10,11,0,0,1,tzinfo=timezone.utc)
  m.fresh('2026-10-11T00:00:00.123456789Z',clock)
  with self.assertRaises(ValueError):m.fresh('2026-10-10T23:58:00.1Z',clock)

class Advertised(unittest.TestCase):
 def test_documented_envelope_and_explicit_flat_list(self):
  for value in ({'value':[{'network':'10.235.77.0/24','origin':'Igp'}]},[{'network':'10.235.77.0/24'}]):
   self.assertEqual(a.parse(json.dumps(value).encode())['prefixes'],['10.235.77.0/24'])
 def test_malformed_partial_and_noncanonical_fail_closed(self):
  for raw in (b'null',b'{"value":[],"nextLink":"more"}',b'{"value":[],"value":[]}',b'[{"network":"10.235.77.1/24"}]',b'[{"network":"::/0"}]',b'[{"network":"10.231.0.0/16","secret":"not accepted"}]'):
   with self.subTest(raw=raw),self.assertRaises(ValueError):a.parse(raw)
 def test_wrong_host_precedes_discovery(self):
  with patch.object(a.socket,'gethostname',return_value='other'),patch.object(a.lab,'discover') as discover:
   with self.assertRaises(ValueError):a.read()
   discover.assert_not_called()

if __name__=='__main__':unittest.main()
