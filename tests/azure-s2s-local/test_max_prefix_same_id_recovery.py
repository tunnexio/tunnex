import copy
from datetime import datetime,timezone,timedelta
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

def load(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

r=load('same_id_recovery','recover-max-prefix-create.py')
fixture=load('same_id_lifecycle_fixture','test_max_prefix_qualification.py')

class SameIDRecovery(unittest.TestCase):
 def setUp(self):
  self.f=fixture.Lifecycle();self.f.setUp();self.state=self.f.reserve_failed_target();self.state['native_binding'].update(node_executable_sha256='d'*64,configuration_revision=5);r.m.secure.write(self.f.state,self.state);self.original_bytes=r.m.secure.read(self.f.state)
  now=datetime.now(timezone.utc);stamp=now.isoformat()
  self.e={'observed_at':stamp,'saved_stage':'create_reserved','target':self.state['target'],'cleanup_revision':self.state['cleanup_revision'],'state_sha256':hashlib.sha256(self.original_bytes).hexdigest(),'creation_marker':True,'creation_marker_mtime':stamp,'selected_http_rows':[{'event':'http_request','path_kind':'configuration_check','method':'POST','status':200,'time':stamp},{'event':'http_request','path_kind':'create','method':'POST','status':409,'time':stamp}],'unparsed_lines':0,'private_raw_log_sha256':'a'*64,'phase_log_generic_refusal_verified':True,'phase_run_id':'max-prefix-phase-create-11111111-1111-4111-8111-111111111111','phase_log_mtime':stamp,'api_identity':r.INITIAL_API}
  self.gateway=True;original_call=self.f.call
  def call(method,path,body=None,revision=None):
   if '/ipsec/eligibility?' in path:return {'azure_bgp_recreation':{'eligible':self.gateway,'reason':'eligible' if self.gateway else 'unsupported'}}
   try:return original_call(method,path,body,revision)
   except fixture.a.api.APIError as error:raise r.m.api.APIError(error.status,error.code) from None
  self.client=type('Client',(),{'call':staticmethod(call)})();self.f.calls=[]
 def tearDown(self):self.f.tearDown()
 def run_recovery(self,execute=False):
  raw=json.dumps(self.e).encode();absence=self.f.absence(r.m.ORIGINAL,self.state['cleanup_revision'])
  absence['absence'].update(configuration_revision=5,node_executable_sha256='e'*64);absence['absence_bytes']=json.dumps(absence['absence']).encode();absence['absence_hash']=hashlib.sha256(absence['absence_bytes']).hexdigest()
  binding=copy.deepcopy(self.state['native_binding']);binding['node_executable_sha256']='e'*64;binding_bytes=json.dumps(binding).encode()
  return r.recover(self.client,self.f.setup,self.f.state,self.e,raw,hashlib.sha256(raw).hexdigest(),absence['absence'],absence['absence_bytes'],absence['absence_hash'],binding,binding_bytes,hashlib.sha256(binding_bytes).hexdigest(),'e'*64,'private.offline.key',self.f.discovery,execute)
 def posts(self):return [v for v in self.f.calls if v[0]=='POST' and v[1].endswith('/connections')]
 def test_default_preflight_never_creates_or_changes_saved_marker_ids(self):
  result=self.run_recovery();self.assertFalse(result['dispatch_sent']);self.assertEqual(self.posts(),[])
  self.assertEqual(r.m.secure.read(self.f.state),self.original_bytes)
  self.assertFalse(self.f.state.with_name(self.f.state.name+'.same-id-recovery-reserved').exists())
 def test_one_dispatch_same_immutable_ids_no_allocation_then_no_replay(self):
  result=self.run_recovery(True);self.assertEqual(result['category'],'same_id_disabled_created_requires_independent_read')
  self.assertEqual(result['normal_connection']['id'],self.state['target']['id']);self.assertEqual(result['normal_connection']['maximum_prefixes'],1)
  self.assertEqual(self.posts()[0][2]['id'],self.state['target']['id']);self.assertEqual(self.posts()[0][2]['tunnel_ids'],self.state['target']['tunnel_ids'])
  self.assertEqual(r.m.secure.read(self.f.state),self.original_bytes)
  with self.assertRaises(ValueError):self.run_recovery(True)
  self.assertEqual(len(self.posts()),1)
 def test_unknown_api_response_preserves_recovery_marker_and_never_reposts(self):
  original_call=self.client.call
  def call(method,path,body=None,revision=None):
   if method=='POST' and path.endswith('/connections'):
    self.f.calls.append((method,path,copy.deepcopy(body),revision));raise r.m.api.APIError(503,'ipsec_connection_unavailable')
   return original_call(method,path,body,revision)
  self.client.call=call
  result=self.run_recovery(True);self.assertEqual(result['category'],'outcome_requires_read_no_replay');self.assertEqual(result['http_status'],503)
  with self.assertRaises(ValueError):self.run_recovery(True)
  self.assertEqual(len(self.posts()),1);self.assertEqual(r.m.secure.read(self.f.state),self.original_bytes)
 def test_only_confirmed_409_exact_state_identity_chronology_and_root_bytes(self):
  original=copy.deepcopy(self.e)
  for fault in ('unknown','201','foreign','state','api','duplicate','unparsed','chronology'):
   self.e=copy.deepcopy(original)
   if fault=='unknown':self.e['selected_http_rows'][1]['status']=503
   if fault=='201':self.e['selected_http_rows'][1]['status']=201
   if fault=='foreign':self.e['target']['id']=fixture.I(99)
   if fault=='state':self.e['state_sha256']='b'*64
   if fault=='api':self.e['api_identity']['executable_sha256']='b'*64
   if fault=='duplicate':self.e['selected_http_rows'].append(copy.deepcopy(self.e['selected_http_rows'][1]))
   if fault=='unparsed':self.e['unparsed_lines']=1
   if fault=='chronology':self.e['creation_marker_mtime']=(datetime.now(timezone.utc)-timedelta(seconds=20)).isoformat()
   with self.subTest(fault=fault),self.assertRaises(ValueError):self.run_recovery(True)
  self.assertEqual(self.posts(),[])
  with self.assertRaises(ValueError):r.digest(b'actual','c'*64)
 def test_missing_capability_stale_native_and_existing_recovery_marker_refuse(self):
  self.gateway=False
  with self.assertRaises(ValueError):self.run_recovery(True)
  self.gateway=True
  with patch.object(r.m,'native_absence',side_effect=ValueError('actual proof expired')):
   with self.assertRaises(ValueError):self.run_recovery(True)
  r.m.reserve(self.f.state.with_name(self.f.state.name+'.same-id-recovery-reserved'))
  with self.assertRaises(ValueError):self.run_recovery(True)
  self.assertEqual(self.posts(),[])
 def test_current_binding_preserves_historical_proof_except_explicit_new_source_pin(self):
  original=self.state['native_binding'];current=copy.deepcopy(original);current['node_executable_sha256']='e'*64
  raw=json.dumps(current).encode();r.current_binding(current,raw,hashlib.sha256(raw).hexdigest(),original,'e'*64)
  for fault in ('node','namespace','extra','digest'):
   value=copy.deepcopy(current)
   if fault=='node':value['node_executable_sha256']='f'*64
   if fault=='namespace':value['namespace_inode']+=1
   if fault=='extra':value['fake_authority']=True
   data=json.dumps(value).encode();pin='f'*64 if fault=='digest' else hashlib.sha256(data).hexdigest()
   with self.subTest(fault=fault),self.assertRaises(ValueError):r.current_binding(value,data,pin,original,'e'*64)
 def test_partial_or_malformed_post_response_returns_finite_unknown_receipt(self):
  for fault in ('partial','timeout','json','projection','config'):
   with self.subTest(fault=fault):
    original_call=self.client.call
    def call(method,path,body=None,revision=None):
     if method=='POST' and path.endswith('/connections'):
      self.f.calls.append((method,path,copy.deepcopy(body),revision))
      if fault=='partial':raise http.client.IncompleteRead(b'private-response',10)
      if fault=='timeout':raise TimeoutError('private-network-details')
      if fault=='json':raise ValueError('private-malformed-response')
      if fault=='projection':return {'private_raw_response':'do not export'}
     if fault=='config' and path.endswith('/configuration') and self.state['target']['id'] in path:raise OSError('private-readback-details')
     return original_call(method,path,body,revision)
    self.client.call=call
    result=self.run_recovery(True);self.assertEqual(result['category'],'outcome_requires_read_no_replay')
    self.assertNotIn('private',json.dumps(result));self.assertNotIn('normal_connection',result)
    self.assertTrue(self.f.state.with_name(self.f.state.name+'.same-id-recovery-reserved').exists())
    # Isolated offline cases only; production markers are never removed.
    self.f.state.with_name(self.f.state.name+'.same-id-recovery-reserved').unlink();self.f.rows.pop(self.state['target']['id'],None);self.client.call=original_call

if __name__=='__main__':unittest.main()
