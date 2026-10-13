import copy
from datetime import datetime,timezone
import importlib.util
from pathlib import Path
import unittest
s=importlib.util.spec_from_file_location('copy_absence',Path(__file__).with_name('copy-max-prefix-absence.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Copy(unittest.TestCase):
 def fixture(self):
  ids={k:'00000000-0000-4000-8000-'+str(i).zfill(12) for i,k in enumerate(('org_id','site_id','gateway_id','connection_id'),1)}
  b={**ids,'mode':'absence','desired_revision':55,'configuration_revision':1,'namespace_device':4,'namespace_inode':9}
  r={**ids,'version':1,'kind':'owned_native_cleanup_absence','observed_at':datetime.now(timezone.utc).isoformat(),'desired_revision':55,'configuration_revision':1,'guard_retained':True,'namespace_device':4,'namespace_inode':9,'azure_connection_id':'/subscriptions/34e2f259-b462-40bf-8f4a-06a3930d99e6/resourceGroups/tunnex-azure-s2s-20261010/providers/Microsoft.Network/connections/tunnex-connection','journal_sha256':'a'*64,'journal_entries':25,'scope':'Independent bracketed native observation only; no authority, synthetic acknowledgement or packet readiness',**{k:0 for k in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes')}}
  st={'setup':ids,'prior':{'id':ids['connection_id']},'cleanup_revision':55};return r,b,st
 def test_exact_typed_samebytes_context(self):
  r,b,st=self.fixture();m.verify(r,b,st,datetime.now(timezone.utc))
 def test_new_proof_requires_exact_executable_binding(self):
  r,b,st=self.fixture();b['node_executable_sha256']='d'*64;r['node_executable_sha256']='d'*64
  m.verify(r,b,st,datetime.now(timezone.utc))
  for value in ('e'*64,'D'*64,'',None):
   r['node_executable_sha256']=value
   with self.assertRaises(ValueError):m.verify(r,b,st,datetime.now(timezone.utc))
 def test_foreign_extra_nonzero_superseded(self):
  for change in ('extra','objects','revision','connection'):
   r,b,st=self.fixture()
   if change=='extra':r['raw_journal']={}
   if change=='objects':r['owned_sad']=1
   if change=='revision':st['cleanup_revision']=56
   if change=='connection':st['prior']['id']='foreign'
   with self.assertRaises(ValueError):m.verify(r,b,st,datetime.now(timezone.utc))
if __name__=='__main__':unittest.main()
