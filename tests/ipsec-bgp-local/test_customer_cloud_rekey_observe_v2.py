import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('driver',pathlib.Path(__file__).with_name('customer-cloud-rekey-observe-v2.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TestSelectedCHILD(unittest.TestCase):
 def setUp(self):
  self.p={'name':'tnx-ipsec-dddddddd-0000-0000-0000-000000000002-d1-c1-s1','unique_id':2,'reqid':2,'spi_in':'c25f773b','spi_out':'cd6cbd88','ifid':702,'local':'198.19.240.10','remote':'198.19.240.21'}
  self.raw='list-sa event {'+self.p['name']+' {state=ESTABLISHED local-host=198.19.240.10 remote-host=198.19.240.21 child-sas {child {name='+self.p['name']+' uniqueid=2 reqid=2 state=INSTALLED mode=TUNNEL protocol=ESP spi-in=c25f773b spi-out=cd6cbd88 if-id-in=000002be if-id-out=000002be encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 local-ts=[0.0.0.0/0] remote-ts=[0.0.0.0/0]}}}}'
 def test_exact_owned_installed(self):self.assertEqual(m.selected_child(self.raw,self.p)['uniqueid'],'2')
 def test_ambiguous_foreign_partial_unknown(self):
  for old,new in [('reqid=2','reqid=3'),('uniqueid=2','uniqueid=3'),('state=INSTALLED','state=DELETING'),('spi-in=c25f773b','spi-in=00000001'),('if-id-out=000002be','if-id-out=000002bf'),('remote-host=198.19.240.21','remote-host=198.19.240.22'),('local-ts=[0.0.0.0/0]','local-ts=[10.0.0.0/8]'),('encr-keysize=256','encr-keysize=128')]:
   with self.subTest(field=old),self.assertRaises(AssertionError):m.selected_child(self.raw.replace(old,new),self.p)
  with self.assertRaises(AssertionError):m.selected_child(self.raw+self.raw,self.p)
 def test_wrong_parent_cannot_borrow_endpoints(self):
  forged=self.raw.replace('local-host=198.19.240.10','local-host=198.19.240.99')
  foreign='list-sa event {foreign {state=ESTABLISHED local-host=198.19.240.10 remote-host=198.19.240.21}}'
  with self.assertRaises(AssertionError):m.selected_child(forged+foreign,self.p)
 def test_duplicate_and_unbalanced_fields(self):
  for raw in [self.raw.replace('reqid=2','reqid=2 reqid=2'),self.raw[:-1],self.raw+' unexpected',self.raw.replace('state=INSTALLED','state=INSTALLED child-sas {}')]:
   with self.assertRaises(AssertionError):m.selected_child(raw,self.p)
if __name__=='__main__':unittest.main()
