import importlib.util,json,pathlib,unittest
spec=importlib.util.spec_from_file_location('multi',pathlib.Path(__file__).with_name('assemble-multi-restoration.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TestActiveSet(unittest.TestCase):
 def fixture(self):
  owner='11111111-1111-4111-8111-111111111111'
  entries=[{'DeliveryID':x,'Phase':'applied','ContractVersion':3,'Engines':[{'Binding':{'GatewayID':owner}}]}for x in ['22222222-2222-4222-8222-222222222222','33333333-3333-4333-8333-333333333333']]
  return {'Payload':{'OwnerID':owner,'Entries':entries}}
 def test_pair(self):
  j=self.fixture();self.assertEqual(len(m.active_deliveries(json.dumps(j).encode())[1]),2)
 def test_invalid(self):
  for mutation in ('duplicate','foreign','pending','empty'):
   j=self.fixture();e=j['Payload']['Entries']
   if mutation=='duplicate':e.append(e[0])
   if mutation=='foreign':e[1]['Engines'][0]['Binding']['GatewayID']=e[0]['DeliveryID']
   if mutation=='pending':e[1]['Phase']='cleanup_pending'
   if mutation=='empty':e.clear()
   with self.subTest(mutation=mutation),self.assertRaises(AssertionError):m.active_deliveries(json.dumps(j).encode())
if __name__=='__main__':unittest.main()
