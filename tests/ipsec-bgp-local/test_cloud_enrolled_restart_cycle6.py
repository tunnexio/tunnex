import ast,json,pathlib,unittest
source=pathlib.Path(__file__).with_name('cloud-enrolled-restart-cycle6.py').read_text();tree=ast.parse(source)
fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='active_entries')
class TestFullActiveSet(unittest.TestCase):
 def fixture(self):
  owner='11111111-1111-4111-8111-111111111111';ids=['22222222-2222-4222-8222-222222222222','33333333-3333-4333-8333-333333333333']
  rows=[{'delivery':id,'node':owner,'connection':id}for id in ids]
  entries=[{'DeliveryID':id,'Phase':'applied','ContractVersion':3,'Allocation':{'Namespace':'net:[41]'},'Engines':[{'Binding':{'GatewayID':owner,'ConnectionID':id}}],'BGPProcess':{'Stage':'ready'},'BGPRoutes':{'Stage':'completed'}}for id in ids]
  return rows,{'Payload':{'Entries':entries}}
 def runfixture(self,rows,j):
  ns={'json':json,'NS':'net:[41]','cp_binding':lambda:rows};exec(compile(ast.Module(body=[fn],type_ignores=[]),'<source>','exec'),ns);return ns['active_entries'](json.dumps(j).encode())
 def test_exact_two(self):
  r,j=self.fixture();self.assertEqual(len(self.runfixture(r,j)),2)
 def test_missing_duplicate_foreign_and_uncertain(self):
  for kind in ['missing','duplicate','foreign','uncertain','namespace']:
   r,j=self.fixture();e=j['Payload']['Entries']
   if kind=='missing':e.pop()
   elif kind=='duplicate':e.append(e[0])
   elif kind=='foreign':e[1]['Engines'][0]['Binding']['GatewayID']=e[1]['DeliveryID']
   elif kind=='uncertain':e[1]['BGPProcess']['Stage']='partial'
   else:e[1]['Allocation']['Namespace']='net:[99]'
   with self.subTest(kind=kind),self.assertRaises(AssertionError):self.runfixture(r,j)
if __name__=='__main__':unittest.main()
