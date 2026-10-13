"""Pure exact current partial/healthy entry census; no cloud calls."""
import ast,copy,pathlib,types,unittest,uuid
SOURCE=pathlib.Path(__file__).with_name('cloud-enrolled-restart-cycle7.py')
def validators():
 boot='11111111-1111-4111-8111-111111111111'
 scope={'DELIVERY':'44e340c8-1111-4c1b-8a79-368e1b628ba9','NS':'net:[4026532816]','pathlib':types.SimpleNamespace(Path=lambda _:types.SimpleNamespace(read_text=lambda:boot))}
 for node in ast.parse(SOURCE.read_text()).body:
  if isinstance(node,ast.Assign) and any(isinstance(x,ast.Name)and x.id=='CYCLE7_ENTRY_PINS'for x in node.targets) or isinstance(node,ast.FunctionDef)and node.name in ['has_prior_restoration','validate_cycle7_entry']:
   exec(compile(ast.Module(body=[node],type_ignores=[]),'validation','exec'),scope)
 return scope,boot
class Cycle7EntryTest(unittest.TestCase):
 def test_exact_and_foreign(self):
  scope,boot=validators()
  for id,pin in scope['CYCLE7_ENTRY_PINS'].items():
   e={'DeliveryID':id,'Allocation':{'Namespace':scope['NS'],'Generation':pin['generation']},'Observed':copy.deepcopy(pin['observed']),'BGPProcess':None,'BGPRoutes':None,'ResetCleanup':None,'BGPProcessRetired':[{'Stage':'cleaned'}for _ in range(11)]}
   h={'Entry':{'Restoration':None,'ResetCleanup':None,'Phase':'applied'},'NewBootID':boot,'NewNamespace':scope['NS'],'NewGeneration':pin['generation'],'EvidenceDigest':pin['prior_sha256']}
   e['Restoration']={'BootID':boot,'Epoch':pin['epoch'],'Retired':[copy.deepcopy(h)for _ in range(pin['epoch'])]}
   if id!=scope['DELIVERY']:e['BGPProcess']={'Stage':'ready','Generation':12,'Namespace':scope['NS']};e['BGPRoutes']={'Stage':'completed'}
   with self.subTest(id=id,case='exact'):self.assertTrue(scope['validate_cycle7_entry'](e))
   for kind in ['foreign-observed','foreign-generation','wrong-prior','uncleaned-retired','unexpected-duty']:
    x=copy.deepcopy(e)
    if kind=='foreign-observed':x['Observed'][0]['InterfaceIndex']=99
    if kind=='foreign-generation':x['Allocation']['Generation']=str(uuid.uuid4())
    if kind=='wrong-prior':x['Restoration']['Retired'][-1]['EvidenceDigest']='0'*64
    if kind=='uncleaned-retired':x['BGPProcessRetired'][0]['Stage']='ready'
    if kind=='unexpected-duty':
     if id==scope['DELIVERY']:x['BGPRoutes']={'Stage':'completed'}
     else:x['BGPProcess']['Generation']=13
    with self.subTest(id=id,case=kind),self.assertRaises(AssertionError):scope['validate_cycle7_entry'](x)
if __name__=='__main__':unittest.main()
