import ast,copy,pathlib,unittest
path=pathlib.Path(__file__).with_name('cloud-enrolled-restart-cycle6-v3.py');tree=ast.parse(path.read_text());fn=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='has_prior_restoration');ns={};exec(compile(ast.Module(body=[fn],type_ignores=[]),str(path),'exec'),ns);check=ns[fn.name]
BOOT='11111111-1111-4111-8111-111111111111'
class TestPriorState(unittest.TestCase):
 def entry(self):return {'Allocation':{'Namespace':'net:[41]','Generation':'22222222-2222-4222-8222-222222222222'}}
 def restored(self):
  e=self.entry();e['Restoration']={'BootID':BOOT,'Epoch':1,'Retired':[{'Entry':{'Phase':'applied','Restoration':None,'ResetCleanup':None},'NewBootID':BOOT,'NewNamespace':e['Allocation']['Namespace'],'NewGeneration':e['Allocation']['Generation'],'EvidenceDigest':'a'*64}]};return e
 def test_nil_and_actual_boot_only(self):
  self.assertFalse(check(self.entry(),BOOT))
  for retired in (None,[]):
   e=self.entry();e['Restoration']={'BootID':BOOT,'Epoch':0,'Retired':retired};self.assertFalse(check(e,BOOT))
 def test_restored(self):self.assertTrue(check(self.restored(),BOOT))
 def test_malformed_epoch_history_boot(self):
  for mutate in [lambda r:r.update(Epoch=0),lambda r:r.update(Epoch=2),lambda r:r.update(Epoch=True),lambda r:r.update(Epoch=17),lambda r:r.update(BootID='33333333-3333-4333-8333-333333333333'),lambda r:r.update(Extra=True),lambda r:r.update(Retired='unknown'),lambda r:r['Retired'][0].update(NewNamespace='net:[99]'),lambda r:r['Retired'][0]['Entry'].update(Restoration={})]:
   e=self.restored();mutate(e['Restoration'])
   with self.assertRaises(AssertionError):check(e,BOOT)
 def test_new_run_history_preserved(self):self.assertIn("run.name=='cloud-enrolled-restart-21169a9f-cycle6-v3'",path.read_text())
if __name__=='__main__':unittest.main()
