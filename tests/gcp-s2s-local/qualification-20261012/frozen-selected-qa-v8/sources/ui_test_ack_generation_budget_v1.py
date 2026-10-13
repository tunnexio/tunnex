import pathlib,types,unittest
D=pathlib.Path(__file__).parent;p=D/'ui_ack_generation_budget_v1.py';m=types.ModuleType('ack_budget');exec(compile(p.read_text(),str(p),'exec'),m.__dict__)
class AckBudgetTests(unittest.TestCase):
 def rig(self,remaining=30,shared=120,outer=180,statuses=None):
  clock=[100.];wall=[m.strict_utc('2026-10-11T19:00:00Z')];records=[];calls=[];statuses=list(statuses or ['accepted'])
  identity={'fresh_until_at':'2026-10-11T19:00:'+str(remaining).zfill(2)+'Z'}
  def ack():calls.append('ack');return statuses.pop(0)
  def wait(reader,budget,until):
   calls.append((budget,until))
   while True:
    status=reader()
    if status=='accepted':return
    if status!='pending':raise ValueError('terminal')
    clock[0]+=.2;wall[0]+=.2
  def run():return m.wait_ack_same_generation(wait,ack,identity,shared,outer,lambda:clock[0],lambda:wall[0],records.append)
  return run,calls,records
 def test_no_five_second_cap(self):
  run,calls,records=self.rig();run();self.assertEqual(calls[0],(11.,111.));self.assertTrue(records[0]['completed'])
 def test_original_shared_and_outer_clip(self):
  for shared,outer,expected in [(103.,180.,103.),(120.,104.,104.)]:
   run,calls,_=self.rig(shared=shared,outer=outer);run();self.assertEqual(calls[0],(expected-100.,expected))
 def test_reserve_exhausted_before_ack(self):
  run,calls,records=self.rig(remaining=19)
  with self.assertRaises(TimeoutError):run()
  self.assertEqual(calls,[]);self.assertFalse(records[0]['completed'])
 def test_known_pending_count_and_terminal_not_swallowed(self):
  run,_,records=self.rig(statuses=['pending','accepted']);run();self.assertEqual(records[0]['pending_samples'],1)
  run,_,records=self.rig(statuses=['unknown'])
  with self.assertRaises(ValueError):run()
  self.assertFalse(records[0]['completed'])
 def test_rfc3339_fraction_and_invalid(self):
  self.assertLess(m.strict_utc('2026-10-11T19:00:00.35227Z'),m.strict_utc('2026-10-11T19:00:00.352271999Z'))
  with self.assertRaises(ValueError):m.strict_utc('2026-10-11 19:00:00Z')
if __name__=='__main__':unittest.main()
