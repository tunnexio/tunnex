"""Local subprocess clock regression only; no transport, API, runtime or cloud."""
import pathlib,types,unittest,time,subprocess,sys,json,ast
D=pathlib.Path(__file__).parent
def module(name):
 p=D/name;m=types.ModuleType(name);m.__file__=str(p);exec(compile(p.read_text(),str(p),'exec'),m.__dict__);return m
class ClockTests(unittest.TestCase):
 def test_subprocess_uses_same_absolute_clock_and_remaining_deadline(self):
  checker=module('check-selected-transition-v5.py');runner=module('run-selected-transition-clean17-v5.py')
  before=runner.shared_clock();end=before+5
  code="import pathlib,types,json,sys;d=pathlib.Path(sys.argv[1]);m=types.ModuleType('clock_child');m.__file__=str(d/'check-selected-transition-v5.py');exec(compile(pathlib.Path(m.__file__).read_text(),m.__file__,'exec'),m.__dict__);now=m.shared_clock();print(json.dumps({'clock':now,'age':now-float(sys.argv[2]),'remaining':float(sys.argv[3])-now}))"
  result=subprocess.run([sys.executable,'-c',code,str(D),repr(before),repr(end)],capture_output=True,text=True,check=True,timeout=5)
  after=runner.shared_clock();observed=json.loads(result.stdout)
  self.assertLessEqual(before,observed['clock']);self.assertLessEqual(observed['clock'],after)
  self.assertGreaterEqual(observed['age'],0);self.assertGreater(observed['remaining'],0);self.assertLessEqual(observed['remaining'],5)
  self.assertLessEqual(before,checker.shared_clock());self.assertLessEqual(checker.shared_clock(),runner.shared_clock())
 def test_no_local_origin_monotonic_calls_or_deadline_reset(self):
  for name in ('check-selected-transition-v5.py','run-selected-transition-clean17-v5.py'):
   tree=ast.parse((D/name).read_text())
   self.assertFalse(any(isinstance(n,ast.Attribute)and isinstance(n.value,ast.Name)and n.value.id=='time'and n.attr=='monotonic'for n in ast.walk(tree)))
  checker=module('check-selected-transition-v5.py');self.assertIs(checker.run.__defaults__[1],checker.shared_clock)
 def test_same_fake_clock_injection_preserved(self):
  checker=module('check-selected-transition-v5.py')
  self.assertIn('clock',checker.run.__code__.co_varnames)
if __name__=='__main__':unittest.main()
