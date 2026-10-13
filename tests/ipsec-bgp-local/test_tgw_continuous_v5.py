import ast,json,os,pathlib,subprocess,tempfile,unittest
p=pathlib.Path(__file__).with_name('tgw-continuous-v5.py')
class Continuous(unittest.TestCase):
 def code(self):
  tree=ast.parse(p.read_text());return [n.value.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='client_code'for t in n.targets)and isinstance(n.value,ast.Constant)][-1]
 def test_real_client_loop_fresh_nonce_and_ocl_record(self):
  with tempfile.TemporaryDirectory()as folder:
   d=pathlib.Path(folder);curl=d/'curl';curl.write_text('#!/usr/bin/env python3\nimport sys,json,hashlib\nn=sys.argv[-1].split("nonce=")[1];print(json.dumps({"nonce":n,"sha256":hashlib.sha256(n.encode()).hexdigest(),"target":"10.86.1.10"}),end="");print("HTTP=200")\n');curl.chmod(0o700);out=d/'rows';code=self.code().replace('os.umask(0o077);','time.sleep=lambda _:None;os.umask(0o077);');args=['python3','-c',code,str(out),'15'];env={**os.environ,'PATH':folder+':'+os.environ['PATH']};result=subprocess.run(args,env=env,capture_output=True,timeout=15);self.assertEqual(result.returncode,0,result.stderr);rows=[json.loads(x)for x in out.read_text().splitlines()];self.assertEqual(len(rows),15);self.assertEqual(len({x['nonce']for x in rows}),15);self.assertTrue(all(x['exit']==0 and x['stdout'].endswith('HTTP=200\n')for x in rows));again=subprocess.run(args,env=env,capture_output=True,timeout=15);self.assertNotEqual(again.returncode,0);self.assertEqual(len(out.read_text().splitlines()),15)
 def test_boundaries_and_no_normal_intent_mutation(self):
  s=p.read_text();self.assertIn('15<=a.count<=300',s);self.assertIn("'--connect-timeout','1','--max-time','2'",s);self.assertIn('O_EXCL',s);self.assertIn("save(stem+'-target-log-raw.json',log)",s);self.assertNotIn('authorize-security-group',s);self.assertNotIn('/policies',s)
if __name__=='__main__':unittest.main()
