import ast,copy,importlib.util,pathlib,unittest
path=pathlib.Path(__file__).with_name('customer-static-central-linux-v2.py');spec=importlib.util.spec_from_file_location('fixture',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ProofBoundaries(unittest.TestCase):
 def rows(self):
  # Full typed fixtures correspond to the independently read central host rows.
  node=next(x for x in ast.parse(path.read_text()).body if isinstance(x,ast.FunctionDef)and x.name=='secondary_routes')
  return ast.literal_eval(node.body[0].value)
 def test_exact_routes_only(self):
  rows=self.rows();m.secondary_routes(rows)
  for field,value in [('metric',201),('gateway','10.87.1.1'),('flags',['onlink','dead']),('protocol','boot'),('unknown',True)]:
   bad=copy.deepcopy(rows);bad[2][field]=value
   with self.assertRaises(AssertionError):m.secondary_routes(bad)
  with self.assertRaises(AssertionError):m.secondary_routes(rows+rows[:1])
  with self.assertRaises(AssertionError):m.secondary_routes(rows+[{'dev':'ens5','table':'101','dst':'10.99.0.0/16'}])
 def test_listener_pid_inode_and_exact_address(self):
  header='sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
  row='0: 0A01570A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1234\n'
  self.assertFalse(m.listener_owned(header,'10.87.1.10',{'1234'}))
  self.assertTrue(m.listener_owned(header+row,'10.87.1.10',{'1234'}))
  for bad,inodes in [(row,{'foreign'}),(row.replace('0A01570A','00000000'),{'1234'}),(row.replace(' 0A ',' 01 '),{'1234'}),(row+row,{'1234'})]:self.assertFalse(m.listener_owned(header+bad,'10.87.1.10',inodes))
 def test_profile_exact_match_no_wildcard(self):
  self.assertIn('PermanentMACAddress=02:ff:da:42:4f:65\nName=ens6',m.NETWORK_PROFILE)
  self.assertNotIn('*',m.NETWORK_PROFILE+m.LINK_PROFILE)
  self.assertIn('From=10.87.2.10\nTable=101',m.NETWORK_PROFILE)
if __name__=='__main__':unittest.main()
