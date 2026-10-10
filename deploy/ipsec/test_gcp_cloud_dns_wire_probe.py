import importlib.util,pathlib,struct,unittest
s=importlib.util.spec_from_file_location('p',pathlib.Path(__file__).with_name('gcp-cloud-dns-wire-probe.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
class Tests(unittest.TestCase):
 def test_actual_tc_and_question_identity(self):
  name='large.ha.gcp.s2s-qa.tunnex.app.';wire=struct.pack('!6H',42,0x8300,1,0,0,0)+p.question(name)
  self.assertTrue(p.response(wire,42,name,False)['tc'])
  with self.assertRaises(ValueError):p.response(wire,43,name,False)
  with self.assertRaises(ValueError):p.response(wire,42,'app.'+name,False)
  with self.assertRaises(ValueError):p.response(wire,42,name,True)
 def test_complete_a_and_no_trailing_or_pointer_loop(self):
  name='app.classic.gcp.s2s-qa.tunnex.app.';wire=struct.pack('!6H',7,0x8100,1,1,0,0)+p.question(name)+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+bytes([10,81,0,10])
  self.assertEqual(p.response(wire,7,name,True)['a'],[{'owner':name,'address':'10.81.0.10'}])
  with self.assertRaises(ValueError):p.response(wire+b'\0',7,name,True)
  with self.assertRaises(ValueError):p.decode_name(b'\xc0\x00',0)
if __name__=='__main__':unittest.main()
