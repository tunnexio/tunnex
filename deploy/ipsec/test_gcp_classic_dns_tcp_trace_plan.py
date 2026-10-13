import importlib.util,pathlib,struct,unittest
s=importlib.util.spec_from_file_location('p',pathlib.Path(__file__).with_name('gcp-classic-dns-tcp-trace-plan.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
def packet(src,dst,sport,dport,flags,fragment=0):
 tcp=struct.pack('!HHII',sport,dport,100,101)+bytes([0x50,flags])+b'\0'*6;ip=bytes([0x45,0])+struct.pack('!HHH',40,1,fragment)+bytes([64,6])+b'\0\0'+bytes(src)+bytes(dst);return ip+tcp
class Tests(unittest.TestCase):
 def test_exact_syn_and_synack_offset0_only(self):
  q=packet([10,70,0,2],[10,81,0,2],46053,53,2);r=p.ipv4_tcp(q,46053);self.assertEqual((r['direction'],r['flags']),('request',2))
  a=packet([10,81,0,2],[10,70,0,2],53,46053,18);self.assertEqual(p.ipv4_tcp(a,46053)['direction'],'reply')
  self.assertIsNone(p.ipv4_tcp(q,46054));self.assertIsNone(p.ipv4_tcp(b'\0'*14+q,46053));self.assertIsNone(p.ipv4_tcp(packet([10,70,0,2],[10,81,0,2],46053,53,2,0x2000),46053))
 def test_identity_turnover_drops_or_xfrm_absence_cannot_accept(self):
  b={'cid':p.CID,'image':p.IMAGE,'source_commit':p.SOURCE_COMMIT,'boot':p.BOOT,'namespace':p.NS,'guard_revision':1};c={'stopped':True,'sockets':[{'drops':0}]}
  self.assertFalse(p.qualify(b,b,c)['causal_acceptance']);self.assertFalse(p.qualify(b,dict(b,guard_revision=2),c)['stable'])
  self.assertFalse(p.qualify(b,b,dict(c,sockets=[{'drops':1}]))['causal_acceptance'])
  with self.assertRaises(ValueError):p.qualify(b,dict(b,cid='foreign'),c)
if __name__=='__main__':unittest.main()
