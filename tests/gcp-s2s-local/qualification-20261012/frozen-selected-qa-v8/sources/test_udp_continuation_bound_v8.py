"""ROOT-only pure saved-evidence admission negatives; no transport."""
import pathlib,types,unittest,json,hashlib
D=pathlib.Path(__file__).parent
p=D/'run-selected-udp-continuation.bound-v8.py';m=types.ModuleType('candidate');m.__file__=str(p);exec(compile(p.read_text(),str(p),'exec'),m.__dict__)
class Tests(unittest.TestCase):
 def test_exact_actual_tcp_udp_only(self):
  reader=types.SimpleNamespace(private=lambda p:pathlib.Path(p).read_bytes())
  self.assertTrue(m.exact_v5_tcp_cleanup('udp',m.KNOWN_TCP_ROOT/'result.json',m.KNOWN_TCP_PINS['result.json'],m.KNOWN_TCP_ROOT/'096-api-retain-resource/state.json',reader))
  with self.assertRaises(ValueError):m.exact_v5_tcp_cleanup('tcp',m.KNOWN_TCP_ROOT/'result.json',m.KNOWN_TCP_PINS['result.json'],m.KNOWN_TCP_ROOT/'096-api-retain-resource/state.json',reader)
 def test_unknown_path_hash_state_reject(self):
  reader=types.SimpleNamespace(private=lambda p:pathlib.Path(p).read_bytes())
  args=['udp',m.KNOWN_TCP_ROOT/'result.json',m.KNOWN_TCP_PINS['result.json'],m.KNOWN_TCP_ROOT/'096-api-retain-resource/state.json',reader]
  for index,value in ((1,pathlib.Path('/unknown/result.json')),(2,'0'*64),(3,pathlib.Path('/unknown/state.json'))):
   a=list(args);a[index]=value
   with self.assertRaises(ValueError):m.exact_v5_tcp_cleanup(*a)
 def test_mutated_source_gateway_state_or_cleanup_refuse(self):
  for rel,key,value in [('result.json','source_sha256','unknown'),('result.json','cleanup_errors',['failure']),('094-native-final/proof/result.json','container','unknown'),('096-api-retain-resource/state.json','grants',{'unknown':{}})]:
   def read(p):
    raw=pathlib.Path(p).read_bytes()
    if p==m.KNOWN_TCP_ROOT/rel:
     x=json.loads(raw);x[key]=value;return json.dumps(x).encode()
    return raw
   with self.assertRaises(ValueError):m.exact_v5_tcp_cleanup('udp',m.KNOWN_TCP_ROOT/'result.json',m.KNOWN_TCP_PINS['result.json'],m.KNOWN_TCP_ROOT/'096-api-retain-resource/state.json',types.SimpleNamespace(private=read))
if __name__=='__main__':unittest.main()
