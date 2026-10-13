import importlib.util,pathlib,json,unittest
P=pathlib.Path(__file__).resolve().parent;spec=importlib.util.spec_from_file_location('w',P/'customer-cloud-rekey-observe-v4.py');w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
raw=json.loads((P/'.runtime/rekey-vici-terminal-fixture-20261008-1/vici.json').read_text())
class Reply(unittest.TestCase):
 def test_actual_four_events(self):self.assertEqual(len(w.parse_vici(raw)),4)
 def test_bad_terminal(self):
  for value in [raw+' list-sas reply {}',raw.replace('list-sas reply {}','list-sas reply {error=foreign}'),raw.replace('list-sas reply {}','list-sas reply {'), 'list-sas reply {} '+raw,raw+' extra',raw.replace('list-sas reply {}','list-sas reply {{}}')]:
   with self.subTest(value=value[-45:]),self.assertRaises(AssertionError):w.parse_vici(value)
 def test_actual_tunnel_bound_child(self):
  events=w.parse_vici(raw);name='tnx-ipsec-925354ec-09c5-4cf4-bd0b-c8754d4b6a0f-d2-c1-s1';parent=next(x[name]for x in events if name in x);c=next(iter(parent['child-sas'].values()))
  pin={'name':name,'local':'172.30.88.2','remote':'51.20.220.141','unique_id':int(c['uniqueid']),'reqid':int(c['reqid']),'spi_in':c['spi-in'],'spi_out':c['spi-out'],'ifid':int(c['if-id-in'],16)}
  self.assertEqual(w.selected_child(raw,pin),c)
  for field in ['name','remote','reqid','spi_in','ifid']:
   q=dict(pin);q[field]=1 if field in ['reqid','ifid']else 'foreign'
   with self.subTest(field=field),self.assertRaises((AssertionError,KeyError)):w.selected_child(raw,q)
unittest.main()
