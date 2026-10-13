import ast,hashlib,ipaddress,json,pathlib,re,unittest
source=pathlib.Path(__file__).with_name('normal-delete-bgp-proof.py');tree=ast.parse(source.read_text());ns={'hashlib':hashlib,'json':json,'ipaddress':ipaddress,'re':re};exec(compile(ast.Module(body=[x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name in ['clean_bgp_entry','retained_guard','ownroute','prefix','parse_xfrm_inventory','automatic_owned_address_route']],type_ignores=[]),str(source),'exec'),ns)
class DeleteProof(unittest.TestCase):
 def test_empty_xfrm_format_and_nonempty_malformed_refusal(self):
  self.assertEqual(ns['parse_xfrm_inventory']('','state'),[]);self.assertEqual(ns['parse_xfrm_inventory']('[]','policy'),[]);self.assertEqual(ns['parse_xfrm_inventory']('[{"if_id":123}]','policy'),[{'if_id':123}])
  for raw in [' ', 'garbage', '{}', 'null', '[123]', '[{}]']:
   with self.assertRaises((AssertionError,ValueError)):ns['parse_xfrm_inventory'](raw,'policy')
 def test_actual_socket_policy_text_only(self):
  raw='src ::/0 dst ::/0 \n\tsocket in priority 0 \nsrc 0.0.0.0/0 dst 0.0.0.0/0 \n\tsocket out priority 0 \n'
  self.assertEqual(len(ns['parse_xfrm_inventory'](raw,'policy')),2)
  for bad in [raw+'if_id 0x14\n',raw.replace('socket in','dir in'),raw.replace('priority 0','priority 1'),raw.replace('dst ::/0','dst 0.0.0.0/0')]:
   with self.assertRaises((AssertionError,ValueError)):ns['parse_xfrm_inventory'](bad,'policy')
  self.assertEqual(ns['parse_xfrm_inventory']('[{"if_id":"0x14"}]','policy')[0]['if_id'],20)
 def test_only_exact_owned_automatic_routes(self):
  row={'dev':'tx6cc5a86d25d0','dst':'169.254.84.1','type':'local','scope':'host','protocol':'kernel','table':'local','prefsrc':'169.254.84.1','flags':[]};self.assertTrue(ns['automatic_owned_address_route'](row))
  for change in [{'dev':'foreign'},{'dst':'169.254.84.2'},{'scope':'link'},{'prefsrc':'169.254.84.5'},{'metric':1},{'protocol':'static'}]:self.assertFalse(ns['automatic_owned_address_route']({**row,**change}))
 def test_known_pre_bgp_history_only(self):
  e={'DeliveryID':'39be0492-aac4-4e74-be0c-749af8f2c0ed','Phase':'retained_refusal','ContractVersion':3};ns['clean_bgp_entry'](e)
  for change in [{'DeliveryID':'foreign'},{'BGPProcess':{'Stage':'ready'}},{'BGPRoutes':{'Stage':'completed','Owned':[1],'Target':[]}}]:
   with self.assertRaises(AssertionError):ns['clean_bgp_entry']({**e,**change})
 def test_exact_peer_tuple_excluded_foreign_not_adopted(self):
  route={'dst':'169.254.84.2','dev':'tx6cc5a86d25d0','protocol':'242','metric':50001};self.assertTrue(ns['ownroute'](route))
  for change in [{'dev':'foreign'},{'metric':50002},{'gateway':'10.1.1.1'},{'protocol':'static'}]:self.assertFalse(ns['ownroute']({**route,**change}))
 def test_guard_actual_native_fixture(self):
  import copy
  raw=json.loads(pathlib.Path(__file__).with_name('testdata').joinpath('native-limit-retained-guard.json').read_text());self.assertEqual(len(ns['retained_guard'](raw)['verified_drop_rules']),12)
  # Unrelated CT string matching must neither crash nor prove prefix denial.
  mixed=copy.deepcopy(raw);mixed['nftables'].append({'rule':{'table':'tunnex_ipsec','chain':'postnat_guard','expr':[{'match':{'left':{'ct':{'key':'status'}},'right':'dnat','op':'in'}},{'drop':None}]}});ns['retained_guard'](mixed)
  missing=copy.deepcopy(raw);missing['nftables']=[x for x in missing['nftables']if not('rule'in x and x['rule']['chain']=='input_guard')]
  with self.assertRaises(AssertionError):ns['retained_guard'](missing)
  wrong=copy.deepcopy(raw);next(x['chain']for x in wrong['nftables']if x.get('chain',{}).get('name')=='postrouting_guard')['prio']=300
  with self.assertRaises(AssertionError):ns['retained_guard'](wrong)
  members=copy.deepcopy(raw);next(x['set']for x in members['nftables']if 'set'in x)['elem']=[1]
  with self.assertRaises(AssertionError):ns['retained_guard'](members)
if __name__=='__main__':unittest.main()
