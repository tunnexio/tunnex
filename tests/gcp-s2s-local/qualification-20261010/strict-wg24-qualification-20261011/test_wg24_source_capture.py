import pathlib,json,types,copy,unittest
from unittest import mock
D=pathlib.Path(__file__).parent
n={ '__name__':'fixture'};exec(compile((D/'capture-post-lifecycle-cutover-wg24-v1.remote.py').read_text(),'capture','exec'),n)
proof={ '__name__':'fixture','__file__':str(D/'verify-wg24-source-proof.py')};exec(compile((D/'verify-wg24-source-proof.py').read_text(),'proof','exec'),proof)
class WG24(unittest.TestCase):
 def test_actual24_and_unknownrefusal(self):
  rec=pathlib.Path('/private/tmp/gcp-classic-psk-lifecycle-actual-20261011-v1/061-post-lifecycle-unqualified-schema.jsonl')
  actual=next(json.loads(x)['observation']for x in rec.read_text().splitlines()if json.loads(x).get('completed')is True)
  def check(raw):
   old={k:n[k]for k in('identity','journal_projection','observational_topology','execC')}
   n.update(identity=lambda:actual['identity'],journal_projection=lambda:actual['journal'],observational_topology=lambda:actual['topology'],execC=lambda *args:'7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f nft'if args[0]=='sha256sum'else json.dumps(raw))
   try:return n['collect']()
   finally:n.update(old)
  good=check(actual['full_nft']);self.assertTrue(good['source_schema_verified']);self.assertEqual(good['wg_objects_sha256'],actual['wg_objects_sha256'])
  bad=copy.deepcopy(actual['full_nft']);bad['nftables'].append({'rule':{'family':'ip','table':'tunnex','chain':'forward','expr':[{'accept':None}]}})
  with self.assertRaisesRegex(ValueError,'schema unproved'):check(bad)
 def test_changed_normal_authority_refuses_offline_proof(self):
  baseline=json.loads(pathlib.Path('/private/tmp/gcp-isolated-cas-actual-prepare-20261011-v1/baseline.json').read_text())
  proof['verify_inputs'](baseline)
  for mode in ('disabled','wider_resource'):
   b=copy.deepcopy(baseline)
   if mode=='disabled':next(r for r in b['policies']if r['id']==proof['TUPLES'][0][0])['enabled']=False
   else:next(r for r in b['resources']if r['id']==proof['TUPLES'][0][1])['cidr']='10.80.0.0/24'
   with self.assertRaises(ValueError):proof['verify_inputs'](b)
if __name__=='__main__':unittest.main()
