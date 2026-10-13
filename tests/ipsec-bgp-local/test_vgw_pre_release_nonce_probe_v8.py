import ast,hashlib,json,pathlib,unittest
p=pathlib.Path(__file__).with_name('vgw-pre-release-nonce-probe-v8.py');tree=ast.parse(p.read_text());fn=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='validate_receipt_metadata');ns={'hashlib':hashlib,'json':json};exec(compile(ast.Module(body=[fn],type_ignores=[]),str(p),'exec'),ns);validate=ns[fn.name]
def sha(b):return hashlib.sha256(b).hexdigest()
class TestReceipts(unittest.TestCase):
 def fixture(self):
  owner='11111111-1111-4111-8111-111111111111';ids=['22222222-2222-4222-8222-222222222222','33333333-3333-4333-8333-333333333333'];entries=[{'DeliveryID':id,'Phase':'applied'}for id in ids];journal=json.dumps({'Payload':{'OwnerID':owner,'Entries':entries}}).encode();receipts={};pin={'owner_id':owner,'namespace':'net:[42]','expected_deliveries':ids,'journal_sha256':sha(journal),'evidence_digest':'a'*64}
  for e in entries:
   r={'Version':1,'OwnerID':owner,'DeliveryID':e['DeliveryID'],'Namespace':pin['namespace'],'EvidenceDigest':pin['evidence_digest'],'EntryDigest':sha(json.dumps(e,separators=(',',':')).encode()),'Termination':'supervisor-confirmed-runtime-stop'};receipts[e['DeliveryID']]=json.dumps(r).encode()
  bundle={'OwnerID':owner,'Namespace':pin['namespace'],'JournalSHA':sha(journal),'EvidenceDigest':pin['evidence_digest'],'Receipts':{id:sha(raw)for id,raw in receipts.items()}};raw=json.dumps(bundle).encode();pin['receipt_set_sha256']=sha(raw);return raw,journal,receipts,pin
 def test_complete(self):
  raw,j,r,p=self.fixture();self.assertEqual(len(validate(raw,j,r,p)['installed_delivery_ids']),2)
 def test_partial_tamper_foreign_stale(self):
  for kind in ['missing','tamper','namespace','journal','extra']:
   raw,j,r,p=self.fixture()
   if kind=='missing':r.pop(p['expected_deliveries'][1])
   elif kind=='tamper':r[p['expected_deliveries'][0]]=b'changed'
   elif kind=='namespace':p['namespace']='net:[99]'
   elif kind=='journal':j+=b' '
   else:r['44444444-4444-4444-8444-444444444444']=b'{}'
   with self.subTest(kind=kind),self.assertRaises(AssertionError):validate(raw,j,r,p)
 def test_source_delta(self):
  s=p.read_text();self.assertIn("['10.85.0.0/16','10.86.0.0/16']",s);self.assertIn('fd3fd0fe6b1985c18f6182286a80b24f463bae93a5fce208ea996e830db67cb6',s)
if __name__=='__main__':unittest.main()
