import json,pathlib,tempfile,unittest
from enrolled_approval import reviewed_run,selected_applied
class EnrolledReview(unittest.TestCase):
 def test_existing_run2_compatible(self):
  old={'old_container_id':'1d4c4eb40c024fcc9f6d0ed46e4f80a8e4edf613f4f21eb73f5cb2b2c7a95eb4','old_binary_path':'/binaries/tunnex-node-bgp9-cleanup-checkpoint','image':'sha256:'+'a'*64,'binary_name':'node-v2','binary_sha256':'b'*64,'cli_file':'receipt-v2','cli_sha256':'c'*64,'cli_build_receipt':'receipt-build-v2.json','cli_source_manifest_sha256':'d'*64,'prior_receipt_sha256':'77123aa847c964ca6557b292db38bc6d2619caf14341a6cc78de50fb5f5bf7a5'}
  with tempfile.TemporaryDirectory()as d:
   shared=pathlib.Path(d);run=shared/'enrolled-repeat-20261008-2';run.mkdir();(run/'approved-build.json').write_text(json.dumps(old));self.assertEqual(reviewed_run(shared,run)[2],2)
 def test_run3_requires_new_receipt_and_exact_artifacts(self):
  approval={'old_container_id':'eddbe7f90cd5684a6c51a14c4d8ccc8263ba02efed73301075bcda311e949a2a','old_binary_path':'/binaries/tunnex-node-bgp9-trusted-restoration','image':'sha256:e789c8c86054e7b2507e7f00da1c13d4498725b47fc7f8158f7f7102e5ec435e','binary_name':'tunnex-node-bgp9-selector-cleanup','binary_sha256':'a14d312802d64be51ab6c06193fd6dc4c7583b79977653ca2eac44197867100e','cli_file':'enrolled-restoration-receipt-v3','cli_sha256':'b'*64,'cli_build_receipt':'enrolled-cli-build-receipt-v3.json','cli_source_manifest_sha256':'d'*64,'prior_receipt_sha256':None}
  with tempfile.TemporaryDirectory()as d:
   shared=pathlib.Path(d);run=shared/'enrolled-repeat-20261008-3';run.mkdir();path=run/'approved-build.json';path.write_text(json.dumps(approval));self.assertEqual(reviewed_run(shared,run)[2],3)
   for k,v in [('prior_receipt_sha256','a'*64),('old_container_id','0'*64),('binary_name','tunnex-node'),('image','sha256:'+'0'*64)]:
    changed={**approval,k:v};path.write_text(json.dumps(changed))
    with self.assertRaises(AssertionError):reviewed_run(shared,run)
   with self.assertRaises(AssertionError):reviewed_run(shared,shared/'enrolled-repeat-20261008-5')
 def test_run4_exact_build_cli_and_no_prior_receipt(self):
  approval={'old_container_id':'a54f61148b1516e69981ac0d26fa34430b454d47f2961bf8879a7e91caf83a82','old_binary_path':'/binaries/tunnex-node-bgp9-selector-cleanup','image':'sha256:60910f0d0ecedf73a7a9bf069d0cc251bbfeb7496df76c31fb11681a2a01ac6f','binary_name':'tunnex-node-bgp9-max-prefix','binary_sha256':'de02a3265fabad1153fc2520fdd6193edd0994878b293727a399a55628a48528','cli_file':'enrolled-restoration-receipt-v4','cli_sha256':'1b09523025cdb4011164da880ee3b9ce5726cd3f1590a02ddd154249c22f8832','cli_build_receipt':'enrolled-cli-build-receipt-v4.json','cli_source_manifest_sha256':'80594d831dd1b4cda516e1a3435ba483b7d4ae57cebe7f5aade531f9c8bcb6f6','prior_receipt_sha256':None}
  with tempfile.TemporaryDirectory()as d:
   shared=pathlib.Path(d);run=shared/'enrolled-repeat-20261008-4';run.mkdir();path=run/'approved-build.json';path.write_text(json.dumps(approval));self.assertEqual(reviewed_run(shared,run)[2],4)
   for k,v in [('prior_receipt_sha256','a'*64),('old_container_id','0'*64),('binary_sha256','0'*64),('cli_sha256','0'*64),('image','sha256:'+'0'*64)]:
    path.write_text(json.dumps({**approval,k:v}))
    with self.assertRaises(AssertionError):reviewed_run(shared,run)
 def test_one_applied_skips_immutable_retained_history(self):
  old={'Phase':'retained_refusal','ContractVersion':3,'DeliveryID':'old'};new={'Phase':'applied','ContractVersion':3,'DeliveryID':'new'}
  self.assertIs(selected_applied([old,new]),new);self.assertEqual(old['DeliveryID'],'old')
  for entries in [[old],[new,new],[old,{**new,'Phase':'cleanup_pending'}]]:
   with self.assertRaises(AssertionError):selected_applied(entries)
if __name__=='__main__':unittest.main()
