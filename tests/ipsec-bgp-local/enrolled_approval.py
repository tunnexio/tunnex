"""Exact reviewed refresh runs; no Docker/API actions or baseline capture."""
import json,pathlib

def reviewed_run(shared,requested):
 shared=shared.resolve();rt=shared if requested is None else requested.resolve()
 allowed={shared:0,shared/'enrolled-repeat-20261008-2':2,shared/'enrolled-repeat-20261008-3':3,shared/'enrolled-repeat-20261008-4':4};assert rt in allowed,'Unreviewed refresh run'
 index=allowed[rt];approval=json.loads((rt/'approved-build.json').read_text())if index else {}
 if index:
  assert set(approval)=={'old_container_id','old_binary_path','image','binary_name','binary_sha256','cli_file','cli_sha256','cli_build_receipt','cli_source_manifest_sha256','prior_receipt_sha256'}
  if index==2:
   assert approval['old_container_id']=='1d4c4eb40c024fcc9f6d0ed46e4f80a8e4edf613f4f21eb73f5cb2b2c7a95eb4'and approval['old_binary_path']=='/binaries/tunnex-node-bgp9-cleanup-checkpoint'
   assert approval['prior_receipt_sha256']=='77123aa847c964ca6557b292db38bc6d2619caf14341a6cc78de50fb5f5bf7a5'
  elif index==3:
   assert approval['old_container_id']=='eddbe7f90cd5684a6c51a14c4d8ccc8263ba02efed73301075bcda311e949a2a'and approval['old_binary_path']=='/binaries/tunnex-node-bgp9-trusted-restoration'
   assert approval['image']=='sha256:e789c8c86054e7b2507e7f00da1c13d4498725b47fc7f8158f7f7102e5ec435e'and approval['binary_name']=='tunnex-node-bgp9-selector-cleanup'and approval['binary_sha256']=='a14d312802d64be51ab6c06193fd6dc4c7583b79977653ca2eac44197867100e'
   assert approval['prior_receipt_sha256']is None,'New delivery must have no prior canonical receipt'
  elif index==4:
   assert approval['old_container_id']=='a54f61148b1516e69981ac0d26fa34430b454d47f2961bf8879a7e91caf83a82'and approval['old_binary_path']=='/binaries/tunnex-node-bgp9-selector-cleanup'
   assert approval['image']=='sha256:60910f0d0ecedf73a7a9bf069d0cc251bbfeb7496df76c31fb11681a2a01ac6f'and approval['binary_name']=='tunnex-node-bgp9-max-prefix'and approval['binary_sha256']=='de02a3265fabad1153fc2520fdd6193edd0994878b293727a399a55628a48528'
   assert approval['cli_file']=='enrolled-restoration-receipt-v4'and approval['cli_sha256']=='1b09523025cdb4011164da880ee3b9ce5726cd3f1590a02ddd154249c22f8832'and approval['cli_build_receipt']=='enrolled-cli-build-receipt-v4.json'and approval['cli_source_manifest_sha256']=='80594d831dd1b4cda516e1a3435ba483b7d4ae57cebe7f5aade531f9c8bcb6f6'
   assert approval['prior_receipt_sha256']is None,'Fresh applied delivery canonical receipt must be absent'
  assert all(len(approval[k])==64 and all(c in '0123456789abcdef'for c in approval[k])for k in ['binary_sha256','cli_sha256','cli_source_manifest_sha256'])
  assert approval['image'].startswith('sha256:')and len(approval['image'])==71
  assert all(pathlib.Path(approval[k]).name==approval[k]for k in ['binary_name','cli_file','cli_build_receipt'])
 return rt,approval,index

def selected_applied(entries):
 active=[entry for entry in entries if entry['Phase']!='retained_refusal']
 assert len(active)==1 and active[0]['Phase']=='applied'and active[0]['ContractVersion']==3,'Exactly one applied BGP obligation required'
 return active[0]


def validate_resume(pending,result,original,current):
 assert pending=={**result,'finish_complete':False},'Pending proof changed'
 assert not result['worker_released']
 assert original['gateway_id']==result['old_container_id']
 assert current=={**original,'gateway_id':result['new_container_id']},'Topology changed after pending'
