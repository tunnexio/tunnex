"""Offline source-input and complete observation comparison; no host/runtime actions."""
import json,pathlib,hashlib,subprocess,types,copy
D=pathlib.Path(__file__).parent
BASELINE_SHA='757a1be9d117ba85239d945ce0ab6b0928403953c0dfba45401fb7d739ce9784'
CURRENT_SHA='1c7dc7ed92f94012059ac677acd07da931d8d26a5112dcf79e11691d53648c1d'
SCHEMA='ac14e9cd861b3260b0c30599fe02b8d4cc9730a5b0e1967cb9e0bb1e0382639e'
HA='80c20667-8d84-4dd8-8e51-ae4a10445cbb';SITE='01a12500-95ae-7728-b901-54f20df98cc1'
TUPLES=[('01a12784-6f38-7613-82e5-6f607684662f','01a12783-f51b-787b-87ec-1ab7a74da30d','tcp',8080),('01a12784-ddad-78d6-bdd6-49595d90c531','01a12784-a3ea-71f0-be7e-e2cca9c40002','udp',9000)]
def verify_inputs(b):
 if b['configurations'][HA]['configuration']['local_prefixes']!=['10.70.0.0/24']:raise ValueError('approved local prefix')
 for policy,resource,protocol,port in TUPLES:
  ps=[x for x in b['policies']if x['id']==policy];rs=[x for x in b['resources']if x['id']==resource]
  if len(ps)!=1 or len(rs)!=1:raise ValueError('unique normal source input')
  p,r=ps[0],rs[0]
  if p['enabled']is not True or p['expires_at']is not None or p['src_kind']!='site' or p['src_site_id']!=SITE or p['dst_kind']!='resource' or p['dst_resource_id']!=resource or any(p.get(k)is not None for k in ('src_cidr','src_device_id','dst_fqdn_resource_id','dst_group_id','dst_site_id')):raise ValueError('normal exact enabled policy')
  if r['cidr']!='10.80.0.10/32' or r['protocol']!=protocol or type(r['port_low'])is not int or type(r['port_high'])is not int or r['port_low']!=port or r['port_high']!=port:raise ValueError('exact normal resource')
def expected_rules():
 def match(left,right):return {'match':{'op':'==','left':left,'right':right}}
 out=[]
 for policy,resource,protocol,port in TUPLES:
  out.append({'rule':{'family':'ip','table':'tunnex','chain':'forward','expr':[match({'payload':{'protocol':'ip','field':'saddr'}},{'prefix':{'addr':'10.70.0.0','len':24}}),match({'ct':{'key':'ip daddr','dir':'original'}},'10.80.0.10'),match({'meta':{'key':'l4proto'}},protocol),match({'ct':{'key':'proto-dst','dir':'original'}},port),{'counter':{'packets':0,'bytes':0}},{'log':{'group':100,'prefix':'tnx:'+policy+' '}},{'accept':None}]}})
 return out

def main():
 baseline=pathlib.Path('/private/tmp/gcp-isolated-cas-actual-prepare-20261011-v1/baseline.json');current=pathlib.Path('/private/tmp/gcp-post-cas-baseline-20261011-v1/baseline.json')
 for p,h in ((baseline,BASELINE_SHA),(current,CURRENT_SHA)):
  raw=p.read_bytes()
  if hashlib.sha256(raw).hexdigest()!=h:raise ValueError('actual API baseline drift')
  verify_inputs(json.loads(raw))
 source=subprocess.check_output(['git','-C','/Users/pawangupta/tunnex','show','9c3ab006c13b72285f43baed1805da1af273ffa7:apps/node/internal/egress/egress_linux.go'])
 if hashlib.sha256(source).hexdigest()!='52f892663107fe0bcc881a3f34dec662f0b8a6e68a1175d09c51d06ca1a39d7e':raise ValueError('frozen renderer drift')
 n={'__name__':'offline'};exec(compile((D/'capture-post-lifecycle-schema-unqualified-v1.remote.py').read_text(),'offline','exec'),n)
 actual=pathlib.Path('/private/tmp/gcp-classic-psk-lifecycle-actual-20261011-v1/061-post-lifecycle-unqualified-schema.jsonl')
 records=[json.loads(x)for x in actual.read_text().splitlines()];rows=[r['observation']for r in records if r.get('completed')is True]
 if len(rows)!=1 or rows[0]['source_schema_verified']is not False:raise ValueError('unqualified original observation required')
 oldpath=pathlib.Path('/private/tmp/gcp-cloud-replacement-9c3ab006-20261011/actual-before-nft.json')
 old=n['shape'](n['wg_objects'](n['normalized'](oldpath.read_text())));new=n['shape'](rows[0]['wg_whole_objects']);remaining=copy.deepcopy(new)
 for rule in expected_rules():
  if remaining.count(rule)!=1:raise ValueError('exact source-derived added rule')
  remaining.remove(rule)
 if len(old)!=22 or len(new)!=24 or remaining!=old or n['digest'](new)!=SCHEMA:raise ValueError('complete source shape mismatch')
 proof={'source_commit':'9c3ab006c13b72285f43baed1805da1af273ffa7','egress_source_sha256':hashlib.sha256(source).hexdigest(),'renderer_anchors':['rulesetWith:715-813','forwardRules:852-925','allowMatchFamily:1004-1045','renderAllowLoggedFamily:1070-1098'],'baseline_sha256':BASELINE_SHA,'current_normal_baseline_sha256':CURRENT_SHA,'actual_unqualified_capture_sha256':hashlib.sha256(actual.read_bytes()).hexdigest(),'old_nft_sha256':hashlib.sha256(oldpath.read_bytes()).hexdigest(),'whole_schema_sha256':SCHEMA,'whole_runtime_wg_sha256':rows[0]['wg_objects_sha256'],'old_objects':22,'new_objects':24,'only_added_rules':expected_rules(),'other22_order_and_semantics_exact':True,'normal_input_verified':True,'scope':'offline source qualification of complete WG schema only; no runtime/authority/teardown acceptance; raw handles retained in separate runtime digest'}
 print(json.dumps(proof,sort_keys=True))
if __name__=='__main__':main()
