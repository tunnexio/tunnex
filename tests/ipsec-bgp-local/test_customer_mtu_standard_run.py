import copy,importlib.util,json,pathlib,tempfile,unittest
from unittest.mock import patch
p=pathlib.Path(__file__).with_name('customer-mtu-standard-run.py');spec=importlib.util.spec_from_file_location('run',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Boundaries(unittest.TestCase):
 def native(self):
  # Accepted actual NFT wire fixture; only translate existing application port
  # and source policy into the proposed normal client32/8081 configuration.
  root=p.parent/'.runtime/customer-wire-b85-peer1-bbd888c7cc97/customer-post-release-b85-peer1-standby-fault-v2.json';v=json.loads(root.read_text())['nft']
  for x in v['nftables']:
   if 'rule'not in x:continue
   r=x['rule'];expr=r['expr']
   if r['chain']=='forward_guard'and any(e.get('match',{}).get('right')==8080 for e in expr):
    for e in expr:
     match=e.get('match',{})
     if match.get('right')==8080:match['right']=8081
     if match.get('right')=={'prefix':{'addr':'10.84.2.0','len':24}}:match['right']='10.84.2.10'
  return v
 def test_exact_native_schema_accepts_narrow_application(self):self.assertEqual(m.actual_authority(self.native()),['tx199f74b5ef5c'])
 def test_no_generic_lease_name_fallback(self):
  v=self.native()
  for x in v['nftables']:
   if 'set'in x:x['set']['name']='lease'
  with self.assertRaises((AssertionError,KeyError)):m.actual_authority(v)
 def test_expired_foreign_reqid_and_wider_source_refused(self):
  for fault in ['expire','reqid','source']:
   v=self.native()
   for x in v['nftables']:
    if 'set'in x and 'lease'in x['set']['name']:
     if fault=='expire':x['set']['elem'][0]['elem']['expires']=0
     if fault=='reqid'and x['set']['name'].startswith('sa_lease'):x['set']['elem'][0]['elem']['val']=1
    if fault=='source'and 'rule'in x:
     for e in x['rule']['expr']:
      if e.get('match',{}).get('right')=='10.84.2.10':e['match']['right']={'prefix':{'addr':'10.84.2.0','len':24}}
   with self.assertRaises((AssertionError,KeyError)):m.actual_authority(v)
 def test_foreign_rules_and_sg_order_canonical_only(self):
  a={'SecurityGroupRules':[{'SecurityGroupRuleId':'b','CidrIpv4':'one'},{'SecurityGroupRuleId':'a','CidrIpv4':'two'}]};b=copy.deepcopy(a);b['SecurityGroupRules'].reverse();self.assertEqual(m.canonical_sg(a),m.canonical_sg(b));b['SecurityGroupRules'][0]['CidrIpv4']='foreign';self.assertNotEqual(m.canonical_sg(a),m.canonical_sg(b))
 def test_firewall_order_is_semantically_preserved(self):
  one='-A DOCKER-USER -s 10.84.2.10/32 -j ACCEPT\n-A DOCKER-USER -s 10.84.2.10/32 -j DROP\n';two='\n'.join(reversed(one.splitlines()))+'\n';self.assertNotEqual(m.canonical_rules(one),m.canonical_rules(two))
 def test_unknown_mutation_intent_blocks_replay(self):
  with tempfile.TemporaryDirectory()as t:
   m.run=pathlib.Path(t);m.identity=lambda:{'fixed':True};m.call=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('unknown result'))
   with self.assertRaises(RuntimeError):m.mutation('operation','gateway','exact')
   with self.assertRaises(FileExistsError):m.mutation('operation','gateway','exact')
 def test_denial_requires_listener_still_alive_after_probe(self):
  events=[];state={'calls':0}
  class Child:
   returncode=124
   def poll(self):return None
   def terminate(self):events.append('terminate')
   def communicate(self,timeout):return ('','')
  def checked(endpoint,command,*args):
   if 'curl'in command:return {'stdout':'HTTP=200','exit':0}
   if 'ss -lntp'in command:
    state['calls']+=1;return {'stdout':m.TARGET+':8081 pid=12'if state['calls']==1 else '', 'exit':0}
   raise AssertionError(command)
  with tempfile.TemporaryDirectory()as directory:
   m.run=pathlib.Path(directory)
   with patch.object(m,'identity',return_value={'fixed':True}),patch.object(m,'native_snapshot',side_effect=lambda:events.append('snapshot')or{}),patch.object(m,'checked',side_effect=checked),patch.object(m,'listener_identity',return_value={'pid':12,'startticks':'1'}),patch.object(m,'listener_after',return_value={'original_process_absent':False}),patch.object(m,'call',return_value={'stdout':'__probe_exit:1','exit':0}),patch.object(m.subprocess,'Popen',side_effect=lambda *a,**k:events.append('spawn')or Child()):
    with self.assertRaises(AssertionError):m.verify_denied('/owned')
   self.assertLess(events.index('snapshot'),events.index('spawn'));self.assertFalse((m.run/'withdraw-deny-result.json').exists());self.assertTrue((m.run/'withdraw-deny-listener-pending.json').exists())
 def test_standard_ssh_only_and_exact_tuple(self):
  for e in ['gateway','client','target','bastion']:
   argv=m.ssh(e,'true');self.assertEqual(argv[0],'ssh');self.assertIn('ubuntu@16.170.207.192',argv)
  for r in m.hostrules('a'*64):self.assertIn('8081',r);self.assertIn('10.84.2.10/32',r);self.assertIn('10.85.1.10/32',r)
if __name__=='__main__':unittest.main()
