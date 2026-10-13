import ast,os,subprocess,hashlib,copy,importlib.util,json,pathlib,tempfile,unittest
from unittest.mock import patch
p=pathlib.Path(__file__).with_name('customer-mtu-standard-stream-v7.py');spec=importlib.util.spec_from_file_location('run',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
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
 def test_no_mutation_paths_and_listener_bounds(self):
  source=p.read_text();self.assertNotIn('def mutation(',source);self.assertNotIn('def normal_action(',source);self.assertIn('timeout -k 3 300 nc',source);self.assertIn('timeout -k 3 270 nc',source)
  self.assertLess(source.index("before=native_snapshot()"),source.index("sp=spawn"));self.assertLess(source.index("hp=spawn"),source.index("sp=spawn"))
 def test_header_timeout_preserves_raw(self):
  class Child:
   def communicate(self,timeout):raise m.subprocess.TimeoutExpired('header',timeout,output=b'header partial',stderr=b'diagnostic')
  value=m.collect(Child(),1);self.assertTrue(value['timeout']);self.assertEqual(value['stdout'],'header partial');self.assertEqual(value['stderr'],'diagnostic')
 def test_listener_missing_or_recycled_rejected(self):
  for raw in ['', 'LISTEN 10.85.1.10:8081 pid=1353']:
   with self.assertRaises(AssertionError):m.parse_listener(raw)
 def test_standard_ssh_only_and_exact_tuple(self):
  for e in ['gateway','client','target','bastion']:
   argv=m.ssh(e,'true');self.assertEqual(argv[0],'ssh');self.assertIn('ubuntu@16.170.207.192',argv)
  for r in m.hostrules('a'*64):self.assertIn('8081',r);self.assertIn('10.84.2.10/32',r);self.assertIn('10.85.1.10/32',r)
 def test_transport_timeout_preserves_partial_raw_before_failure(self):
  with tempfile.TemporaryDirectory()as directory:
   m.run=pathlib.Path(directory)
   error=m.subprocess.TimeoutExpired('ssh',1,output=b'partial stdout',stderr=b'partial stderr')
   with patch.object(m.subprocess,'run',side_effect=error):value=m.call('client','read-only',1)
   self.assertTrue(value['timeout']);self.assertEqual(value['stdout'],'partial stdout');receipts=list(m.run.glob('transport-timeout-*.json'));self.assertEqual(len(receipts),1);self.assertEqual(json.loads(receipts[0].read_text())['stderr'],'partial stderr')
 def test_listener_requires_exact_argv(self):
  raw='State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 1 10.85.1.10:8081 0.0.0.0:* users:(("nc",pid=123,fd=3))\n/usr/bin/nc.openbsd\n123 (nc) S '+ ' '.join(['0']*18+['100'])+'\nnc\x00-N\x00-l\x0010.85.1.10\x008081\x00'
  self.assertEqual(m.parse_listener(raw)['startticks'],'100')
  with self.assertRaises(AssertionError):m.parse_listener(raw.replace('nc\x00-N','nc\x00-X'))
 def test_actual_fifo_producer_command_records_both_exits(self):
  tree=ast.parse(p.read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');assignment=next(n for n in ast.walk(main)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='body'for t in n.targets))
  with tempfile.TemporaryDirectory()as folder:
   directory=pathlib.Path(folder)/'attempt';directory.mkdir();block=b'known-block'*6000;block=block[:65536].ljust(65536,b'x');(directory/'send.bin').write_bytes(block)
   tools=pathlib.Path(folder)/'tools';tools.mkdir()
   for name,code in [('nc','#!/bin/sh\ncat\n'),('sleep','#!/bin/sh\nexit 0\n'),('timeout','#!/bin/sh\nshift 3\nexec \"$@\"\n')]:
    f=tools/name;f.write_text(code);f.chmod(0o700)
   command=eval(compile(ast.Expression(assignment.value),str(p),'eval'),{'directory':str(directory),'CLIENT':m.CLIENT,'TARGET':m.TARGET})
   result=subprocess.run(['sh','-c',command],capture_output=True,timeout=20,env={**os.environ,'PATH':str(tools)+':'+os.environ['PATH']});self.assertEqual(result.returncode,0,result.stderr);self.assertIn(b'nc_exit=0 producer_exit=0',result.stdout);self.assertEqual((directory/'producer-exit').read_text().strip(),'0');self.assertEqual(hashlib.sha256((directory/'client-received.bin').read_bytes()).digest(),hashlib.sha256(block*200).digest())
 def test_long_observer_drains_before_client(self):
  source=p.read_text();self.assertNotIn('stdout=subprocess.PIPE',source);self.assertLess(source.index("gp=spawn('growth'"),source.index("result=call('client'"))
  with tempfile.TemporaryDirectory()as folder:
   m.run=pathlib.Path(folder);child=m.spawn('test',['python3','-c','import sys; sys.stdout.write("x"*1000000);sys.stderr.write("y"*100000)']);result=m.collect(child,10);self.assertEqual(result['exit'],0);self.assertEqual(len(result['stdout']),1000000);self.assertEqual(len(result['stderr']),100000)
if __name__=='__main__':unittest.main()
