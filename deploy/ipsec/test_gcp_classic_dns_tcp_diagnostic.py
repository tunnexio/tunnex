import copy,importlib.util,json,pathlib,struct,unittest
from unittest import mock
s=importlib.util.spec_from_file_location('p',pathlib.Path(__file__).with_name('gcp-classic-dns-tcp-diagnostic.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
SA='tnx-ipsec-'+p.TUNNEL+': #7, ESTABLISHED, IKEv2, a_i b_r\n  child: #9, reqid 3912688814, INSTALLED, TUNNEL, ESP:AES_CBC_256\n    in 1234abcd, 123 bytes, 2 packets\n    out abcd1234, 456 bytes, 3 packets\n'
def snapshot():return {'identity':{'cid':p.trace.CID,'image':p.trace.IMAGE,'source_commit':p.trace.SOURCE_COMMIT,'boot':p.trace.BOOT,'namespace':p.trace.NS},'pid':1,'started_at':'same','delivery_id':'same','interfaces':{'xfrm':{'name':'owned'}},'route':[{'dev':'owned'}],'native_semantic_sha256':'same','sa':p.selected_sa(SA),'guard':{'Revision':1},'leases':[{'expires':52}]}
class Tests(unittest.TestCase):
 def test_only_selected_public_sa_metadata_and_duplicates_refuse(self):
  sa=p.selected_sa(SA);self.assertEqual(sa['in'],{'spi':0x1234abcd,'bytes':123,'packets':2});self.assertEqual(sa['reqid'],3912688814)
  with self.assertRaises(ValueError):p.selected_sa(SA+SA)
  with self.assertRaises(ValueError):p.selected_sa(SA.replace('INSTALLED','INSTALLING'))
 def test_native_interface_tuple_matches_selected_reqid(self):
  native=SA.replace('in 1234abcd, 123 bytes, 2 packets','in  c586bcae (-|0xe936e4ae),      0 bytes,     0 packets').replace('out abcd1234, 456 bytes, 3 packets','out fb575aac (-|0xe936e4ae),      0 bytes,     0 packets')
  parsed=p.selected_sa(native);self.assertEqual(parsed['in']['spi'],0xc586bcae);self.assertEqual(parsed['out']['packets'],0)
  for invalid in [native.replace('0xe936e4ae','0xe936e4af'),native.replace('(-|0x','(unknown|0x'),native+'    in c586bcae (-|0xe936e4ae), 0 bytes, 0 packets\n',native.replace('(-|0xe936e4ae)','(-|0xe936e4ae) trailing')]:
   with self.assertRaises(ValueError):p.selected_sa(invalid)
 def test_counters_remaininglease_and_revision_not_identity(self):
  a=snapshot();b=copy.deepcopy(a);b['sa']['out']['packets']+=1;b['leases'][0]['expires']=48;b['guard']['Revision']=2;self.assertTrue(p.stable(a,b))
  b['sa']['out']['spi']+=1;self.assertFalse(p.stable(a,b));b=copy.deepcopy(a);b['route']=[{'dev':'foreign'}];self.assertFalse(p.stable(a,b))
  self.assertEqual(p.semantic({'counter':{'packets':1,'bytes':2},'elem':{'val':99,'expires':20},'handle':3}),p.semantic({'counter':{'packets':9,'bytes':8},'elem':{'val':99,'expires':5},'handle':8}))
 def test_exact_outer_spi_metadata_rejects_wrong_spi_or_fragment(self):
  sa=p.selected_sa(SA);udp=struct.pack('!HHHHII',4500,4500,16,0,sa['out']['spi'],5);ip=bytes([0x45,0])+struct.pack('!HHH',36,1,0)+bytes([64,17])+b'\0\0'+bytes([10,70,0,2])+bytes([34,131,214,202]);r=p.encapsulation(ip+udp,sa);self.assertEqual(r['spi'],sa['out']['spi']);self.assertNotIn('payload',r)
  self.assertIsNone(p.encapsulation(ip+udp[:-8]+struct.pack('!II',99,5),sa));self.assertIsNone(p.encapsulation(ip[:6]+b'\x20\x00'+ip[8:]+udp,sa))
 def test_tcp_connect_failure_preserves_exact_stage_without_retry(self):
  sock=mock.MagicMock();sock.getsockname.return_value=('10.70.0.2',46053);sock.connect.side_effect=TimeoutError('not emitted');records=[]
  with self.assertRaises(TimeoutError):p.tcp_case(sock,records.append)
  self.assertEqual(records[-1]['stage'],'tcp_connect');self.assertTrue(records[-1]['failed']);sock.connect.assert_called_once_with(('10.81.0.2',53));sock.sendall.assert_not_called()
 def test_tcp_total_deadline_progress_never_resets(self):
  sock=mock.MagicMock();sock.getsockname.return_value=('10.70.0.2',46053);sock.recv.side_effect=[b'\x00\x0c',b'abcd',b'efgh',b'ijkl']
  with mock.patch.object(p.time,'monotonic',side_effect=[0,0,0,1,2,3,4.1]):
   with self.assertRaises(TimeoutError):p.tcp_case(sock,lambda x:None)
  self.assertEqual(sock.recv.call_count,3)
 def test_native_rule_gate_rejects_wrongsource_or_missing_reply(self):
  def match(left,right):return {'match':{'op':'==','left':left,'right':right}}
  rules=[]
  for proto in ['tcp','udp']:
   for direction in ['output','input']:
    out=direction=='output';key='oif'if out else'iif';src,dst=(p.trace.SOURCE,p.trace.RESOLVER)if out else(p.trace.RESOLVER,p.trace.SOURCE);expr=[match({'payload':{'protocol':'ip','field':'saddr'}},src),match({'payload':{'protocol':'ip','field':'daddr'}},dst),match({'payload':{'protocol':proto,'field':'dport'if out else'sport'}},53),match({'meta':{'key':key}},'owned'),match({'meta':{'key':key}},('@lease_'if out else'@reply_lease_')+'b79d7edafafe41cfaf2c4115d4ef32c6'),match({'ct':{'key':'direction'}},'original'if out else'reply'),{'accept':None}]
    if not out:expr.insert(-1,{'match':{'op':'in','left':{'ct':{'key':'state'}},'right':'established'}})
    rules.append({'chain':direction+'_guard','expr':expr})
  self.assertTrue(p.dns_ready(rules,'owned'));self.assertFalse(p.dns_ready(rules[:-1],'owned'));wrong=copy.deepcopy(rules);wrong[0]['expr'][0]['match']['right']='10.70.0.10';self.assertFalse(p.dns_ready(wrong,'owned'))
 def test_actual_docker_revision_label_required_and_dependency_drift_refused(self):
  i={'Id':p.trace.CID,'Image':p.trace.IMAGE,'Config':{'Labels':{'org.opencontainers.image.revision':p.trace.SOURCE_COMMIT}}};self.assertEqual(p.docker_identity(i,p.trace.BOOT,p.trace.NS)['source_commit'],p.trace.SOURCE_COMMIT)
  for labels in [{},{'org.opencontainers.image.revision':'foreign'}]:
   with self.assertRaises(ValueError):p.docker_identity(dict(i,Config={'Labels':labels}),p.trace.BOOT,p.trace.NS)
  with mock.patch.object(pathlib.Path,'read_bytes',return_value=b'raise RuntimeError(\"must not execute\")'):
   with self.assertRaises(ValueError):p.module('wire','gcp-cloud-dns-wire-probe.py')
if __name__=='__main__':unittest.main()
