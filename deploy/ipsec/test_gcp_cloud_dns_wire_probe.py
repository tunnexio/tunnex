import importlib.util,json,os,pathlib,struct,tempfile,unittest
from unittest import mock
s=importlib.util.spec_from_file_location('p',pathlib.Path(__file__).with_name('gcp-cloud-dns-wire-probe.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
class Tests(unittest.TestCase):
 def test_actual_tc_and_question_identity(self):
  name='large.ha.gcp.s2s-qa.tunnex.app.';wire=struct.pack('!6H',42,0x8300,1,0,0,0)+p.question(name)
  self.assertTrue(p.response(wire,42,name,False)['tc'])
  with self.assertRaises(ValueError):p.response(wire,43,name,False)
  with self.assertRaises(ValueError):p.response(wire,42,'app.'+name,False)
  with self.assertRaises(ValueError):p.response(wire,42,name,True)
 def test_complete_a_and_no_trailing_or_pointer_loop(self):
  name='app.classic.gcp.s2s-qa.tunnex.app.';wire=struct.pack('!6H',7,0x8100,1,1,0,0)+p.question(name)+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+bytes([10,81,0,10])
  self.assertEqual(p.response(wire,7,name,True)['a'],[{'owner':name,'address':'10.81.0.10'}])
  with self.assertRaises(ValueError):p.response(wire+b'\0',7,name,True)
  with self.assertRaises(ValueError):p.decode_name(b'\xc0\x00',0)
 def test_alias_rejects_unrelated_a_owner_or_extra_cname(self):
  zone='ha.gcp.s2s-qa.tunnex.app.';valid={'rcode':0,'answer_count':2,'other_answers':[],'a':[{'owner':'app.'+zone,'address':'10.80.0.10'}],'cname':[{'owner':'alias.'+zone,'target':'app.'+zone}]}
  self.assertTrue(p.validate_answers(valid,'ha','alias'))
  wrong=dict(valid,a=[{'owner':'unrelated.'+zone,'address':'10.80.0.10'}])
  self.assertFalse(p.validate_answers(wrong,'ha','alias'))
  wrong=dict(valid,cname=valid['cname']+[{'owner':'unrelated.'+zone,'target':'app.'+zone}],answer_count=3)
  self.assertFalse(p.validate_answers(wrong,'ha','alias'))
 def test_tcp_total_deadline_refuses_dribbled_frame(self):
  sock=mock.MagicMock();sock.__enter__.return_value=sock
  sock.recv.side_effect=[b'\x00\x0c',b'abcd',b'efgh',b'ijkl']
  # Deadline4 includes connect/send and all reads; repeated progress cannot reset it.
  with mock.patch.object(p.socket,'socket',return_value=sock),mock.patch.object(p.time,'monotonic',side_effect=[0,0,0,1,2,3,4.1]):
   with self.assertRaises(TimeoutError):p.tcp_query('10.80.0.2',b'query')
  self.assertEqual(sock.recv.call_count,3)
  values=[x.args[0]for x in sock.settimeout.call_args_list]
  self.assertEqual(values,[4,4,3,2,1])
 def test_tc100_requires_actual_udp_tc_then_exact_tcp100(self):
  name='tc-large.classic.gcp.s2s-qa.tunnex.app.';q=p.question(name);answers=b''.join(b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+bytes([10,81,0,n])for n in range(100,200));full=struct.pack('!6H',42,0x8100,1,100,0,0)+q+answers;truncated=struct.pack('!6H',42,0x8300,1,0,0,0)+q
  sock=mock.MagicMock();sock.__enter__.return_value=sock;sock.recvfrom.return_value=(truncated,('10.81.0.2',53))
  with mock.patch.object(p.socket,'socket',return_value=sock),mock.patch.object(p.secrets,'randbelow',return_value=42),mock.patch.object(p,'tcp_query',return_value=full)as tcp:
   r=p.probe('classic','tc-large');self.assertTrue(r['accepted']);self.assertTrue(r['tcp_fallback_used']);tcp.assert_called_once();self.assertEqual(r['full']['answer_count'],100)
  sock.recvfrom.return_value=(full,('10.81.0.2',53))
  with mock.patch.object(p.socket,'socket',return_value=sock),mock.patch.object(p.secrets,'randbelow',return_value=42),mock.patch.object(p,'tcp_query')as tcp:
   self.assertFalse(p.probe('classic','tc-large')['accepted']);tcp.assert_not_called()
  with self.assertRaises(ValueError):p.probe('ha','tc-large')
 def test_udp_tc_header_preserved_before_tcp_timeout(self):
  name='tc-large.classic.gcp.s2s-qa.tunnex.app.';sock=mock.MagicMock();sock.__enter__.return_value=sock;sock.recvfrom.return_value=(struct.pack('!6H',42,0x8300,1,0,0,0)+p.question(name),('10.81.0.2',53));progress=[]
  def failed_tcp(resolver,wire,observe):observe('tcp_connect');raise TimeoutError('not logged')
  with mock.patch.object(p.socket,'socket',return_value=sock),mock.patch.object(p.secrets,'randbelow',return_value=42),mock.patch.object(p,'tcp_query',side_effect=failed_tcp):
   with self.assertRaises(TimeoutError):p.probe('classic','tc-large',progress.append)
  self.assertTrue(progress[-1]['udp']['tc']);self.assertEqual(progress[-1]['udp']['id'],42);self.assertEqual(progress[-1]['stage'],'tcp_connect');self.assertEqual(progress[-1]['error_type'],'TimeoutError')
 def test_direct_tcp_app_never_issues_udp(self):
  name='app.classic.gcp.s2s-qa.tunnex.app.';wire=struct.pack('!6H',42,0x8100,1,1,0,0)+p.question(name)+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+bytes([10,81,0,10])
  with mock.patch.object(p.socket,'socket')as udp,mock.patch.object(p.secrets,'randbelow',return_value=42),mock.patch.object(p,'tcp_query',return_value=wire)as tcp:
   r=p.probe('classic','tcp-app');self.assertTrue(r['accepted']);self.assertTrue(r['tcp_direct_used']);self.assertIsNone(r['udp']);udp.assert_not_called();tcp.assert_called_once()
 def test_partial_stage_fsynced_and_final_failure_preserved(self):
  with tempfile.TemporaryDirectory()as directory:
   os.chmod(directory,0o700);receipt=pathlib.Path(directory)/'receipt.json'
   def fail(profile,label,record):
    record({'stage':'tcp_read_length','udp':{'tc':True,'id':42}});saved=json.loads(receipt.read_text());self.assertTrue(saved['progress'][0]['udp']['tc']);raise TimeoutError('not logged')
   with mock.patch.object(p,'probe',side_effect=fail),mock.patch('sys.argv',['probe','--profile','classic','--case','tc-large','--receipt',str(receipt)]):
    with self.assertRaises(TimeoutError):p.main()
   r=json.loads(receipt.read_text());self.assertFalse(r['accepted']);self.assertFalse(r['completed']);self.assertEqual(r['error_type'],'TimeoutError');self.assertEqual(r['progress'][0]['stage'],'tcp_read_length');self.assertEqual(r['results'],[])
if __name__=='__main__':unittest.main()
