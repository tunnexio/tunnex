import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name('customer-stream-growth-observer.py');s=importlib.util.spec_from_file_location('growth',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Growth(unittest.TestCase):
 def owner(self):return {'listener':{'pid':55,'startticks':'100','exe':'/usr/bin/nc.openbsd'}}
 def rows(self,values=(100,100,200),ports=(45000,45000,45000),inode='9',ticks='100'):
  return ''.join('__SAMPLE__ '+str(i)+'\n'+str(1000+i)+'\n'+str(2000+i)+'\n'+str(value)+' 1 '+inode+' 0 600\n'+ticks+'\nESTAB 0 0 10.85.1.10:8081 10.84.2.10:'+str(ports[i])+' users:(("nc",pid=55,fd=3))\n__END__\n'for i,value in enumerate(values)).encode()
 def test_growth_stall_resume_same_tuple(self):
  v=m.parse(self.rows(),self.owner());self.assertEqual(v['observed_client_ports'],['45000']);self.assertEqual(v['zero_growth_to_resume_intervals'][0]['bound_seconds'],2);self.assertFalse(v['payload_read'])
 def test_socket_reconnect_rejected(self):
  with self.assertRaises(AssertionError):m.parse(self.rows(ports=(45000,45001,45001)),self.owner())
 def test_recycled_listener_rejected(self):
  with self.assertRaises(AssertionError):m.parse(self.rows(ticks='101'),self.owner())
 def test_changed_file_and_decreasing_bytes_rejected(self):
  with self.assertRaises(AssertionError):m.parse(self.rows().replace(b'200 1 9 0 600',b'200 1 10 0 600'),self.owner())
  with self.assertRaises(AssertionError):m.parse(self.rows(values=(100,50,200)),self.owner())
 def test_trailing_stall_censored(self):
  v=m.parse(self.rows(values=(100,200,200)),self.owner());self.assertTrue(v['trailing_zero_growth_censored']);self.assertEqual(v['zero_growth_to_resume_intervals'],[])
 def test_foreign_fixture_and_listener_rejected(self):
  b={'nonce':'a'*64};l={'identity':{'pid':1353,'startticks':'100','exe':'/usr/bin/nc.openbsd','cmdline':'nc10.85.1.10 8081'}}
  with self.assertRaises(AssertionError):m.ownership(b,l)
if __name__=='__main__':unittest.main()
