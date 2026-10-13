import copy, pathlib, runpy, unittest
ROOT=pathlib.Path(__file__).parent
H=runpy.run_path(str(ROOT/'cloud-enrolled-endpoint-resume-cycle3.py'))
V={};exec(compile((ROOT/'cloud-enrolled-restart-v6.py').read_text().split('p=argparse.ArgumentParser();',1)[0],'v6','exec'),V)
H['reviewed_link_proof'].__globals__['link_proof']=V['link_proof']
class ResumeTests(unittest.TestCase):
 def endpoints(self):
  row={'NetworkID':H['REVIEWED_NETWORK'],'MacAddress':H['OLD_MAC'],'IPAddress':'172.30.88.2','IPAMConfig':{'IPv4Address':'172.30.88.2'},'Aliases':['gateway'],'Gateway':'172.30.88.1','IPPrefixLen':24,'EndpointID':'old','DNSNames':['tunnex-bgp-20261007-gateway','gateway','382b1763ae4b']}
  old={'net':row};new=copy.deepcopy(old);new['net']['MacAddress']=H['NEW_MAC'];new['net']['EndpointID']='new';new['net']['DNSNames']=['tunnex-bgp-20261007-gateway-trusted-restart-3','gateway','0faef89deabf'];return old,new
 def test_exact_reviewed_endpoint(self):
  self.assertTrue(H['endpoint_proof'](*self.endpoints()))
 def test_foreign_endpoint_refused(self):
  for key,value in [('MacAddress','00:00:00:00:00:01'),('NetworkID','foreign'),('IPAddress','172.30.88.3'),('Aliases',['foreign']),('IPAMConfig',{}),('Gateway','172.30.88.9'),('DNSNames',['foreign'])]:
   old,new=self.endpoints();new['net'][key]=value
   with self.subTest(key=key),self.assertRaises(AssertionError):H['endpoint_proof'](old,new)
 def test_duplicate_endpoint_refused(self):
  old,new=self.endpoints();new['foreign']=copy.deepcopy(new['net'])
  with self.assertRaises(AssertionError):H['endpoint_proof'](old,new)
 def links(self):
  old=[{'ifname':'eth0','ifindex':2,'operstate':'UP','flags':['UP','LOWER_UP'],'link_type':'ether','linkinfo':{'info_kind':'veth'},'address':H['OLD_MAC'],'mtu':1500}]
  new=copy.deepcopy(old);new[0].update(ifindex=3,address=H['NEW_MAC'])
  addr=[{'ifname':'eth0','addr_info':[{'family':'inet','local':'172.30.88.2','prefixlen':24,'scope':'global','broadcast':'172.30.88.255','label':'eth0'}]}]
  return new,addr,old,addr
 def test_reviewed_new_link(self):
  p=H['reviewed_link_proof'](*self.links());self.assertEqual(p['current_ifindex'],3);self.assertEqual(p['old_mac'],H['OLD_MAC'])
 def test_link_changes_refused(self):
  for key,value in [('ifindex',4),('address',H['OLD_MAC']),('mtu',1400),('operstate','DOWN'),('flags',['UP']),('linkinfo',{'info_kind':'xfrm'})]:
   args=list(self.links());args[0][0][key]=value
   with self.subTest(key=key),self.assertRaises(AssertionError):H['reviewed_link_proof'](*args)
 def test_no_topology_mutations_in_resume(self):
  s=(ROOT/'cloud-enrolled-endpoint-resume-cycle3.py').read_text()
  self.assertNotIn("call('network'",s);self.assertNotIn("api('POST'",s)
if __name__=='__main__':unittest.main()
