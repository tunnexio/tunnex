import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('linuxfixture',pathlib.Path(__file__).with_name('customer-static-central-linux.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TestPhysicalOwnership(unittest.TestCase):
 def test_exact_mac_index_address(self):
  l=[{'ifname':'ens6','ifindex':3,'address':m.SECONDARY[2],'link_type':'ether','flags':['UP','LOWER_UP']}];a=[{'ifindex':3,'addr_info':[{'family':'inet','local':'10.87.2.10','prefixlen':24,'scope':'global','label':'ens6'}]}]
  self.assertEqual(m.exact_link(l,a,m.SECONDARY)['ipv4']['local'],'10.87.2.10')
  for key,value in [('ifindex',4),('address',m.PRIMARY[2]),('link_type','veth'),('flags',['UP'])]:
   bad=dict(l[0]);bad[key]=value
   with self.assertRaises(AssertionError):m.exact_link([bad],a,m.SECONDARY)
 def test_secondary_foreign_route_refuses(self):
  m.secondary_routes([{'dev':'ens6','dst':'default','gateway':'10.87.2.1','protocol':'dhcp','prefsrc':'10.87.2.10'}])
  for row in [{'dev':'ens6','dst':'10.99.0.0/16','protocol':'static'},{'dev':'ens6','dst':'default','gateway':'10.87.1.1','protocol':'static'},{'dev':'ens6','dst':'default','gateway':'10.87.2.1','protocol':'boot'}]:
   with self.assertRaises(AssertionError):m.secondary_routes([row])
 def test_preserve_foreign_rules(self):
  own={'priority':32765,'src':'10.87.2.10','table':'101','protocol':'static'};foreign={'priority':100,'src':'10.99.0.1','table':'101','protocol':'static'}
  self.assertEqual(m.management([], [own,foreign])['rules'],[foreign])
if __name__=='__main__':unittest.main()
