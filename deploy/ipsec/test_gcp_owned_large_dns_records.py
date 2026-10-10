import importlib.util,pathlib,unittest
s=importlib.util.spec_from_file_location('p',pathlib.Path(__file__).with_name('gcp-owned-large-dns-records.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
class Tests(unittest.TestCase):
 def test_exact40_and_prior_records_preserved(self):
  e=p.record('classic');self.assertEqual(len(e['rrdatas']),40);self.assertEqual(len(set(e['rrdatas'])),40)
  before={('app.classic.gcp.s2s-qa.tunnex.app.','A'):{'name':'app.classic.gcp.s2s-qa.tunnex.app.','type':'A','ttl':30,'rrdatas':['10.81.0.10']}}
  after=dict(before);after[(e['name'],'A')]=e;p.preserve(before,after,e)
  after[('app.classic.gcp.s2s-qa.tunnex.app.','A')]=dict(before[('app.classic.gcp.s2s-qa.tunnex.app.','A')],ttl=60)
  with self.assertRaises(ValueError):p.preserve(before,after,e)
 def test_existing_exact_noop_or_mismatch_refusal(self):
  e=p.record('ha');self.assertEqual(p.decide({},e),'absent');self.assertEqual(p.decide({(e['name'],'A'):e},e),'exact_exists')
  with self.assertRaises(ValueError):p.decide({(e['name'],'A'):dict(e,rrdatas=['10.80.0.100'])},e)
 def test_wrong_network_or_extra_private_binding_refused(self):
  link='https://www.googleapis.com/compute/v1/projects/'+p.PROJECT+'/global/networks/tn-gcps2s-20261010-ha';n={'id':'6379914247511756275','name':'tn-gcps2s-20261010-ha','selfLink':link};z={'name':'tn-gcps2s-20261010-ha-qa-zone','dnsName':'ha.gcp.s2s-qa.tunnex.app.','visibility':'private','privateVisibilityConfig':{'networks':[{'networkUrl':link}]}}
  p.validate_identity('ha',n,z)
  with self.assertRaises(ValueError):p.validate_identity('ha',dict(n,id='different'),z)
  z['privateVisibilityConfig']['networks'].append({'networkUrl':'other'})
  with self.assertRaises(ValueError):p.validate_identity('ha',n,z)
 def test_actual_google_binding_url_kind_and_foreign_urls(self):
  n={'id':'6379914247511756275','name':'tn-gcps2s-20261010-ha','selfLink':'https://www.googleapis.com/compute/v1/projects/'+p.PROJECT+'/global/networks/tn-gcps2s-20261010-ha'}
  url='https://compute.googleapis.com/compute/v1/projects/'+p.PROJECT+'/global/networks/tn-gcps2s-20261010-ha'
  binding={'kind':'dns#managedZonePrivateVisibilityConfigNetwork','networkUrl':url}
  z={'name':'tn-gcps2s-20261010-ha-qa-zone','dnsName':'ha.gcp.s2s-qa.tunnex.app.','visibility':'private','privateVisibilityConfig':{'kind':'dns#managedZonePrivateVisibilityConfig','networks':[binding]}}
  p.validate_identity('ha',n,z)
  for bad in [dict(binding,networkUrl=url.replace('https://','http://')),dict(binding,networkUrl=url.replace(p.PROJECT,'foreign-project')),dict(binding,networkUrl=url+'-foreign'),dict(binding,networkUrl=url+'?x=1'),dict(binding,networkUrl=url+'#fragment'),dict(binding,networkUrl=url.replace('compute.googleapis.com','user@compute.googleapis.com')),dict(binding,networkUrl=url.replace('compute.googleapis.com','compute.googleapis.com:443')),dict(binding,kind='foreign'),dict(binding,extra='unknown')]:
   z['privateVisibilityConfig']['networks']=[bad]
   with self.assertRaises(ValueError):p.validate_identity('ha',n,z)
if __name__=='__main__':unittest.main()
