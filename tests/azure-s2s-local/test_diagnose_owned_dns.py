import importlib.util
from pathlib import Path
from datetime import datetime,timezone,timedelta
import unittest
spec=importlib.util.spec_from_file_location('dnsdiag',Path(__file__).with_name('diagnose-owned-dns.py'))
diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)
class DNSTests(unittest.TestCase):
 def test_exact_bound_grants_distinguish_stale_context(self):
  grant={'source_address':'10.233.10.1','resolver_address':'10.231.2.4','connection_id':'connection','configuration_revision':6,'context_config_id':'context','context_config_version':2,'profile_id':'profile'}
  material={'manifest':{'connection_id':'connection','configuration_revision':6},'policy':{'dns_resolver_grants':[grant]},'secrets':[{'psk':'NEVER_ECHO'}]}
  request={'resolver_ipsec_path':{'source_address':'10.233.10.1','connection_id':'connection','configuration_revision':6},'resolver_config_id':'context','resolver_config_version':2,'resolver_profile_id':'profile','deadline':(datetime.now(timezone.utc)+timedelta(seconds=10)).isoformat(),'resolver_endpoints':[{'address':'10.231.2.4','port':53,'transport':'udp'}],'hostname':'NEVER_ECHO'}
  result=diag.project(material,{'dns_resolve_request':request});self.assertEqual(result['request_exact_bound_grant_counts']['10.231.2.4'],1);self.assertNotIn('NEVER_ECHO',str(result))
  request['resolver_config_version']=3
  result=diag.project(material,{'dns_resolve_request':request});self.assertEqual(result['known_source_endpoint_grant_counts']['10.231.2.4'],1);self.assertEqual(result['request_exact_bound_grant_counts']['10.231.2.4'],0)
 def test_header_census_excludes_office_source_and_payload(self):
  raw=b'IP 10.233.10.1.40000 > 10.231.2.4.53: UDP, length 25\nIP 10.231.2.4.53 > 10.233.10.1.40000: UDP, length 60\nIP 10.233.10.2.40000 > 10.231.2.20.53: UDP, length 25 NEVER_ECHO\n'
  result=diag.header_counts(raw);self.assertEqual(result['10.231.2.4'],{'requests':1,'responses':1});self.assertEqual(result['10.231.2.20'],{'requests':0,'responses':0});self.assertNotIn('NEVER_ECHO',str(result))
