import importlib.util
import json
import pathlib
import unittest

spec=importlib.util.spec_from_file_location('collector',pathlib.Path(__file__).with_name('gcp-cloud-public-status.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PublicStatusTests(unittest.TestCase):
    def test_strict_projection_drops_private_and_unknown_nested_fields(self):
        c={'id':'owned','desired_revision':2,'configuration':{'psk':'secret-fixture'},'join_token':'secret-fixture'}
        s={'observed_at':None,'active_slot':None,'psk':'secret-fixture','tunnels':[{'id':'t','slot':1,'status':'unknown','key':'secret-fixture'}],'bgp':{'version':2,'sequence':1,'peers':[{'slot':1,'state':'unknown','psk':'secret-fixture'}],'routes':[{'slot':1,'prefix':'10.80.0.0/24','secret':'secret-fixture'}]}}
        out=m.project(c,s)
        self.assertNotIn('secret-fixture',json.dumps(out))
        self.assertIsNone(out['status']['observed_at']);self.assertEqual(out['status']['tunnels'][0]['status'],'unknown')
        self.assertNotIn('configuration',out['connection'])

    def test_templates_only_exact_hosts_ports_and_unfilled_grant_ids(self):
        p=pathlib.Path(__file__).resolve().parents[2]/'tests/gcp-s2s-local/GCP-CLOUD-KEYFREE-GRANT-TEMPLATES-20261010.json'
        items=json.loads(p.read_text())['items'];self.assertEqual(len(items),8)
        tuples=set()
        for item in items:
            r=item['resource_body'];g=item['grant_body']
            self.assertEqual(r['port_low'],r['port_high']);self.assertTrue(r['cidr'].endswith('/32'))
            self.assertEqual(g['src_kind'],'site');self.assertEqual(g['src_site_id'],'01a12500-95ae-7728-b901-54f20df98cc1');self.assertIsNone(g['dst_resource_id'])
            tuples.add((r['cidr'],r['protocol'],r['port_low']))
        expected={(net+'.10/32','tcp',8080) for net in ['10.80.0','10.81.0']}|{(net+'.10/32','udp',9000) for net in ['10.80.0','10.81.0']}|{(net+'.2/32',protocol,53) for net in ['10.80.0','10.81.0'] for protocol in ['udp','tcp']}
        self.assertEqual(tuples,expected)

if __name__=='__main__':unittest.main()
