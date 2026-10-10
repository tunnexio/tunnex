import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('actions',pathlib.Path(__file__).with_name('gcp-cloud-owner-actions.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Boundaries(unittest.TestCase):
    def test_exact_cas_and_profile_capabilities(self):
        c={'site_id':m.SITE,'gateway_node_id':m.NODE,'desired_intent':'disabled','desired_revision':7,'deleted_at':None,'cleanup_state':'retained_guard'}
        e={'eligible':True,'gcp_ha':{'eligible':True},'bgp':{'eligible':True},'gcp_classic':{'eligible':True}}
        self.assertEqual(m.enable_preflight(c,e,7,'ha'),({'If-Match':'"7"'},{'intent':'enabled'}))
        for field,value in [('gateway_node_id','foreign'),('site_id','foreign'),('desired_revision',8),('desired_intent','enabled'),('cleanup_state','pending'),('deleted_at','date')]:
            with self.subTest(field=field),self.assertRaises(ValueError):m.enable_preflight(dict(c,**{field:value}),e,7,'ha')
        for gate in ['gcp_ha','bgp']:
            with self.subTest(gate=gate),self.assertRaises(ValueError):m.enable_preflight(c,dict(e,**{gate:{'eligible':False}}),7,'ha')
        self.assertEqual(m.enable_preflight(c,dict(e,bgp={'eligible':False}),7,'classic')[1],{'intent':'enabled'})
        with self.assertRaises(ValueError):m.enable_preflight(c,dict(e,gcp_classic={'eligible':False}),7,'classic')
    def test_exact_eight_tuples(self):
        import json
        p=pathlib.Path(__file__).parents[2]/'tests/gcp-s2s-local/GCP-CLOUD-KEYFREE-GRANT-TEMPLATES-20261010.json'
        items=json.loads(p.read_text())['items'];self.assertEqual(len(items),8)
        actual={(x['resource_body']['cidr'],x['resource_body']['protocol'],x['resource_body']['port_low'],x['resource_body']['port_high']) for x in items}
        expected={(f'10.{n}.0.{host}/32',proto,port,port) for n in [80,81] for host,proto,port in [(10,'tcp',8080),(10,'udp',9000),(2,'tcp',53),(2,'udp',53)]}
        self.assertEqual(actual,expected)
        for item in items:
            grant=item['grant_body']
            if item['resource_body']['port_low']==53:
                self.assertEqual((grant['src_kind'],grant['src_cidr']),('cidr','10.70.0.2/32'));self.assertNotIn('src_site_id',grant)
            else:self.assertEqual((grant['src_kind'],grant['src_site_id']),('site',m.SITE))
if __name__=='__main__':unittest.main()
