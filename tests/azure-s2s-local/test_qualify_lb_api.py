import importlib.util
import copy
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('lb_api', Path(__file__).with_name('qualify-lb-api.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class LBAPIScopeTests(unittest.TestCase):
    def test_existing_rule_counts_and_unique_identity_required(self):
        state = {'dns_rules': ['d1', 'd2', 'd3', 'd4'], 'app_rules': ['a1', 'a2'], 'reverse_rules': ['r1', 'r2']}
        self.assertEqual(len(probe.protected_ids(state)), 8)
        for changed in ({**state, 'dns_rules': []}, {**state, 'reverse_rules': ['a1', 'r2']}):
            with self.assertRaises(probe.lab.LabError):
                probe.protected_ids(changed)
    def test_distinct_resource_never_expands_existing_app_scope(self):
        self.assertEqual(probe.resource_body(), {'name': 'Azure owned private LB TCP', 'cidr': '10.231.1.10/32', 'protocol': 'tcp', 'port_low': 8080, 'port_high': 8080})
    def test_fqdn_profile_refuses_stale_binding_cross_profile_and_public_endpoint(self):
        profile = {'id': 'owned', 'provider_hint': 'azure', 'legacy_default': False, 'zone_suffixes': ['azure-s2s.test'],
                   'endpoints': [{'address': ip, 'port': 53, 'transport': transport} for ip in ('10.231.2.4', '10.231.2.20') for transport in ('udp', 'tcp')],
                   'ipsec_path': {'connection_id': 'connection', 'configuration_revision': 7, 'source_address': '10.233.10.1'}}
        context = {'state': 'active', 'profiles': [profile]}
        self.assertEqual(probe.selected_profile(context, 'connection', 7)['id'], 'owned')
        invalid = []
        changed = copy.deepcopy(context); changed['profiles'][0]['ipsec_path']['configuration_revision'] = 6; invalid.append(changed)
        changed = copy.deepcopy(context); changed['profiles'][0]['endpoints'][0]['address'] = '8.8.8.8'; invalid.append(changed)
        changed = copy.deepcopy(context); other = copy.deepcopy(profile); other.update(id='other', zone_suffixes=['lbapp.azure-s2s.test']); changed['profiles'].append(other); invalid.append(changed)
        for changed in invalid:
            with self.assertRaises(probe.lab.LabError):
                probe.selected_profile(changed, 'connection', 7)

if __name__ == '__main__':
    unittest.main()
