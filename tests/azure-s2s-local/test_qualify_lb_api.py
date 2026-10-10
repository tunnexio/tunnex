import importlib.util
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

if __name__ == '__main__':
    unittest.main()
