"""Offline normal-client regression for the actual provider readback envelope."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location('owned_lifecycle', Path(__file__).with_name('lifecycle-live.py'))
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


class LifecycleEnvelopeTests(unittest.TestCase):
    def test_go_variable_fraction_status_timestamp_on_older_python(self):
        for fraction, expected in [('1', '100000'), ('17802', '178020'), ('178020', '178020'), ('178020123', '178020')]:
            with self.subTest(fraction=fraction):
                self.assertEqual(lifecycle.timestamp('2026-10-10T15:59:52.' + fraction + 'Z'),
                                 '2026-10-10T15:59:52.' + expected + '+00:00')
        self.assertEqual(lifecycle.timestamp('2026-10-10T15:59:52Z'), '2026-10-10T15:59:52+00:00')
        self.assertIsNone(lifecycle.timestamp(None))
        for invalid in ('2026-10-10T15:59:52.17802', '2026-10-99T15:59:52.17802Z', 'untrusted input', 42):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                lifecycle.timestamp(invalid)

    def test_actual_top_level_profile_envelope_reaches_exact_disable_and_enable_cas(self):
        # GetIPsecProviderConfiguration returns ProfileId/ConfigurationRevision
        # outside Configuration, which contains network fields only.
        for phase, initial_intent, desired in [('disable', 'enabled', 'disabled'), ('enable', 'disabled', 'enabled')]:
            with self.subTest(phase=phase):
                ids = [str(uuid.uuid4()) for _ in range(6)]
                setup = dict(zip(('org_id', 'site_id', 'gateway_id'), ids))
                state = {'id': ids[3], 'tunnel_ids': ids[4:]}
                calls = []
                record = {'id': state['id'], 'org_id': setup['org_id'], 'site_id': setup['site_id'],
                          'gateway_node_id': setup['gateway_id'], 'desired_revision': 2,
                          'desired_intent': initial_intent, 'application_state': 'not_applied',
                          'cleanup_state': 'retained_guard'}
                envelope = {
                    'profile_id': 'azure-active-active-bgp-ipv4-v1', 'configuration_revision': 1,
                    'configuration': {'mode': 'ipv4-bgp', 'customer_outside_address': '20.219.28.146',
                                      'local_prefixes': ['10.233.10.0/24'], 'remote_prefixes': ['10.231.0.0/16'],
                                      'azure': {'gateway_sku': 'VpnGw1AZ', 'vpn_type': 'RouteBased', 'ike_version': 2,
                                                'custom_policy': 'aes256-sha256-dh14-pfs2048',
                                                'use_policy_based_traffic_selectors': False, 'nat_enabled': False},
                                      'bgp': {'local_asn': 65000, 'remote_asn': 65515, 'router_id': '10.233.10.1', 'maximum_prefixes': 8},
                                      'tunnels': [{'outside_address': '52.140.60.21', 'inside_cidr': '169.254.10.1/32',
                                                   'customer_inside_address': '169.254.10.1', 'cloud_inside_address': '169.254.21.2'},
                                                  {'outside_address': '20.219.125.34', 'inside_cidr': '169.254.10.1/32',
                                                   'customer_inside_address': '169.254.10.1', 'cloud_inside_address': '169.254.22.2'}]}}
                self.assertNotIn('profile_id', envelope['configuration'])

                class FakeClient:
                    def call(self, method, path, body=None, revision=None):
                        if path.endswith('/organizations'):
                            return [{'id': setup['org_id'], 'slug': 'azure-s2s-local'}]
                        if path.endswith('/configuration'):
                            return envelope
                        if path.endswith('/intent'):
                            calls.append((method, path, body, revision))
                            record.update(desired_revision=3, desired_intent=body['intent'])
                            return dict(record)
                        if path.endswith('/status'):
                            return {'observed_at': None, 'tunnels': [{'id': ident, 'slot': index + 1,
                                     'status': 'unknown', 'selected': False} for index, ident in enumerate(state['tunnel_ids'])]}
                        if '/ipsec/connections/' in path:
                            return dict(record)
                        return {}

                with tempfile.TemporaryDirectory() as root:
                    os.chmod(root, 0o700)
                    for name, value in [('ui-accounts.json', {'owner': {'email': 'browser-owner@azure-s2s.local', 'password': 'PRIVATE-TEST-PASSWORD'}}),
                                        ('api-setup.json', setup), ('azure-live-activation.json', state)]:
                        lifecycle.activation.private_write(root + '/' + name, value)
                    output = io.StringIO()
                    with patch.object(lifecycle.activation, 'Client', FakeClient), patch('sys.argv', ['lifecycle', phase, '--private-root', root]), contextlib.redirect_stdout(output):
                        lifecycle.main()
                    self.assertEqual(calls, [('PUT', '/api/v1/organizations/' + setup['org_id'] + '/ipsec/connections/' + state['id'] + '/intent', {'intent': desired}, 2)])
                    projected = json.loads(output.getvalue())
                    self.assertTrue(projected['cas_request_sent'])
                    self.assertEqual(projected['connection']['desired_revision'], 3)
                    self.assertEqual(projected['connection']['desired_intent'], desired)
                    self.assertNotIn('PRIVATE-TEST-PASSWORD', output.getvalue())
                    self.assertNotIn('customer_outside_address', output.getvalue())
                    self.assertNotIn('configuration', output.getvalue())
                    receipt = Path(root, 'azure-lifecycle-' + phase + '.json')
                    self.assertEqual(receipt.stat().st_mode & 0o077, 0)
                    self.assertEqual(json.loads(receipt.read_text()), projected)


if __name__ == '__main__':
    unittest.main()
