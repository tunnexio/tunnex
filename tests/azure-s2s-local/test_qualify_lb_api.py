import importlib.util
import copy
import contextlib
import io
import json
import tempfile
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('lb_api', Path(__file__).with_name('qualify-lb-api.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class LBAPIScopeTests(unittest.TestCase):
    def test_nested_actual_detail_projects_only_fresh_owned_generation(self):
        now = datetime.now(timezone.utc)
        profile = {'id': 'profile', 'provider_hint': 'azure', 'legacy_default': False, 'zone_suffixes': ['azure-s2s.test'], 'endpoints': [{'address': ip, 'port': 53, 'transport': transport} for ip in ('10.231.2.4', '10.231.2.20') for transport in ('udp', 'tcp')], 'ipsec_path': {'connection_id': 'connection', 'configuration_revision': 7, 'source_address': '10.233.10.1'}}
        config = {'id': 'config', 'version': 3, 'state': 'active', 'profiles': [profile]}
        setup = {'org_id': 'org', 'site_id': 'site', 'gateway_id': 'gateway'}
        state = {'connection_id': 'connection', 'fqdn_resource_id': 'resource'}
        binding = {'context_id': 'config', 'context_version': 3, 'profile_id': 'profile', 'configuration_revision': 7}
        resource = {'id': 'resource', 'org_id': 'org', 'fqdn': 'lbapp.azure-s2s.test', 'destination_kind': 'fqdn', 'protocol': 'tcp', 'port_low': 8080, 'port_high': 8080, 'state': 'healthy', 'answer_count': 1, 'generation': 2,
                    'resolver_context': {'site_id': 'site', 'gateway_id': 'gateway', 'site_name': 'actual-name', 'gateway_name': 'actual-name', 'resolver_config': config}, 'resolver_profile_selection': {'id': 'profile', 'config_version': 3, 'matched_suffix': 'azure-s2s.test', 'provider_hint': 'azure'}}
        detail = {'resource': resource, 'active_answer_addresses': ['10.231.1.10'], 'status_source': 'active_generation', 'resolver_ready': True, 'observed_at': (now - timedelta(seconds=1)).isoformat(), 'fresh_until_at': (now + timedelta(seconds=20)).isoformat(), 'server_reason': 'PRIVATE-DO-NOT-ECHO'}
        projected = probe.fqdn_detail_projection(detail, setup, state, binding, now)
        self.assertTrue(projected['ready']); self.assertEqual(projected['generation'], 2)
        self.assertNotIn('PRIVATE', str(projected))
        for change in ({'active_answer_addresses': ['8.8.8.8']}, {'fresh_until_at': (now - timedelta(seconds=1)).isoformat()}, {'resource': {**resource, 'resolver_profile_selection': {**resource['resolver_profile_selection'], 'id': 'other'}}}):
            with self.assertRaises(probe.lab.LabError):
                probe.fqdn_detail_projection({**detail, **change}, setup, state, binding, now)
        not_ready = {**detail, 'resource': {**resource, 'state': 'resolving'}, 'status_source': 'latest_generation'}
        self.assertFalse(probe.fqdn_detail_projection(not_ready, setup, state, binding, now)['ready'])
    def test_normal_grant_contract_uses_list_and_preserves_eight_rules(self):
        connection_id = '11111111-1111-4111-8111-111111111111'
        setup = {'org_id': 'org', 'site_id': 'site', 'gateway_id': 'gateway'}
        dns = {'connection_id': connection_id, 'source_address': '10.233.10.2', 'dns_rules': ['d1', 'd2', 'd3', 'd4'], 'app_rules': ['a1', 'a2'], 'reverse_rules': ['r1', 'r2']}
        protected = sorted(probe.protected_ids(dns))
        calls = []
        class Client:
            def __init__(self, _account):
                pass
            def call(self, method, path, body=None):
                calls.append((method, path, body))
                if method == 'GET' and '/resources/' in path:
                    raise AssertionError('Unsupported resource GET-by-ID')
                if path == '/api/v1/organizations':
                    return [{'id': 'org', 'slug': 'azure-s2s-local'}]
                if path.endswith('/policies'):
                    if method == 'POST':
                        return {'id': 'lb-rule'}
                    return [{'id': value} for value in protected]
                if path.endswith('/configuration'):
                    return {'configuration_revision': 1, 'configuration': {'local_prefixes': ['10.233.10.0/24'], 'remote_prefixes': ['10.231.0.0/16']}}
                if '/ipsec/connections/' in path:
                    return {'site_id': 'site', 'gateway_node_id': 'gateway', 'desired_intent': 'enabled'}
                if path.endswith('/resources') and method == 'GET':
                    return [{'id': 'other', **probe.resource_body()}, {'id': 'lb-resource', **probe.resource_body()}]
                raise AssertionError('Unexpected endpoint')
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            private = Path(directory)
            inputs = {'ui-accounts.json': {'owner': {'email': 'browser-owner@azure-s2s.local', 'password': 'private-fixture'}}, 'api-setup.json': setup, 'dns-api-setup.json': dns,
                      'lb-api-setup.json': {'connection_id': connection_id, 'source_address': '10.233.10.2', 'resource_body': probe.resource_body(), 'rule_id': None, 'resource_id': 'lb-resource', 'protected_policy_ids': protected}}
            for name, value in inputs.items():
                path = private / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            with patch.object(probe.lab, 'Client', Client), patch.object(probe.argparse.ArgumentParser, 'parse_args', return_value=type('Args', (), {'phase': 'grant', 'private_root': private, 'connection_id': connection_id, 'expiry_seconds': 90})()), contextlib.redirect_stdout(io.StringIO()):
                probe.main()
            self.assertEqual(json.loads((private / 'dns-api-setup.json').read_text()), dns)
            self.assertEqual(json.loads((private / 'lb-api-setup.json').read_text())['rule_id'], 'lb-rule')
        mutations = [(method, path, body) for method, path, body in calls if method != 'GET']
        self.assertEqual(len(mutations), 1)
        body = mutations[0][2]
        self.assertEqual(body['src_cidr'], '10.233.10.2/32')
        self.assertEqual(body['dst_resource_id'], 'lb-resource')
        self.assertIn('expires_at', body)

    def test_list_requires_one_exact_identity_and_diagnostics_do_not_echo_errors(self):
        for values in ([], [{'id': 'saved'}, {'id': 'saved'}], {'resource': {'id': 'saved'}}):
            client = type('Client', (), {'call': lambda _self, *_args: values})()
            with self.assertRaises(probe.lab.LabError):
                probe.saved_resource(client, '/resources', 'saved')
        self.assertEqual(probe.saved_resource(type('Client', (), {'call': lambda *_args: [{'id': 'saved'}]})(), '/fqdn-resources', 'saved')['id'], 'saved')
        result = probe.safe_diagnostic(probe.lab.LabError('PRIVATE', 403, 'forbidden'))
        self.assertIn('status=403 code=forbidden', result)
        self.assertNotIn('PRIVATE', result)
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
