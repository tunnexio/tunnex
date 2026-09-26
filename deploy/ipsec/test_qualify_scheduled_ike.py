import copy
import struct
import unittest
from unittest.mock import patch

import qualify_scheduled_ike as q


def engine(number):
    return {'TunnelID': '00000000-0000-0000-0000-%012d' % number,
            'Binding': {'DesiredRevision': 3, 'ConfigurationRevision': 4},
            'SecretRevision': 2, 'LocalAddress': '192.0.2.1', 'RemoteAddress': '192.0.2.2',
            'LocalIdentity': '198.51.100.1', 'RemoteIdentity': '192.0.2.2',
            'LocalPrefixes': ['10.1.0.0/24'], 'RemotePrefixes': ['10.2.0.0/24'],
            'XFRMID': 1000 + number, 'ReqID': 2000 + number}


class IKEQualificationTests(unittest.TestCase):
    def setUp(self):
        self.engines = [engine(1), engine(2)]

    def test_only_ike_timer_and_its_jitter_change(self):
        baseline = q.render(self.engines)
        accelerated = q.render(self.engines, [120, 150])
        normalized = accelerated.replace('rekey_time = 120s', 'rekey_time = 28800s').replace('rekey_time = 150s', 'rekey_time = 28800s')
        normalized = normalized.replace('    rand_time = 0s\n', '').replace('    over_time = 2880s\n', '')
        self.assertEqual(normalized, baseline)
        self.assertEqual(baseline.count('life_time = 3600s'), 2)
        self.assertEqual(baseline.count('rekey_time = 3000s'), 2)
        self.assertIn('reqid = 2001', baseline)
        self.assertIn('if_id_out = 1002', baseline)
        self.assertNotIn('secrets', baseline)

    def test_foreign_loaded_config_refuses_bulk_reload(self):
        m = {'engines': self.engines}
        text = '\n'.join(q.name(e) + ': IKEv2' for e in self.engines)
        with patch.object(q, 'swan', return_value=text):
            q.verify_exact_configs(m)
        with patch.object(q, 'swan', return_value=text + '\nforeign: IKEv2'):
            with self.assertRaises(ValueError):
                q.verify_exact_configs(m)

    def test_profile_values_cannot_inject_config(self):
        for field in ['LocalAddress', 'LocalIdentity']:
            bad = copy.deepcopy(self.engines)
            bad[0][field] = '192.0.2.1\nsecrets {}'
            with self.assertRaises(ValueError):
                q.render(bad)

    def test_sample_requires_installed_child_and_timer(self):
        n = q.name(self.engines[0])
        text = '%s: #17, ESTABLISHED, IKEv2\n  established 1s ago, rekeying in 119s\n  %s: #2, reqid 2001, INSTALLED, TUNNEL\n' % (n, n)
        self.assertEqual(q.sample(text, self.engines)[n], {'ike_serial': 17, 'remaining_seconds': 119})
        self.assertEqual(q.sample(text.replace('INSTALLED', 'INSTALLING'), self.engines), {})
        self.assertEqual(q.sample(text.replace('rekeying in 119s', 'no countdown'), self.engines), {})

    def test_decode_rekey_event_has_old_and_new_ike_ids(self):
        def section(key):
            return bytes([1, len(key)]) + key.encode()
        def value(key, val):
            return bytes([3, len(key)]) + key.encode() + struct.pack('!H', len(val)) + val.encode()
        raw = section('connection') + section('old') + value('uniqueid', '17') + bytes([2])
        raw += section('new') + value('uniqueid', '19') + value('state', 'ESTABLISHED') + bytes([2, 2])
        event = q.decode_vici(raw)
        self.assertEqual(event['connection']['old']['uniqueid'], '17')
        self.assertEqual(event['connection']['new']['uniqueid'], '19')
        with self.assertRaises(ValueError):
            q.decode_vici(raw[:-1])

    def test_changed_runtime_or_delivery_refuses_mutation(self):
        manifest = {'container': 'exact', 'pid': 1, 'started': 'old', 'journal': '/state', 'delivery': 'delivery', 'engines': self.engines}
        identity = {'state': {'Running': True, 'Pid': 2, 'StartedAt': 'new'}}
        with patch.object(q.proof, 'inspect', return_value=identity):
            with self.assertRaises(ValueError):
                q.authority_unchanged(manifest)
        identity['state'].update(Pid=1, StartedAt='old')
        entry = {'Phase': 'applied', 'ContractVersion': 2, 'DeliveryID': 'different', 'Engines': self.engines}
        with patch.object(q.proof, 'inspect', return_value=identity), patch.object(q.proof, 'state_mount'), patch.object(q.proof, 'private_read', return_value={'Payload': {'Entries': [entry]}}):
            with self.assertRaises(ValueError):
                q.authority_unchanged(manifest)

    def test_bootstrap_uses_exact_child_and_parent_not_rekey(self):
        n = q.name(self.engines[0])
        with patch.object(q, 'authority_unchanged'), patch.object(q, 'read_sample', side_effect=[{n: {'ike_serial': 1}}, {n: {'ike_serial': 2, 'remaining_seconds': 119}}]), patch.object(q, 'swan') as swan:
            result = q.fresh_session({}, self.engines[0], 120)
            self.assertEqual(result['ike_serial'], 2)
            self.assertEqual(swan.call_args_list[0].args[1:4], ('--terminate', '--ike', n))
            self.assertEqual(swan.call_args_list[1].args[1:6], ('--initiate', '--child', n, '--ike', n))


if __name__ == '__main__':
    unittest.main()
