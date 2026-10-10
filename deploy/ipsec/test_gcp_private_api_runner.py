import copy
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
import uuid
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('private_runner', pathlib.Path(__file__).with_name('gcp-private-api-runner.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class PrivateRunnerTests(unittest.TestCase):
    def template(self, ha=False):
        return {'id': str(uuid.uuid4()), 'name': 'owned cloud', 'site_id': str(uuid.uuid4()), 'gateway_node_id': str(uuid.uuid4()),
                'tunnel_ids': [str(uuid.uuid4()) for _ in range(2 if ha else 1)],
                'configuration': {'profile_id': 'gcp-ha-bgp-ipv4-v1' if ha else 'gcp-classic-static-ipv4-v1',
                  'mode': 'ipv4-bgp' if ha else 'ipv4-static', 'customer_outside_address': '34.131.136.132',
                  'local_prefixes': ['10.70.0.0/24'], 'remote_prefixes': ['10.80.0.0/24' if ha else '10.81.0.0/24'],
                  'tunnels': [{'outside_address': '35.1.1.' + str(i + 1), 'inside_cidr': '', 'customer_inside_address': '', 'cloud_inside_address': ''} for i in range(2 if ha else 1)],
                  **({'bgp': {'local_asn': 64520, 'remote_asn': 64521, 'router_id': '10.70.0.2', 'maximum_prefixes': 1}} if ha else {})}}

    def test_exact_profile_key_order_and_template_immutable(self):
        for ha in [False, True]:
            t = self.template(ha); before = copy.deepcopy(t); paths = []
            def read(path, limit):
                paths.append(path); return b'SyntheticFixture-PSK'
            out = m.payload(t, read)
            self.assertEqual(t, before)
            self.assertEqual([p.rsplit('-', 2)[-2:] for p in paths], [['ha', '0.psk'], ['ha', '1.psk']] if ha else [['classic', '0.psk']])
            self.assertTrue(all(x['psk'] == 'SyntheticFixture-PSK' for x in out['configuration']['tunnels']))

    def test_scope_count_secret_inside_and_framing_refuse(self):
        for change in [lambda t: t['configuration'].update(local_prefixes=['10.71.0.0/24']),
                       lambda t: t['configuration'].update(remote_prefixes=['0.0.0.0/0']),
                       lambda t: t['configuration']['tunnels'][0].update(psk='InjectedKey'),
                       lambda t: t['configuration']['tunnels'][0].update(inside_cidr='169.254.1.0/30'),
                       lambda t: t['tunnel_ids'].append(str(uuid.uuid4()))]:
            t = self.template(); change(t)
            with self.assertRaises(ValueError):m.payload(t, lambda *_: b'SyntheticKey')
        for raw in [b'SyntheticKey\n', b'1234567', b' '*12, b'A'*65, b'Key\x00abcdefgh']:
            with self.assertRaises(ValueError):m.payload(self.template(), lambda *_: raw)

    def test_private_file_and_cookie_boundaries(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)/'input';p.write_bytes(b'private');p.chmod(0o600)
            self.assertEqual(m.private_read(str(p)), b'private')
            p.chmod(0o644)
            with self.assertRaises(ValueError):m.private_read(str(p))
            p.chmod(0o600);q=pathlib.Path(d)/'link';q.symlink_to(p)
            with self.assertRaises(OSError):m.private_read(str(q))
        self.assertEqual(m.cookie_header(b'#HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t0\tsession\tsynthetic\n'), 'session=synthetic')
        for raw in [b'other.example\tFALSE\t/\tFALSE\t0\tsession\tvalue', b'127.0.0.1\tFALSE\t/\tFALSE\t0\tsession\tvalue;bad']:
            with self.assertRaises(ValueError):m.cookie_header(raw)

    def test_remote_projection_excludes_any_private_response_fields(self):
        t=self.template()
        with patch.object(m,'payload',return_value=t), patch.object(m,'api',return_value={'id':t['id'],'desired_intent':'disabled','desired_revision':1,'psk':'never-output','secrets':['never-output']}):
            out=m.remote({'action':'provider-create','cookie':'session=synthetic','input':t})
            self.assertNotIn('never-output',json.dumps(out))
        with patch.object(m,'payload',return_value=t), patch.object(m,'api',return_value={'id':t['id'],'desired_intent':'enabled'}):
            with self.assertRaises(ValueError):m.remote({'action':'provider-create','cookie':'session=synthetic','input':t})

    def test_token_delivery_stdin_only_and_no_start(self):
        class Result:returncode=0
        token='SyntheticJoinToken-12345678'
        with patch.object(m,'api',return_value={'join_token':token}), patch.object(m.subprocess,'run',return_value=Result()) as run:
            out=m.remote({'action':'join-token','cookie':'session=synthetic','input':{'node_name':'tn-gcps2s-20261010-gateway','enrols_kind':'gateway'}})
            self.assertNotIn(token,json.dumps(out))
            self.assertFalse(out['gateway_started'])
            self.assertNotIn(token,' '.join(run.call_args.args[0]))
            self.assertIn(token.encode(),run.call_args.kwargs['input'])
            self.assertIn('StrictHostKeyChecking=yes',run.call_args.args[0])
        with patch.object(m,'api',return_value={'join_token':'BadTokenWith\nNewline'}), patch.object(m.subprocess,'run') as run:
            with self.assertRaises(ValueError):m.remote({'action':'join-token','cookie':'session=synthetic','input':{'node_name':'tn-gcps2s-20261010-gateway','enrols_kind':'gateway'}})
            run.assert_not_called()

if __name__ == '__main__':unittest.main()
