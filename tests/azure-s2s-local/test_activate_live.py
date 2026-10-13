import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('activation', Path(__file__).with_name('activate-live.py'))
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)


class ActivationTests(unittest.TestCase):
    def test_create_and_enable_use_normal_protocol_without_printing_secrets(self):
        org, site, gateway = [str(activation.uuid.uuid4()) for _ in range(3)]
        calls = []
        connection = {'gateway_node_id': gateway, 'site_id': site, 'desired_revision': 7,
                      'desired_intent': 'disabled', 'application_state': 'pending'}

        class FakeClient:
            def call(self, method, path, body=None, revision=None):
                calls.append((method, path, body, revision))
                if path.endswith('/organizations'):
                    return [{'id': org, 'slug': 'azure-s2s-local'}]
                if path.endswith('/status'):
                    return {'tunnels': [{'slot': 0, 'status': 'down', 'psk': 'SECRET-SHOULD-NOT-PRINT'}]}
                if path.endswith('/intent'):
                    return dict(connection, desired_revision=8, desired_intent='enabled')
                return connection

        with tempfile.TemporaryDirectory() as root:
            for name, content in [('ui-accounts.json', {'owner': {'email': 'browser-owner@azure-s2s.local', 'password': 'PRIVATE-PASSWORD'}}),
                                  ('api-setup.json', {'org_id': org, 'site_id': site, 'gateway_id': gateway})]:
                activation.private_write(root + '/' + name, content)
            psk = root + '/psk'
            fd = os.open(psk, os.O_CREAT | os.O_WRONLY, 0o600)
            os.write(fd, b'PRIVATE-PSK-MATERIAL')
            os.close(fd)
            output = io.StringIO()
            with patch.object(activation, 'Client', FakeClient), contextlib.redirect_stdout(output):
                with patch('sys.argv', ['activate', 'create', '--private-root', root, '--psk-file', psk]):
                    activation.main()
                with patch('sys.argv', ['activate', 'enable', '--private-root', root]):
                    activation.main()
            self.assertNotIn('PRIVATE-', output.getvalue())
            self.assertNotIn('SECRET-', output.getvalue())
            check = next(call for call in calls if call[1].endswith('/configuration-check'))
            self.assertEqual(check[2]['profile_id'], 'azure-active-active-bgp-ipv4-v1')
            create = next(call for call in calls if call[0] == 'POST' and call[1].endswith('/connections'))
            self.assertNotIn('desired_intent', create[2])
            self.assertEqual(create[2]['configuration']['local_prefixes'], ['10.233.10.0/24'])
            self.assertEqual(create[2]['configuration']['bgp']['router_id'], '10.233.10.1')
            self.assertEqual(create[2]['configuration']['tunnels'][0]['psk'], create[2]['configuration']['tunnels'][1]['psk'])
            enable = next(call for call in calls if call[1].endswith('/intent'))
            self.assertEqual(enable[3], 7)
            self.assertEqual(enable[2], {'intent': 'enabled'})
            self.assertEqual(json.loads(output.getvalue().splitlines()[-1])['application_reachability'], 'not_probed')

    def test_resume_reuses_ids_only_after_verified_404(self):
        org, site, gateway, connection_id, tunnel1, tunnel2 = [str(activation.uuid.uuid4()) for _ in range(6)]
        state = {'id': connection_id, 'tunnel_ids': [tunnel1, tunnel2]}
        calls = []
        absent_status = [404]

        class FakeClient:
            def call(self, method, path, body=None, revision=None):
                calls.append((method, path, body))
                if path.endswith('/organizations'):
                    return [{'id': org, 'slug': 'azure-s2s-local'}]
                if method == 'GET' and path.endswith(connection_id) and absent_status:
                    raise activation.APIError(absent_status.pop())
                if path.endswith('/status'):
                    return {'tunnels': []}
                return {'gateway_node_id': gateway, 'site_id': site, 'desired_revision': 1}

        with tempfile.TemporaryDirectory() as root:
            activation.private_write(root + '/ui-accounts.json', {'owner': {'email': 'browser-owner@azure-s2s.local', 'password': 'PRIVATE'}})
            activation.private_write(root + '/api-setup.json', {'org_id': org, 'site_id': site, 'gateway_id': gateway})
            activation.private_write(root + '/azure-live-activation.json', state)
            psk = root + '/psk'
            fd = os.open(psk, os.O_CREAT | os.O_WRONLY, 0o600)
            os.write(fd, b'PRIVATE-PSK-MATERIAL')
            os.close(fd)
            arguments = ['activate', 'resume-create', '--private-root', root, '--psk-file', psk]
            with patch.object(activation, 'Client', FakeClient), patch('sys.argv', arguments), contextlib.redirect_stdout(io.StringIO()):
                activation.main()
                create = next(c for c in calls if c[0] == 'POST' and c[1].endswith('/connections'))
                self.assertEqual(create[2]['id'], connection_id)
                self.assertEqual(create[2]['tunnel_ids'], [tunnel1, tunnel2])
                self.assertEqual(json.loads(activation.private_read(root + '/azure-live-activation.json')), state)
                for failure in [403, 500, None]:
                    calls.clear()
                    absent_status[:] = [failure]
                    with self.assertRaises(activation.APIError):
                        activation.main()
                    self.assertFalse(any(c[0] == 'POST' and c[1].endswith('/connections') for c in calls))
                calls.clear()
                with self.assertRaises(ValueError):
                    activation.main()
                self.assertFalse(any(c[0] == 'POST' and c[1].endswith('/connections') for c in calls))

    def test_api_error_only_exposes_allowlisted_bounded_code(self):
        for body, expected in [(b'{"code":"ipsec_connection_ineligible","message":"PRIVATE"}', 'ipsec_connection_ineligible'),
                               (b'{"code":"PRIVATE-PSK"}', None), (b'x' * 16385, None)]:
            client = activation.Client()
            error = activation.urllib.error.HTTPError('private', 409, 'private', {}, io.BytesIO(body))
            with patch.object(client.opener, 'open', side_effect=error):
                with self.assertRaises(activation.APIError) as raised:
                    client.call('POST', '/reviewed')
            self.assertEqual(raised.exception.status, 409)
            self.assertEqual(raised.exception.code, expected)

    def test_private_input_rejects_symlinks_and_public_files(self):
        with tempfile.TemporaryDirectory() as root:
            path = root + '/input'
            Path(path).write_text('secret')
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                activation.private_read(path)
            os.chmod(path, 0o600)
            os.symlink(path, root + '/link')
            with self.assertRaises(OSError):
                activation.private_read(root + '/link')


if __name__ == '__main__':
    unittest.main()
