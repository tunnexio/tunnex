import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from unittest.mock import patch
import contextlib
import io
import itertools

spec = importlib.util.spec_from_file_location('private_lb', Path(__file__).with_name('probe-private-lb.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class PrivateLBGuards(unittest.TestCase):
    def test_duration_timeout_reject_nonfinite_and_out_of_bounds(self):
        for seconds, timeout in ((0, 1), (61, 1), (1, float('nan')), (1, float('inf')), (1, .1), (1, 3)):
            with self.assertRaises(ValueError):
                probe.bounds(seconds, timeout)
        probe.bounds(60, 2)

    def test_dns_requires_only_actual_owned_frontend(self):
        self.assertTrue(probe.allowed_answers(['10.231.1.10']))
        for answers in ([], ['10.231.1.4'], ['10.231.1.10', '8.8.8.8'], ['::1']):
            self.assertFalse(probe.allowed_answers(answers))

    def test_untrusted_body_has_no_receipt_echo_and_requires_identity_source(self):
        body = json.dumps({'service': 'azure-s2s-owned-app', 'client_ip': '10.233.10.2', 'private': 'NEVER_ECHO'}).encode()
        self.assertTrue(probe.project(200, body)['success'])
        self.assertNotIn('NEVER_ECHO', str(probe.project(200, body)))
        for payload in (b'not json', b'x' * 16385, b'{"service":"other","client_ip":"10.233.10.2"}', b'{"service":"azure-s2s-owned-app","client_ip":"8.8.8.8"}'):
            self.assertFalse(probe.project(200, payload)['success'])
        self.assertFalse(probe.project(500, body)['success'])

    def test_receipt_is_private_and_never_overwrites_or_follows_symlink(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path = Path(directory) / 'receipt.json'
            probe.write_receipt(path, {'success': False})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                probe.write_receipt(path, {})
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                probe.write_receipt(link, {})
    def test_response_timeout_keeps_preexisting_socket_identity(self):
        connection = Mock()
        connection.sock.getsockname.return_value = ('10.233.10.2', 41023)
        connection.getresponse.side_effect = TimeoutError('private socket error')
        entry = {'success': False, **probe.socket_identity(connection, 41023)}
        try:
            connection.getresponse()
        except TimeoutError:
            entry['error_code'] = 'dns_or_http_failed'
            connection.close()
        self.assertTrue(entry['reused_existing_socket'])
        self.assertTrue(entry['same_local_port_as_previous_persistent'])
        self.assertEqual(entry['local_port'], 41023)
        self.assertFalse(entry['success'])
        self.assertNotIn('private', str(entry))
    def test_main_timeout_receipt_retains_established_socket_after_cleanup(self):
        class Connection:
            def __init__(self, *_args, **_kwargs):
                self.sock = Mock()
                self.sock.getsockname.return_value = ('10.233.10.2', 41023)
                self.requests = 0
            def request(self, *_args, **_kwargs):
                self.requests += 1
            def getresponse(self):
                if self.requests > 1:
                    raise TimeoutError('private error must not echo')
                response = Mock(status=200, version=11, will_close=False)
                response.read.return_value = b'{"service":"azure-s2s-owned-app","client_ip":"10.233.10.2"}'
                return response
            def close(self):
                self.sock = None
        output = []
        ticks = itertools.count(0, .01)
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            with patch.object(probe.sys, 'argv', ['probe', '--receipt', str(Path(directory) / 'new.json'), '--seconds', '1']), \
                 patch.object(probe.socket, 'socket'), patch.object(probe, 'resolve', return_value=probe.TARGET), \
                 patch.object(probe.http.client, 'HTTPConnection', Connection), \
                 patch.object(probe.time, 'monotonic', side_effect=lambda: next(ticks)), patch.object(probe.time, 'sleep'), \
                 patch.object(probe.signal, 'setitimer'), patch.object(probe.signal, 'signal'), \
                 patch.object(probe, 'write_receipt', side_effect=lambda _path, value: output.append(value)), contextlib.redirect_stdout(io.StringIO()):
                probe.main()
        failures = [sample for sample in output[0]['samples'] if sample['kind'] == 'persistent_http' and not sample['success']]
        self.assertTrue(failures)
        self.assertTrue(failures[0]['reused_existing_socket'])
        self.assertTrue(failures[0]['same_local_port_as_previous_persistent'])
        self.assertEqual(failures[0]['local_port'], 41023)
        self.assertNotIn('private error', str(output))

if __name__ == '__main__':
    unittest.main()
