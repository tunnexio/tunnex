import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

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

if __name__ == '__main__':
    unittest.main()
