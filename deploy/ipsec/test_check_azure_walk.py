import hashlib
import pathlib
import subprocess
import sys
import tempfile
import unittest
from check_azure_walk import PROFILE_CHECKS, check

class AzureWalkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / 'proof.txt').write_bytes(b'synthetic checker fixture')

    def receipt(self, profile):
        return {'schema_version': 1, 'profile': profile, 'source_sha': 'a' * 40,
            'environment': 'live-azure', 'checks': {name: {'status': 'pass',
            'artifacts': [{'path': 'proof.txt', 'sha256': hashlib.sha256(
                b'synthetic checker fixture').hexdigest()}]} for name in PROFILE_CHECKS[profile]}}

    def test_explicit_profiles(self):
        for profile in PROFILE_CHECKS:
            self.assertEqual(check(self.receipt(profile), self.root), [])

    def test_cross_cloud_and_local_refused(self):
        for profile in PROFILE_CHECKS:
            receipt = self.receipt(profile)
            for env in ('live-aws', 'live-gcp', 'local-emulator'):
                receipt['environment'] = env
                self.assertIn('live Azure evidence required', check(receipt, self.root))
        receipt['profile'] = 'aws-static-ipv4-v1'
        self.assertEqual(check(receipt, self.root), ['unsupported Azure profile'])

    def test_topology_and_mode_cannot_share_incomplete_coverage(self):
        receipt = self.receipt('azure-active-standby-static-ipv4-v1')
        receipt['profile'] = 'azure-active-active-bgp-ipv4-v1'
        self.assertIn('required check set does not match', check(receipt, self.root))

    def test_pending_templates_refused(self):
        for profile in PROFILE_CHECKS:
            path = pathlib.Path(__file__).with_name(profile.removesuffix('-ipv4-v1')+'-walk-template.json')
            result = subprocess.run([sys.executable, str(path.with_name('check_azure_walk.py')), str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('pending or failed', result.stdout)

    def test_integrity_and_sanitized_error(self):
        for profile in PROFILE_CHECKS:
            receipt = self.receipt(profile)
            name = next(iter(receipt['checks']))
            receipt['checks'][name]['artifacts'][0]['path'] = '../secret-marker'
            errors = check(receipt, self.root)
            self.assertTrue(errors)
            self.assertNotIn('secret-marker', str(errors))
        (self.root / 'proof.txt').write_bytes(b'changed')
        self.assertTrue(check(self.receipt(profile), self.root))

if __name__ == '__main__':
    unittest.main()
