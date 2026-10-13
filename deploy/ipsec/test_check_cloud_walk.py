import hashlib
import pathlib
import tempfile
import unittest

from check_cloud_walk import check_walk


class CloudWalkIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / 'proof.txt').write_bytes(b'synthetic checker fixture')
        self.receipt = {
            'schema_version': 1, 'profile': 'synthetic-gcp-test-profile',
            'source_sha': 'a' * 40, 'environment': 'synthetic-gcp-test-environment',
            'checks': {'routing': {'status': 'pass', 'artifacts': [{
                'path': 'proof.txt',
                'sha256': hashlib.sha256(b'synthetic checker fixture').hexdigest(),
            }]}},
        }

    def check(self):
        return check_walk(self.receipt, self.root,
            profile='synthetic-gcp-test-profile',
            environment='synthetic-gcp-test-environment',
            checks_required=('routing',), environment_error='wrong environment')

    def test_exact_provider_contract(self):
        self.assertEqual(self.check(), [])
        self.receipt['profile'] = 'aws-static-ipv4-v1'
        self.assertIn('unsupported receipt schema/profile', self.check())

    def test_cross_cloud_evidence_is_refused(self):
        self.receipt['environment'] = 'live-aws'
        self.assertIn('wrong environment', self.check())

    def test_provider_specific_gates_cannot_be_omitted(self):
        self.receipt['checks'] = {}
        self.assertIn('required check set does not match', self.check())

    def test_sanitized_errors(self):
        self.receipt['checks']['routing']['artifacts'][0]['path'] = '../secret-marker'
        errors = self.check()
        self.assertTrue(errors)
        self.assertNotIn('secret-marker', str(errors))


if __name__ == '__main__':
    unittest.main()
