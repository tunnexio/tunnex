import hashlib
import pathlib
import subprocess
import sys
import tempfile
import unittest

from check_aws_walk import CHECKS, check


class AWSWalkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / 'proof.txt').write_bytes(b'redacted fixture evidence')
        self.receipt = {
            'schema_version': 1, 'profile': 'aws-static-ipv4-v1',
            'source_sha': 'a' * 40, 'environment': 'live-aws',
            'checks': {name: {'status': 'pass', 'artifacts': [{
                'path': 'proof.txt',
                'sha256': hashlib.sha256(b'redacted fixture evidence').hexdigest(),
            }]} for name in CHECKS},
        }

    def test_pending_template_exits_nonzero(self):
        script = pathlib.Path(__file__).with_name("check_aws_walk.py")
        result = subprocess.run([sys.executable, str(script),
            str(script.with_name("aws-walk-template.json"))], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("pending or failed", result.stdout)

    def test_complete_manifest(self):
        self.assertEqual(check(self.receipt, self.root), [])

    def test_missing_failed_or_pending_check_refused(self):
        del self.receipt['checks'][CHECKS[0]]
        self.assertTrue(check(self.receipt, self.root))
        for status in ('pending', 'fail', 'skip', True):
            self.receipt['checks'][CHECKS[0]] = {'status': status}
            self.assertTrue(check(self.receipt, self.root))

    def test_modified_empty_missing_artifacts_refused(self):
        for value in (b'changed', b''):
            (self.root / 'proof.txt').write_bytes(value)
            self.assertTrue(check(self.receipt, self.root))
        (self.root / 'proof.txt').unlink()
        self.assertTrue(check(self.receipt, self.root))

    def test_outside_root_and_symlink_escape_refused(self):
        with tempfile.TemporaryDirectory() as other:
            outside = pathlib.Path(other) / 'secret.txt'
            outside.write_text('must not echo this')
            (self.root / 'link').symlink_to(outside)
            for path in (str(outside), '../secret.txt', 'link'):
                self.receipt['checks'][CHECKS[0]]['artifacts'][0]['path'] = path
                errors = check(self.receipt, self.root)
                self.assertTrue(errors)
                self.assertNotIn('secret', str(errors))

    def test_synthetic_evidence_and_missing_provenance_refused(self):
        self.receipt['environment'] = 'local-emulator'
        self.assertTrue(check(self.receipt, self.root))
        self.receipt['environment'] = 'live-aws'
        self.receipt['source_sha'] = 'branch-name'
        self.assertTrue(check(self.receipt, self.root))

    def test_malformed_receipts_refused(self):
        for document in (None, [], {}, {'checks': []}):
            self.assertTrue(check(document, self.root))


if __name__ == '__main__':
    unittest.main()
