import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from channel_guard import validate, read_ref

BASE = {'version': '0.1.99', 'tag': 'v0.1.99', 'source_sha': 'a' * 40}

def release(version, sha='a' * 40):
    return {'version': version, 'tag': 'v' + version, 'source_sha': sha}

class ChannelGuardTests(unittest.TestCase):
    def test_bootstrap_and_identical_retry(self):
        validate(BASE)
        validate(copy.deepcopy(BASE), BASE)

    def test_numeric_upgrade(self):
        validate(release('0.1.100', 'b' * 40), BASE)

    def test_rollback_refused(self):
        with self.assertRaisesRegex(ValueError, 'rollback'):
            validate(BASE, release('0.1.100'))

    def test_same_version_new_source_refused(self):
        with self.assertRaisesRegex(ValueError, 'different source'):
            validate(release('0.1.99', 'b' * 40), BASE)

    def test_invalid_identity_refused(self):
        for candidate in [release('0.1.99', 'not-a-sha'), dict(BASE, tag='v0.1.98')]:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate(candidate)

    def test_ref_lookup_errors_are_not_bootstrap(self):
        with patch('channel_guard.subprocess.check_output', side_effect=subprocess.CalledProcessError(128, 'git')):
            with self.assertRaises(subprocess.CalledProcessError):
                read_ref('missing-ref')

    def test_arch_downloads_are_unique_and_package_path_matches(self):
        # Run the real generator with release/network operations stubbed; inspect
        # the generated shell's evaluated sources across versions/architectures.
        import os
        import runpy
        generator = Path(__file__).with_name('channels.py').resolve()
        with tempfile.TemporaryDirectory() as temp:
            prior = os.getcwd()
            os.chdir(temp)
            try:
                def download(info, _):
                    info['binary_sha256'] = {'tnx-linux-amd64': 'a'*64, 'tnx-linux-arm64': 'b'*64}
                with patch('upstream.resolve', return_value=release('0.1.99')), patch('upstream.download', side_effect=download):
                    runpy.run_path(str(generator), run_name='__main__')
                script = 'source aur/tunnex-cli-bin/PKGBUILD; printf "%s\\n" "${source_x86_64[0]}" "${source_aarch64[0]}"; declare -f package'
                result = subprocess.check_output(['bash', '-c', script], text=True)
                self.assertIn('tunnex-0.1.99-x86_64::', result)
                self.assertIn('tunnex-0.1.99-aarch64::', result)
                self.assertIn('tunnex-${pkgver}-${CARCH}', result)
            finally:
                os.chdir(prior)

if __name__ == '__main__':
    unittest.main()
