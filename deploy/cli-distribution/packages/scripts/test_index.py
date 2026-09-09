import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from index import verify, apk_destination

class RepositoryBoundaryTests(unittest.TestCase):
    def test_unlisted_package_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder/'legitimate.deb').write_bytes(b'package')
            digest = hashlib.sha256(b'package').hexdigest()
            (folder/'SHA256SUMS').write_text(f'{digest}  legitimate.deb\n')
            (folder/'SHA256SUMS.asc').write_text('signature is checked by the native smoke test')
            with patch('index.subprocess.run'):
                self.assertEqual(verify(folder), [folder/'legitimate.deb'])
                (folder/'unlisted.deb').write_bytes(b'extra')
                with self.assertRaisesRegex(ValueError, 'differ from the signed manifest'):
                    verify(folder)

    def test_duplicate_and_traversal_refused(self):
        for name in ['../outside.deb', '/outside.deb', '.hidden.deb']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                folder = Path(temp)
                (folder/'SHA256SUMS').write_text('0'*64 + '  ' + name + '\n')
                with patch('index.subprocess.run'), self.assertRaisesRegex(ValueError, 'Invalid signed checksum'):
                    verify(folder)

    def test_apk_destination_reads_metadata_across_gzip_members(self):
        def stream(name, data):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w') as archive:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            return gzip.compress(output.getvalue())
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp)/'tunnex-cli_0.1.25_arm64.apk'
            package.write_bytes(stream('.SIGN.RSA.tunnex.rsa.pub', b'signature') +
                                stream('.PKGINFO', b'pkgname = tunnex-cli\npkgver = 0.1.25-r1\narch = aarch64\n'))
            self.assertEqual(str(apk_destination(package)), 'alpine/aarch64/tunnex-cli-0.1.25-r1.apk')

if __name__ == '__main__':
    unittest.main()
