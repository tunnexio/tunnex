import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("verify_source", Path(__file__).with_name("verify_source.py"))
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)

class SourceVerificationTest(unittest.TestCase):
    def archive(self, entries):
        target = self.root / "source.tar.gz"
        with tarfile.open(target, "w:gz") as archive:
            for name, kind, size in entries:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.size = size
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    item.linkname = "/tmp/escape"
                archive.addfile(item, io.BytesIO(b"x" * size) if kind == tarfile.REGTYPE else None)
        return target
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
    def test_changed_archive_refused_before_signature_or_extraction(self):
        path = self.root / "bad.tar.gz"
        path.write_bytes(b"untrusted bytes")
        with self.assertRaises(source.InvalidSource):
            source.verify_digest(path)
    def test_archive_layout(self):
        source.verify_archive_layout(self.archive([("strongswan-6.1.0/file", tarfile.REGTYPE, 1)]))
        for entries in [
            [("../escape",tarfile.REGTYPE,1)],
            [("/strongswan-6.1.0/file",tarfile.REGTYPE,1)],
            [("strongswan-6.1.0/../escape",tarfile.REGTYPE,1)],
            [("strongswan-6.1.0/link",tarfile.SYMTYPE,0)],
            [("strongswan-6.1.0/link",tarfile.LNKTYPE,0)],
            [("strongswan-6.1.0/device",tarfile.CHRTYPE,0)],
            [("strongswan-6.1.0/file",tarfile.REGTYPE,1)]*2,
        ]:
            with self.subTest(entries=entries), self.assertRaises(source.InvalidSource):
                source.verify_archive_layout(self.archive(entries))
    def test_signature_status_exact_identity(self):
        valid = "[GNUPG:] VALIDSIG " + source.FINGERPRINT + " 2026-01-01 1 0 4 0 1 10 00 " + source.FINGERPRINT + "\n"
        self.assertTrue(source.valid_signature_status(valid))
        for status in ["",valid.replace(source.FINGERPRINT,"0"*40),valid+valid,valid+"[GNUPG:] BADSIG wrong\n",valid+"[GNUPG:] EXPKEYSIG wrong\n"]:
            self.assertFalse(source.valid_signature_status(status))

if __name__ == "__main__":
    unittest.main()
