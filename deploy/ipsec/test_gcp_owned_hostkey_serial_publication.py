import base64,importlib.util,pathlib,tempfile,unittest,unittest.mock,types,os
spec=importlib.util.spec_from_file_location('pub',pathlib.Path(__file__).with_name('gcp-owned-hostkey-serial-publication.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class PublicOnly(unittest.TestCase):
    def test_exact_existing_public_key_and_reject_alternate(self):
        raw=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+bytes(range(32))
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'public';p.write_text('ssh-ed25519 '+base64.b64encode(raw).decode()+' comment\n')
            real=os.fstat
            def root(fd):
                s=real(fd);return types.SimpleNamespace(st_mode=s.st_mode,st_uid=0,st_size=s.st_size,st_nlink=s.st_nlink,st_dev=s.st_dev,st_ino=s.st_ino,st_mtime_ns=s.st_mtime_ns,st_ctime_ns=s.st_ctime_ns)
            with unittest.mock.patch.object(m.os,'fstat',side_effect=root):
                key,fp=m.public_key(str(p));self.assertEqual(key.split()[0],'ssh-ed25519');self.assertTrue(fp.startswith('SHA256:'));self.assertNotIn('comment',key)
                p.chmod(0o666)
                with self.assertRaises(ValueError):m.public_key(str(p))
                p.chmod(0o600)
                hard=pathlib.Path(d)/'hard';os.link(p,hard)
                with self.assertRaises(ValueError):m.public_key(str(p))
                hard.unlink()
                p.write_text('ssh-rsa '+base64.b64encode(raw).decode())
                with self.assertRaises(ValueError):m.public_key(str(p))
                p.write_text('ssh-ed25519 '+base64.b64encode(raw+b'extra').decode())
                with self.assertRaises(ValueError):m.public_key(str(p))
            link=pathlib.Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):m.public_key(str(link))
if __name__=='__main__':unittest.main()
