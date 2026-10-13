import importlib.util, pathlib, tempfile, unittest, os, stat, hashlib
spec=importlib.util.spec_from_file_location('capture_under_test',pathlib.Path(__file__).with_name('capture.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class CaptureSourceTests(unittest.TestCase):
    def test_remote_static_and_unchanged_link_fields(self):
        compile(c.REMOTE,'bounded-remote','exec')
        self.assertIn("ex('/sbin/ip','-j','-d','link','show')",c.REMOTE)
        self.assertNotIn("'-s'",c.REMOTE)
        self.assertNotIn('stats',c.REMOTE)
        self.assertIn('links!=after_links',c.REMOTE)
        self.assertIn("if n1!='net:[4026531840]' or h1!=n1",c.REMOTE)
    def test_transport_pin(self):
        self.assertEqual(hashlib.sha256(c.DEPENDENCY.read_bytes()).hexdigest(),c.DEPENDENCY_SHA)
    def test_exclusive_private_reservation(self):
        old=c.ROOT
        with tempfile.TemporaryDirectory() as d:
            c.ROOT=pathlib.Path(d)/'evidence'
            a,b=c.reserve('before-v1.json');os.close(a);os.close(b)
            self.assertEqual(stat.S_IMODE(c.ROOT.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((c.ROOT/'before-v1.json').stat().st_mode),0o600)
            with self.assertRaises(FileExistsError):c.reserve('before-v1.json')
            for name in ['../escape.json','bad/name.json','UPPER.json','bad.json;echo']:
                with self.assertRaises(ValueError):c.reserve(name)
        c.ROOT=old
    def test_symlink_directory_refused(self):
        old=c.ROOT
        with tempfile.TemporaryDirectory() as d:
            target=pathlib.Path(d)/'target';target.mkdir(mode=0o700)
            c.ROOT=pathlib.Path(d)/'link';c.ROOT.symlink_to(target,target_is_directory=True)
            with self.assertRaises(ValueError):c.reserve('before.json')
        c.ROOT=old
if __name__=='__main__':unittest.main()
