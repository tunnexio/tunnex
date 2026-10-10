import base64,hashlib,json,subprocess,sys,tempfile,importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('recovery',pathlib.Path(__file__).with_name('gcp-owned-client-hostkey-recovery.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Preservation(unittest.TestCase):
    def test_original_exit_preserved_child_and_publication_runs_after(self):
        original='#!/bin/bash\nset -e\necho fixture\nexit 23\n'
        items=[{'key':'ssh-keys','value':'unchanged-private-fixture'},{'key':'startup-script','value':original},{'key':'other','value':'keep\nbytes'}]
        before=[dict(x) for x in items];wrapped=m.startup(items,b'public-helper-source','11111111-1111-4111-8111-111111111111')
        self.assertEqual(items,before);self.assertEqual(wrapped[0],items[0]);self.assertEqual(wrapped[2],items[2])
        sh_items=[{'key':'startup-script','value':'#!/bin/sh\nexit 23\n'}]
        self.assertIn("subprocess.run(['/bin/sh']+[str(original)])",m.startup(sh_items,b'helper','11111111-1111-4111-8111-111111111111')[0]['value'])
        driver=wrapped[1]['value'];self.assertIn(repr(base64.b64encode(original.encode()).decode()),driver)
        self.assertLess(driver.index('original_status=subprocess.run'),driver.index('publication=subprocess.run'))
        self.assertIn('original_status if original_status else publication.returncode',driver)
    def test_readonly_original_noexec_model_runs_publisher_and_preserves_exit(self):
        original='#!/bin/sh\nexit 23\n';helper=b"print('PUBLIC_TEST_MARKER')\n"
        wrapped=m.startup([{'key':'startup-script','value':original}],helper,'11111111-1111-4111-8111-111111111111')[0]['value']
        driver=wrapped.split("TUNNEX_PUBLIC_HOSTKEY_DRIVER'\n",1)[1].rsplit('TUNNEX_PUBLIC_HOSTKEY_DRIVER',1)[0]
        with tempfile.TemporaryDirectory() as d:
            modeled=driver.replace("dir='/run'",'dir='+repr(d)).replace('original.chmod(0o700)','original.chmod(0o600)').replace("'/usr/bin/python3'",repr(sys.executable))
            result=subprocess.run([sys.executable,'-c',modeled],capture_output=True,text=True)
            self.assertEqual(result.returncode,23);self.assertIn('PUBLIC_TEST_MARKER',result.stdout)
            old=modeled.replace("original_status=subprocess.run(['/bin/sh']+[str(original)]).returncode","original_status=subprocess.run([str(original)]).returncode").replace(' except OSError:\n  original_status=126',' except OSError:\n  raise')
            red=subprocess.run([sys.executable,'-c',old],capture_output=True,text=True)
            self.assertNotEqual(red.returncode,23);self.assertIn('PermissionError',red.stderr);self.assertNotIn('PUBLIC_TEST_MARKER',red.stdout)
            missing=modeled.replace("original_status=subprocess.run(['/bin/sh']+[str(original)]).returncode","original_status=subprocess.run(['/missing-original-interpreter',str(original)]).returncode")
            result=subprocess.run([sys.executable,'-c',missing],capture_output=True,text=True)
            self.assertEqual(result.returncode,126);self.assertIn('PUBLIC_TEST_MARKER',result.stdout)
    def test_cas_stale_fingerprint_and_split_authenticated_marker(self):
        before={'fingerprint':'original','items':[{'key':'startup-script','value':'original'}]}
        self.assertEqual(m.cas_body(before,dict(before),[]),{'fingerprint':'original','items':[]})
        with self.assertRaises(ValueError):m.cas_body(before,dict(before,fingerprint='other'),[])
        raw=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+bytes(range(32));attempt='11111111-1111-4111-8111-111111111111'
        marker={'marker':'TUNNEX_OWNED_PUBLIC_HOSTKEY_V1','instance_id':m.ID,'attempt':attempt,'boot_id':'22222222-2222-4222-8222-222222222222','public_key':'ssh-ed25519 '+base64.b64encode(raw).decode(),'fingerprint':'SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')}
        encoded=json.dumps(marker,separators=(',',':'))+'\n';lines,carry=m.serial_lines('',encoded[:30]);self.assertEqual(lines,[])
        lines,carry=m.serial_lines(carry,encoded[30:]);self.assertEqual(carry,'');self.assertEqual(m.parse_marker(lines[0],attempt),marker)
        with self.assertRaises(ValueError):m.parse_marker(encoded.replace('"instance_id":','"instance_id":"foreign","instance_id":'),attempt)
        bad=dict(marker,public_key='ssh-ed25519 '+base64.b64encode(bytes(51)).decode())
        with self.assertRaises(ValueError):m.parse_marker(json.dumps(bad),attempt)
    def test_url_duplicate_and_wrong_identity_refuse(self):
        with self.assertRaises(ValueError):m.startup([{'key':'startup-script-url','value':'https://example.invalid/script'}],b'helper','attempt')
        with self.assertRaises(ValueError):m.metadata_items({'items':[{'key':'a','value':'1'},{'key':'a','value':'2'}]})
        with self.assertRaises(ValueError):m.identity({'id':m.ID,'name':m.NAME,'status':'RUNNING','networkInterfaces':[{'networkIP':m.IP,'network':'https://compute.googleapis.com/compute/v1/projects/foreign/global/networks/tn-gcps2s-20261010-peer'}]})
if __name__=='__main__':unittest.main()
