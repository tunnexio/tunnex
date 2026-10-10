import datetime, importlib.util, json, os, pathlib, tempfile, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('remediation',pathlib.Path(__file__).with_name('remediate-disabled15-owned.py'))
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class EvidenceTests(unittest.TestCase):
    def test_normal_owner_revision_and_freshness(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        v={'observed_at':now.isoformat(),'connection':{'id':m.CONNECTION,'desired_revision':15,'desired_intent':'disabled','cleanup_state':'pending'}}
        self.assertEqual(m.normal(json.dumps(v).encode()),v)
        for key,value in [('id','foreign'),('desired_revision',14),('desired_intent','enabled'),('cleanup_state','retained_guard')]:
            changed=json.loads(json.dumps(v)); changed['connection'][key]=value
            with self.assertRaises(ValueError): m.normal(json.dumps(changed).encode())
        for delta in [-61,5]:
            changed=dict(v,observed_at=(now+datetime.timedelta(seconds=delta)).isoformat())
            with self.assertRaises(ValueError): m.normal(json.dumps(changed).encode())
    def test_exclusive_evidence_keeps_prior_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'evidence'; m.save(p,b'original')
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError): m.save(p,b'changed')
            self.assertEqual(p.read_bytes(),b'original')
            link=pathlib.Path(d)/'link'; link.symlink_to(p)
            with self.assertRaises(OSError): m.save(link,b'changed')
    def test_proc_comm_parentheses_and_start_ticks(self):
        fields=['T','42']+['0']*17+['12345']
        with patch.object(pathlib.Path,'read_text',return_value='7 (child ) name) '+' '.join(fields)):
            self.assertEqual(m.proc(7),('T',42,12345))
        with patch.object(pathlib.Path,'read_text',return_value='7 (child) T 42'):
            with self.assertRaises(ValueError): m.proc(7)
    def test_frozen_baseline_failure_still_resumes_exact_container(self):
        import types, sys
        cid='a'*64; binary=b'helper'; exe=b'node'
        container={'Id':cid,'Image':'sha256:image','State':{'Pid':55,'StartedAt':'start'}}
        read=json.dumps({'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'connection':{'id':m.CONNECTION,'desired_revision':15,'desired_intent':'disabled','cleanup_state':'pending'}}).encode()
        calls=[]
        def call(args,timeout=10):
            calls.append(args)
            return read if args[0]=='sudo' else b''
        def metadata(path):
            return types.SimpleNamespace(st_uid=1000 if str(path)=='/private/.runtime' else 0,st_mode=(0o40700 if str(path)=='/private/.runtime' else 0o100644))
        def private(path,*args):
            if str(path)=='/helper': return binary,None
            raise ValueError('injected frozen journal refusal')
        argv=['wrapper','--container',cid,'--private-root','/private/.runtime','--lifecycle-helper','/api.py','--helper-binary','/helper','--helper-sha256',m.digest(binary),'--evidence-dir','/private/.runtime/evidence','--expected-cid',cid,'--expected-image-id','sha256:image','--expected-node-sha256',m.digest(exe)]
        with patch.object(sys,'argv',argv),patch.object(m.os,'geteuid',return_value=0),patch.object(m.socket,'gethostname',return_value='tunnex-peer'),patch.object(m,'private_read',side_effect=private),patch.object(m,'inspect',return_value=container),patch.object(m,'proc',return_value=('T',1,7)),patch.object(m.os,'readlink',return_value='net:[99]'),patch.object(pathlib.Path,'read_bytes',return_value=exe),patch.object(pathlib.Path,'resolve',lambda p:p),patch.object(pathlib.Path,'lstat',metadata),patch.object(pathlib.Path,'mkdir'),patch.object(m,'save'),patch.object(m,'command',side_effect=call),patch('builtins.print'):
            self.assertEqual(m.main(),1)
        self.assertIn(['docker','kill','--signal','STOP',cid],calls)
        self.assertEqual(calls[-1],['docker','kill','--signal','CONT',cid])
if __name__=='__main__': unittest.main()
