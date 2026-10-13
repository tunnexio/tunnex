import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('harness',Path(__file__).with_name('run-disconnected-fqdn-expiry.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Harness(unittest.TestCase):
 def fixture(self,root):
  root.chmod(0o700);binary=root/'test';raw=bytearray(64);raw[:6]=b'\x7fELF\x02\x01';raw[18:20]=(183).to_bytes(2,'little');binary.write_bytes(raw);binary.chmod(0o600)
  return binary,hashlib.sha256(binary.read_bytes()).hexdigest(),root/'reserved.json'
 def test_default_never_calls_docker(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(m,'docker') as d:
   values=self.fixture(Path(folder).resolve());self.assertEqual(m.run(*values)['stage'],'source_preflight_only');d.assert_not_called()
 def test_bad_hash_and_public_input_refuse(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(m,'docker') as d:
   b,sha,r=self.fixture(Path(folder).resolve())
   with self.assertRaises(ValueError):m.run(b,'0'*64,r,True)
   b.chmod(0o644)
   with self.assertRaises(ValueError):m.run(b,sha,r,True)
   d.assert_not_called()
 def test_unknown_create_reservation_prevents_replay(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(m,'docker',side_effect=m.subprocess.TimeoutExpired('docker',15)) as d:
   values=self.fixture(Path(folder).resolve())
   with self.assertRaises(m.subprocess.TimeoutExpired):m.run(*values,True)
   self.assertTrue(values[2].exists());self.assertEqual(d.call_count,1)
   with self.assertRaises(ValueError):m.run(*values,True)
   self.assertEqual(d.call_count,1)
 def test_foreign_image_inspect_refuses_before_start(self):
  import json
  with tempfile.TemporaryDirectory() as folder:
   values=self.fixture(Path(folder).resolve());cid='a'*64
   with patch.object(m,'docker',side_effect=[cid.encode(),json.dumps([{'Id':cid,'Image':'foreign','Name':'/wrong','HostConfig':{}}]).encode()]) as d:
    with self.assertRaises(ValueError):m.run(*values,True)
    self.assertEqual(d.call_count,2)
    args=d.call_args_list[0].args[0]
    self.assertIn('--network',args);self.assertIn('none',args);self.assertIn('--cap-drop',args);self.assertIn('--read-only',args)
    self.assertNotIn('--privileged',args);self.assertNotIn('--volume',args);self.assertNotIn('--rm',args)
 def test_complete_intent_and_created_identity_preserved_before_start(self):
  import json
  def inspect(cid,name):return {'Id':cid,'Image':m.IMAGE,'Name':'/'+name,'Mounts':[],'HostConfig':{'NetworkMode':'none','Privileged':False,'ReadonlyRootfs':True,'CapAdd':['CAP_NET_ADMIN'],'CapDrop':['ALL'],'Binds':None,'RestartPolicy':{'Name':'no'},'Memory':256*1024*1024,'PidsLimit':64,'Tmpfs':{'/tmp':'rw,nosuid,nodev,exec,size=128m'},'SecurityOpt':['no-new-privileges']},'Config':{'Entrypoint':['/bin/sh'],'Cmd':['-c','sleep 300'],'Labels':{'tunnex.qualification':'azure-fqdn-expiry'}}}
  for field in ('Memory','PidsLimit','Tmpfs','SecurityOpt','Entrypoint','Cmd','label','cap_legacy','cap_extra','tmpfs_noexec','tmpfs_default','tmpfs_extra','valid'):
   with self.subTest(field=field),tempfile.TemporaryDirectory() as folder:
    values=self.fixture(Path(folder).resolve());cid='a'*64
    def command(args,*unused,**kw):
     if args[0]=='create':
      self.assertEqual(args[args.index('--tmpfs')+1],'/tmp:rw,nosuid,nodev,exec,size=128m');return cid.encode()
     created=values[2].with_name(values[2].name+'.created.json')
     self.assertEqual(json.loads(created.read_text())['container_id'],cid)
     name=json.loads(values[2].read_text())['name'];data=inspect(cid,name)
     if args[0]=='inspect':
      if field in ('Memory','PidsLimit','Tmpfs','SecurityOpt'):data['HostConfig'][field]=None
      elif field in ('Entrypoint','Cmd'):data['Config'][field]=None
      elif field=='label':data['Config']['Labels']={}
      elif field=='tmpfs_noexec':data['HostConfig']['Tmpfs']={'/tmp':'rw,nosuid,nodev,noexec,size=128m'}
      elif field=='tmpfs_default':data['HostConfig']['Tmpfs']={'/tmp':'rw,nosuid,nodev,size=128m'}
      elif field=='tmpfs_extra':data['HostConfig']['Tmpfs']={'/tmp':'rw,nosuid,nodev,exec,size=128m','/other':'exec'}
      elif field=='cap_legacy':data['HostConfig']['CapAdd']=['NET_ADMIN']
      elif field=='cap_extra':data['HostConfig']['CapAdd']=['CAP_NET_ADMIN','CAP_SYS_ADMIN']
      return json.dumps([data]).encode()
     self.assertEqual(field,'valid');self.assertEqual(args,['start',cid]);raise m.subprocess.TimeoutExpired('docker',15)
    with patch.object(m,'docker',side_effect=command) as d:
     with self.assertRaises(m.subprocess.TimeoutExpired if field=='valid' else ValueError):m.run(*values,True)
     self.assertEqual(d.call_count,3 if field=='valid' else 2)
     self.assertTrue(values[2].with_name(values[2].name+'.created.json').exists())
 def test_directory_durability_failure_keeps_record_and_refuses_replay(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(m,'docker') as d:
   values=self.fixture(Path(folder).resolve());original=m.os.fsync;calls=[]
   def sync(fd):
    calls.append(fd)
    if len(calls)==2:raise OSError('fixture directory sync failure')
    return original(fd)
   with patch.object(m.os,'fsync',side_effect=sync):
    with self.assertRaises(OSError):m.run(*values,True)
   self.assertTrue(values[2].exists());d.assert_not_called()
   with self.assertRaises(ValueError):m.run(*values,True)
 def test_native_failure_and_timeout_output_preserved_before_refusal(self):
  import base64,json
  for timeout in (False,True):
   with self.subTest(timeout=timeout),tempfile.TemporaryDirectory() as folder:
    values=self.fixture(Path(folder).resolve());cid='a'*64
    if timeout:result=patch.object(m.subprocess,'run',side_effect=m.subprocess.TimeoutExpired('docker',25,output=b'partial native output',stderr=b'partial error'))
    else:result=patch.object(m.subprocess,'run',return_value=m.subprocess.CompletedProcess([],1,stdout=b'actual failed test',stderr=b'actual stderr'))
    with result:
     with self.assertRaises(ValueError):m.component(cid,values[2])
    receipt=values[2].with_name(values[2].name+'.component.json');data=json.loads(receipt.read_bytes())
    self.assertEqual(data['timed_out'],timeout);self.assertEqual(data['returncode'],None if timeout else 1)
    self.assertEqual(base64.b64decode(data['stdout_base64']),b'partial native output' if timeout else b'actual failed test')
    self.assertEqual(receipt.stat().st_mode&0o777,0o600)
 def test_native_success_receipt_hash_and_no_skip(self):
  import json
  with tempfile.TemporaryDirectory() as folder:
   values=self.fixture(Path(folder).resolve());cid='a'*64;output=('--- PASS: '+m.TEST+' (3.20s)\nPASS\n').encode()
   with patch.object(m.subprocess,'run',return_value=m.subprocess.CompletedProcess([],0,stdout=output,stderr=b'')) as call:
    path,sha=m.component(cid,values[2]);self.assertEqual(sha,hashlib.sha256(path.read_bytes()).hexdigest());self.assertEqual(call.call_args.kwargs['timeout'],25)
   values2=values[2].with_name('skip')
   with patch.object(m.subprocess,'run',return_value=m.subprocess.CompletedProcess([],0,stdout=b'SKIP\nPASS\n',stderr=b'')):
    with self.assertRaises(ValueError):m.component(cid,values2)
   self.assertTrue(values2.with_name('skip.component.json').exists())
 def test_plain_full_native_absence_exact_empty_only(self):
  cid='a'*64
  with patch.object(m,'docker',return_value=b'') as d:
   m.native_absence(cid)
   self.assertEqual([call.args[0] for call in d.call_args_list],[['exec',cid,'/sbin/ip','xfrm','state','list'],['exec',cid,'/sbin/ip','xfrm','policy','list']])
  for raw in (b'\n',b'[]',b'fixture nonempty native listing'):
   with self.subTest(kind='nonempty'),patch.object(m,'docker',return_value=raw):
    with self.assertRaises(ValueError):m.native_absence(cid)
  with patch.object(m,'docker',side_effect=ValueError('command exit nonzero')):
   with self.assertRaises(ValueError):m.native_absence(cid)
 def test_symlink_parent_refuses_before_docker(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(m,'docker') as d:
   root=Path(folder).resolve();b,sha,r=self.fixture(root);link=root/'link';link.symlink_to(root,target_is_directory=True)
   with self.assertRaises(ValueError):m.run(b,sha,link/'state',True)
   d.assert_not_called()
if __name__=='__main__':unittest.main()
