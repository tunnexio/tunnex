import importlib.util,unittest,tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('helper',str(Path(__file__).resolve().parents[2]/'apps/web/public/tunnex-browser-ssh.py'))
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
ORG='01a10b8b-648e-7268-a28c-4180cd72761a';SERVER='01a10b8f-33e9-7d2d-87cd-11794af2c4be'
class Safety(unittest.TestCase):
 def test_exact_identity(self):
  with patch.object(h.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1000,pw_shell='/bin/bash')):
   self.assertEqual(h.identity(ORG,SERVER,'ubuntu'),f'tunnex:{ORG}:{SERVER}:ubuntu')
 def test_reject_injection_and_invalid_ids(self):
  for account in ('ubuntu;id','../root','*','ubuntu\nroot',"ubuntu'",'-option'):
   with self.assertRaises(ValueError):h.identity(ORG,SERVER,account)
  with self.assertRaises(ValueError):h.identity('wrong',SERVER,'ubuntu')
 def test_reject_root_and_non_login(self):
  for uid,shell in ((0,'/bin/bash'),(1000,'/usr/sbin/nologin'),(1000,'/bin/false')):
   with patch.object(h.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=uid,pw_shell=shell)):
    with self.assertRaises(ValueError):h.identity(ORG,SERVER,'ubuntu')
 def test_listener_restricts_access(self):
  s=h.render({'port':2222,'accounts':['ubuntu','fixture']})
  for line in ('AllowUsers fixture ubuntu','PasswordAuthentication no','AuthorizedKeysFile none','PermitRootLogin no','AllowTcpForwarding no','AllowAgentForwarding no','X11Forwarding no','PermitTunnel no','PermitUserRC no'):
   self.assertIn(line,s)
  self.assertNotIn('Port 22\n',s)
 def test_atomic_permissions(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'state';h.write(p,'original',0o600);h.write(p,'updated',0o600)
   self.assertEqual(p.read_text(),'updated');self.assertEqual(p.stat().st_mode&0o777,0o600)
 def test_refuse_unmanaged_removal(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'managed.json').write_text('{"owner":"someone-else"}');unit=root/'unit';unit.write_text('unrelated')
   with patch.object(h,'ROOT',root),patch.object(h,'UNIT',unit):
    with self.assertRaises(ValueError):h.load()
class Discovery(unittest.TestCase):
 def user(self,name,uid=1000,shell='/bin/bash'):
  return SimpleNamespace(pw_name=name,pw_uid=uid,pw_shell=shell)
 def test_excludes_root_system_nobody_and_non_login(self):
  for user in (self.user('root',0),self.user('service',999),self.user('nobody',65534),self.user('locked',1001,'/usr/sbin/nologin'),self.user('bad;name'),self.user('unknown',1001,'/custom/shell')):
   self.assertFalse(h.is_eligible(user,1000,{'/bin/bash','/usr/sbin/nologin'}))
  self.assertTrue(h.is_eligible(self.user('ubuntu'),1000,{'/bin/bash'}))
 def test_selected_accounts_are_existing_eligible_users(self):
  with patch.object(h,'eligible_accounts',return_value=['fixture','ubuntu']):
   self.assertEqual(h.selected_accounts(SimpleNamespace(all_login_users=True,accounts=None)),['fixture','ubuntu'])
   self.assertEqual(h.selected_accounts(SimpleNamespace(all_login_users=False,accounts='ubuntu,ubuntu')),['ubuntu'])
   with self.assertRaises(ValueError):h.selected_accounts(SimpleNamespace(all_login_users=False,accounts='ubuntu,root'))
 def test_limit_rejected_before_mutation(self):
  with patch.object(h,'eligible_accounts',return_value=['u'+str(i) for i in range(17)]):
   with self.assertRaises(ValueError):h.selected_accounts(SimpleNamespace(all_login_users=True,accounts=None))
 def test_conflicting_batch_principal_preserved(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'principals').mkdir();p=root/'principals'/'ubuntu';p.write_text('foreign-principal\n')
   meta={'org':ORG,'server':SERVER,'accounts':['ubuntu'],'ca_fingerprint':'SHA256:verified'}
   with patch.object(h,'ROOT',root),patch.object(h,'identity',return_value='expected-principal'),patch.object(h,'run',return_value=SimpleNamespace(stdout='256 SHA256:verified comment')):
    with self.assertRaises(ValueError):h.sync(meta,['ubuntu'])
   self.assertEqual(p.read_text(),'foreign-principal\n')
   self.assertFalse((root/'managed.json').exists())
class FailureCodes(unittest.TestCase):
 # SA-UX-3: a refusal prints one structured line with a fixed code; free text stays on stderr and in the journal.
 def refuse(self,error):
  import io,contextlib
  out,err=io.StringIO(),io.StringIO()
  with patch.object(h,'journal') as journal,contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):h.refuse(error)
  return out.getvalue(),err.getvalue(),journal.call_args[0][0]
 def test_coded_refusal_prints_only_the_code(self):
  out,err,logged=self.refuse(h.SetupError('setup_existing_setup','Existing setup found at /etc/x'))
  self.assertEqual(out,'TUNNEX SSH SETUP ERROR setup_existing_setup\n')
  self.assertIn('Existing setup found',err);self.assertNotIn('/etc/x',out)
  self.assertEqual(logged,'setup refused: setup_existing_setup')
 def test_uncoded_refusal_prints_no_line(self):
  out,err,logged=self.refuse(ValueError('something else'))
  self.assertEqual(out,'');self.assertIn('something else',err);self.assertEqual(logged,'setup refused: unclassified (ValueError)')
 def test_journal_never_raises(self):
  with patch.dict('sys.modules',{'syslog':None}):h.journal('x')
 def test_setup_error_is_a_value_error(self):
  self.assertIsInstance(h.SetupError('setup_not_root','Run with sudo'),ValueError)
 def test_foreign_or_missing_configuration_is_coded(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);unit=root/'unit';unit.write_text('unrelated')
   with patch.object(h,'ROOT',root),patch.object(h,'UNIT',unit):
    for content in (None,'not json','{"owner":"someone-else"}'):
     if content is not None:(root/'managed.json').write_text(content)
     with self.assertRaises(h.SetupError) as c:h.load()
     self.assertEqual(c.exception.code,'setup_foreign_setup')
 def test_missing_prerequisite_is_coded(self):
  with tempfile.TemporaryDirectory() as d:
   release=Path(d)/'os-release';release.write_text('ID=ubuntu\n')
   real=Path
   def fake(p,*a):
    if str(p)=='/etc/os-release':return release
    if str(p)=='/run/systemd/system':return real(d)
    return real(p,*a)
   with patch.object(h.sys,'platform','linux'),patch.object(h,'Path',side_effect=fake),patch.object(h.shutil,'which',side_effect=lambda c:None if c=='ip' else '/usr/bin/'+c):
    with self.assertRaises(h.SetupError) as c:h.platform_preflight()
   self.assertEqual(c.exception.code,'setup_missing_ip')
 def test_too_many_and_ineligible_accounts_are_coded(self):
  with patch.object(h,'eligible_accounts',return_value=['u'+str(i) for i in range(17)]):
   with self.assertRaises(h.SetupError) as c:h.selected_accounts(SimpleNamespace(all_login_users=True,accounts=None))
  self.assertEqual(c.exception.code,'setup_too_many_accounts')
  with patch.object(h,'eligible_accounts',return_value=['ubuntu']):
   with self.assertRaises(h.SetupError) as c:h.selected_accounts(SimpleNamespace(all_login_users=False,accounts='root'))
  self.assertEqual(c.exception.code,'setup_no_eligible_accounts')
if __name__=='__main__':unittest.main()
