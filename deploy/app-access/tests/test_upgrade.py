"""Focused same-schema image replacement guards; no live stores or containers."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('app_upgrade',Path(__file__).parents[1]/'upgrade.py')
upgrade=importlib.util.module_from_spec(spec);spec.loader.exec_module(upgrade)
AUTH={'schema_version':173,'supported_schema_version':173,'generation':'11111111-1111-4111-8111-111111111111','authority_version':1,'recovery_completed':True}

class AuthorityAdmission(unittest.TestCase):
 def test_exact_clean_same_schema_only(self):
  upgrade.validate_preflight(AUTH,dict(AUTH))
  for key,value in [('schema_version',172),('supported_schema_version',174),('generation','00000000-0000-0000-0000-000000000000'),('authority_version',0),('recovery_completed',False)]:
   with self.subTest(key=key),self.assertRaises(upgrade.restore.RestoreError):upgrade.validate_preflight(AUTH,dict(AUTH,**{key:value}))
  with self.assertRaises(upgrade.restore.RestoreError):upgrade.validate_preflight(AUTH,dict(AUTH,authority_version=2))
 def test_image_preflight_only_exact_marker_writable_and_ports_removed(self):
  with tempfile.TemporaryDirectory() as directory:
   runner=object.__new__(upgrade.UpgradeRunner);runner.frozen_directory=type('Dir',(),{'name':directory})();runner.compose=['docker','compose','-f','old.json']
   config={'services':{'api':{'ports':['8080:8080'],'image':'sha256:test','volumes':[{'target':str(Path(upgrade.restore.BARRIER).parent),'source':'marker','type':'volume','read_only':True},{'target':'/var/lib/tunnex/secrets','source':'secret','type':'volume','read_only':True}]}},'volumes':{}}
   def command(args):
    saved=json.loads(Path(args[3]).read_text());api=saved['services']['api'];self.assertNotIn('ports',api);self.assertFalse(api['volumes'][0]['read_only']);self.assertTrue(api['volumes'][1]['read_only']);self.assertEqual(args[-4:],['--entrypoint','/usr/local/bin/backupctl','api','app-preflight']);return json.dumps(AUTH).encode()
   with patch.object(upgrade.restore,'command',command):self.assertEqual(runner.preflight(config),AUTH)
   self.assertTrue(config['services']['api']['volumes'][0]['read_only'])
   config['services']['api']['volumes'].append({'target':'/usr/local/bin','type':'bind','source':'foreign'})
   with self.assertRaises(upgrade.restore.RestoreError):runner.preflight(config)
 def test_signed_ref_must_exist_as_cached_matching_platform_repo_digest(self):
  with tempfile.TemporaryDirectory() as directory:
   runner=object.__new__(upgrade.UpgradeRunner);runner.frozen_directory=type('Dir',(),{'name':directory})();runner.docker=['docker','--host','unix:///fixture.sock']
   descriptor=Path(directory)/'source';descriptor.write_text('{}')
   verifier=Path(directory)/'verifier';verifier.write_text('test')
   pins='TUNNEX_API_IMAGE=ghcr.io/tunnexio/tunnex-api@sha256:'+('a'*64)+'\nTUNNEX_APP_PROXY_IMAGE=ghcr.io/tunnexio/tunnex-app-proxy@sha256:'+('b'*64)+'\n'
   with patch.object(upgrade.restore,'command',side_effect=[pins.encode(),json.dumps([{'Id':'sha256:cached','Architecture':'arm64','RepoDigests':[]}]).encode()]):
    with self.assertRaises(upgrade.restore.RestoreError):runner.verified_images(descriptor,verifier,'trusted','arm64')

class NetworkAdmission(unittest.TestCase):
 def test_reviewed_network_and_identity_are_required(self):
  runner=object.__new__(upgrade.UpgradeRunner);runner.docker=['docker'];runner.project='owned';runner.network_identities={}
  config={'services':{'api':{'image':'image','environment':{},'volumes':[],'networks':{'default':None}}},'networks':{'default':{'name':'owned_default'}}}
  actual={'Image':'image-id','Config':{'Env':[]},'Mounts':[],'NetworkSettings':{'Networks':{'foreign_default':{'NetworkID':'foreign'}}}}
  def check(value):
   with patch.object(upgrade.restore,'command',side_effect=[json.dumps([value]).encode(),json.dumps([{'Id':'image-id'}]).encode(),json.dumps([{'Name':'owned_default','Id':'first','Labels':{'com.docker.compose.project':'owned'}}]).encode()]):runner.validate_service(config,[('a','api')],'api')
  with self.assertRaises(upgrade.restore.RestoreError):check(actual)
  actual['NetworkSettings']['Networks']={'owned_default':{'NetworkID':'first'}};check(actual)
  actual['NetworkSettings']['Networks']={'owned_default':{'NetworkID':'replacement'}}
  with self.assertRaises(upgrade.restore.RestoreError):check(actual)
  actual['NetworkSettings']['Networks']={'owned_default':{'NetworkID':''}};check(actual)
  actual['State']={'Running':True}
  with self.assertRaises(upgrade.restore.RestoreError):check(actual)

class PortAdmission(unittest.TestCase):
 def test_unreviewed_listener_refused_before_network_or_mutation(self):
  runner=object.__new__(upgrade.UpgradeRunner);runner.docker=['docker']
  config={'services':{'api':{'image':'image','environment':{},'volumes':[]}}}
  actual={'Image':'image-id','Config':{'Env':[]},'Mounts':[], 'HostConfig':{'PortBindings':{'8445/tcp':[{'HostIp':'0.0.0.0','HostPort':'8445'}]}}}
  with patch.object(upgrade.restore,'command',side_effect=[json.dumps([actual]).encode(),json.dumps([{'Id':'image-id'}]).encode()]) as command:
   with self.assertRaises(upgrade.restore.RestoreError):runner.validate_service(config,[('a','api')],'api')
   self.assertEqual(command.call_count,2)
 def test_reviewed_binding_and_host_scope_preserved(self):
  runner=object.__new__(upgrade.UpgradeRunner);runner.docker=['docker'];runner.project='owned';runner.network_identities={}
  config={'services':{'api':{'image':'image','environment':{},'volumes':[],'ports':[{'target':8443,'published':'443','host_ip':'127.0.0.1','protocol':'tcp'}]}},'networks':{'default':{'name':'owned_default'}}}
  actual={'Image':'image-id','Config':{'Env':[]},'Mounts':[], 'HostConfig':{'PortBindings':{'8443/tcp':[{'HostIp':'127.0.0.1','HostPort':'443'}]}},'NetworkSettings':{'Networks':{'owned_default':{'NetworkID':'first'}}}}
  with patch.object(upgrade.restore,'command',side_effect=[json.dumps([actual]).encode(),json.dumps([{'Id':'image-id'}]).encode(),json.dumps([{'Name':'owned_default','Id':'first','Labels':{'com.docker.compose.project':'owned'}}]).encode()]):runner.validate_service(config,[('a','api')],'api')
  actual['HostConfig']['PortBindings']['8443/tcp'][0]['HostIp']='0.0.0.0'
  with patch.object(upgrade.restore,'command',side_effect=[json.dumps([actual]).encode(),json.dumps([{'Id':'image-id'}]).encode()]):
   with self.assertRaises(upgrade.restore.RestoreError):runner.validate_service(config,[('a','api')],'api')

class ReviewedPlan(unittest.TestCase):
 def flow(self, target=AUTH, expected='wrong'):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
  path=Path(temporary.name)/'compose.json';path.write_text(json.dumps({'services':{'api':{'image':'old-a'},'app-proxy':{'image':'old-p'}}}))
  runner=object.__new__(upgrade.UpgradeRunner);runner.frozen_directory=temporary;runner.compose=['docker','compose','-f',str(path)];runner.docker=['docker','--host','unix:///fixture.sock'];runner.network_identities={}
  with patch.object(runner,'participants',return_value=[('a','api'),('p','app-proxy')]),patch.object(runner,'validate_service'),patch.object(runner,'verified_images',return_value=({'api':'new-a','app-proxy':'new-p'},'signed-hash')),patch.object(runner,'preflight',side_effect=[dict(AUTH),dict(target)]),patch.object(upgrade.restore,'command') as command:
   with self.assertRaises(upgrade.restore.RestoreError):runner.replace('release','verifier','key','arm64',expected)
   command.assert_not_called()
 def test_changed_reviewed_plan_never_stops(self):self.flow()
 def test_target_wrong_schema_ceiling_never_stops(self):self.flow(dict(AUTH,supported_schema_version=174))
 def test_foreign_participant_refusal_precedes_any_mutation(self):
  runner=object.__new__(upgrade.UpgradeRunner)
  with patch.object(runner,'participants',side_effect=upgrade.restore.RestoreError('foreign checkout')),patch.object(upgrade.restore,'command') as command:
   with self.assertRaises(upgrade.restore.RestoreError):runner.replace('release','verifier','key','arm64','plan')
   command.assert_not_called()

if __name__=='__main__':unittest.main()
