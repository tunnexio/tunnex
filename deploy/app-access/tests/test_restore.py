"""Restore orchestration fixtures; no Docker process or store mutation is run."""
import importlib.util
import json
import contextlib
import io
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('owned_restore', Path(__file__).parents[1] / 'restore.py')
restore = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(restore)
MARKER = '11111111-1111-4111-8111-111111111111'

class FlowRunner(restore.Runner):
    def __init__(self, directory, failure=None):
        super().__init__('owned', directory, [Path(directory)/'compose.yml'], '/fixture.sock')
        self.events=[]
        self.captured_archive=None
        self.failure=failure
    def participants(self):
        return [('a','api'),('p','app-proxy')]
    def require_stopped(self, participants):
        self.events.append('stopped')
        if self.failure=='stop': raise restore.RestoreError('not stopped')
    def tool(self,args,**kwargs):
        self.events.append(args[0])
        if self.failure==args[0]: raise restore.RestoreError('fixture refused')
        if args[0]=='app-restore-begin':return json.dumps({'id':MARKER}).encode()
        if args[0]=='app-recovery':return json.dumps({'confirmed':self.failure!='unconfirmed','generation':MARKER,'version':2}).encode()
        return b''

class RestoreFlow(unittest.TestCase):
    def setUp(self):
        socket_patch=patch.object(restore,"local_socket",return_value="/fixture.sock");socket_patch.start();self.addCleanup(socket_patch.stop)
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.dir=Path(self.tmp.name)
        for name in ['compose.yml','dump','manifest']: (self.dir/name).write_bytes(b'fixture')
    def run_flow(self,failure=None,apply=True,resume=None):
        runner=FlowRunner(self.dir,failure)
        def command(args,**kwargs): runner.events.append('stop'); return b''
        def process(args,**kwargs):
            runner.events.append('pg_restore')
            runner.captured_archive=kwargs['stdin'].read()
            return type('Result',(),{'returncode':int(failure=='restore'),'stderr':b'SECRET'})()
        with patch.object(restore,'command',command),patch.object(restore.subprocess,'run',process):
            try: result=runner.restore(self.dir/'dump',self.dir/'manifest','operator',apply,resume)
            except restore.RestoreError: result=None
            finally: runner.close()
        return runner.events,result
    def test_dryrun_verifies_without_fencing(self):
        events,result=self.run_flow(apply=False)
        self.assertEqual(events,['verify']);self.assertTrue(result['ready_for_operator_review'])
    def test_success_order(self):
        events,result=self.run_flow()
        self.assertEqual(events,['verify','app-restore-begin','stop','stopped','pg_restore','stopped','verify','app-recovery','stopped'])
        self.assertTrue(result['listeners_stopped'])
    def test_verify_failure_precedes_fence_and_restore(self):
        events,result=self.run_flow('verify')
        self.assertEqual(events,['verify']);self.assertIsNone(result)
    def test_fail_closed_before_restore_and_recovery(self):
        for failure in ['app-restore-begin','stop','restore','unconfirmed','app-recovery']:
            events,result=self.run_flow(failure)
            self.assertIsNone(result)
            if failure in ['app-restore-begin','stop']:self.assertNotIn('pg_restore',events)
            if failure=='restore':self.assertNotIn('app-recovery',events)
    def test_resume_verifies_manifest_without_reapplying_dump(self):
        events,result=self.run_flow(resume=MARKER)
        self.assertEqual(events,['verify','stop','stopped','stopped','verify','app-recovery','stopped'])
        self.assertTrue(result['restore_complete'])
    def test_verified_dump_is_frozen_against_original_replacement(self):
        runner=FlowRunner(self.dir)
        original=runner.tool
        def tool(args,**kwargs):
            result=original(args,**kwargs)
            if args[0]=='verify':(self.dir/'dump').write_bytes(b'replaced-unverified')
            return result
        def process(args,**kwargs):
            runner.captured_archive=kwargs['stdin'].read()
            return type('Result',(),{'returncode':0})()
        with patch.object(runner,'tool',tool),patch.object(restore,'command',return_value=b''),patch.object(restore.subprocess,'run',process):
            try:runner.restore(self.dir/'dump',self.dir/'manifest','operator',True)
            finally:runner.close()
        self.assertEqual(runner.captured_archive,b'fixture')

    def test_command_failure_does_not_expose_subprocess_output(self):
        result=type('Result',(),{'returncode':1,'stdout':b'SECRET','stderr':b'postgres://secret'})()
        with patch.object(restore.subprocess,'run',return_value=result):
            with self.assertRaises(restore.RestoreError) as caught:restore.command(['fixture'])
        self.assertNotIn('SECRET',str(caught.exception));self.assertNotIn('postgres',str(caught.exception))

    def test_cli_generic_error_and_owned_cleanup(self):
        class FailedRunner:
            closed=False
            def __init__(self,*args):pass
            def restore(self,*args):raise restore.RestoreError('postgres://private-secret')
            def close(self):FailedRunner.closed=True
        args=['restore.py','--docker-socket','/fixture.sock','--project','owned','--directory',str(self.dir),'--compose-file',str(self.dir/'compose.yml'),'--dump',str(self.dir/'dump'),'--manifest',str(self.dir/'manifest'),'--operator','operator']
        output=io.StringIO()
        with patch.object(restore,'Runner',FailedRunner),patch.object(sys,'argv',args),contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as caught:restore.main()
        self.assertEqual(caught.exception.code,1)
        self.assertTrue(FailedRunner.closed)
        self.assertNotIn('private-secret',output.getvalue())
        self.assertIn('retain the external marker',output.getvalue())

class Ownership(unittest.TestCase):
    def setUp(self):
        socket_patch=patch.object(restore,"local_socket",return_value="/fixture.sock");socket_patch.start();self.addCleanup(socket_patch.stop)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name);(self.directory/'compose.yml').write_text('fixture')
        self.runner=restore.Runner('owned',self.directory,[self.directory/'compose.yml'], '/fixture.sock')
    def test_foreign_checkout_wrong_marker_and_mixed_volume_refused(self):
        def fixture(service='api'):
            return {'Config':{'Labels':{'com.docker.compose.project':'owned','com.docker.compose.service':service,'com.docker.compose.project.working_dir':str(self.directory)},'Env':['TUNNEX_APP_ACCESS_RESTORE_MARKER='+restore.BARRIER]},'Mounts':[{'Destination':str(Path(restore.BARRIER).parent),'Type':'volume','Name':'owned_app_restore'}]}
        for mutation in ['directory','marker','mount','volume','project']:
            first,second=fixture(),fixture('app-proxy')
            if mutation=='directory':first['Config']['Labels']['com.docker.compose.project.working_dir']='/foreign'
            if mutation=='marker':first['Config']['Env']=[]
            if mutation=='mount':first['Mounts'][0]['Type']='bind'
            if mutation=='volume':second['Mounts'][0]['Name']='different'
            if mutation=='project':first['Config']['Labels']['com.docker.compose.project']='foreign'
            def command(args,**kwargs):
                if args[:2]==['docker','ps']:return b'a p'
                return json.dumps([first if args[-1]=='a' else second]).encode()
            with self.subTest(mutation=mutation),patch.object(restore,'command',command):
                with self.assertRaises(restore.RestoreError):self.runner.participants()

    def test_helper_named_volume_and_guard_checked(self):
        def config():
            return {'services':{'api':{'environment':{'TUNNEX_APP_ACCESS_RESTORE_MARKER':restore.BARRIER},'volumes':[{'type':'volume','target':str(Path(restore.BARRIER).parent),'source':'app_restore'}]}},'volumes':{'app_restore':{'name':'owned_app_restore'}}}
        for mutation in ['valid','volume','marker','bind']:
            runner=restore.Runner('owned',self.directory,[self.directory/'compose.yml'], '/fixture.sock')
            runner.marker_mount='owned_app_restore'
            self.addCleanup(lambda runner=runner: getattr(runner,'close',lambda:None)())
            value=config()
            if mutation=='volume':value['volumes']['app_restore']['name']='other'
            if mutation=='marker':value['services']['api']['environment']={}
            if mutation=='bind':value['services']['api']['volumes'][0]['type']='bind'
            with self.subTest(mutation=mutation),patch.object(restore,'command',return_value=json.dumps(value).encode()):
                if mutation=='valid':runner.validate_helper()
                else:
                    with self.assertRaises(restore.RestoreError):runner.validate_helper()

    def test_validated_snapshot_is_private_immutable_and_cleaned(self):
        runner=restore.Runner('owned',self.directory,[self.directory/'compose.yml'], '/fixture.sock')
        self.addCleanup(lambda: getattr(runner,'close',lambda:None)())
        runner.marker_mount='owned_app_restore'
        config={'services':{'api':{'environment':{'TUNNEX_APP_ACCESS_RESTORE_MARKER':restore.BARRIER,'DATABASE_URL':'postgres://private-secret'},'volumes':[{'type':'volume','target':str(Path(restore.BARRIER).parent),'source':'app_restore'}]}},'volumes':{'app_restore':{'name':'owned_app_restore'}}}
        calls=[]
        def command(args,**kwargs):
            calls.append(list(args))
            if 'config' in args:
                file=Path(args[args.index('-f')+1])
                if file.name=='compose.yml':return json.dumps(config).encode()
                return file.read_bytes()
            return b''
        with patch.object(restore,'command',command):
            runner.validate_helper()
            files=[Path(runner.compose[i+1]) for i,value in enumerate(runner.compose) if value=='-f']
            self.assertEqual(len(files),1)
            snapshot=files[0]
            self.assertNotEqual(snapshot,self.directory/'compose.yml')
            self.assertEqual(snapshot.stat().st_mode & 0o777,0o600)
            self.assertEqual(snapshot.parent.stat().st_mode & 0o777,0o700)
            config['volumes']['app_restore']['name']='foreign'
            (self.directory/'compose.yml').write_text('changed original')
            runner.tool(['app-restore-begin','--barrier',restore.BARRIER])
            self.assertEqual(Path(calls[-1][calls[-1].index('-f')+1]).name,'helper.json')
            self.assertNotIn(str(self.directory/'compose.yml'),calls[-1])
            root=snapshot.parent
            runner.close()
            self.assertFalse(snapshot.exists())
            self.assertFalse(root.exists())
            self.assertTrue((self.directory/'compose.yml').exists())

    def test_only_marker_mutation_helpers_get_exact_rw_override(self):
        runner=restore.Runner('owned',self.directory,[self.directory/'compose.yml'], '/fixture.sock')
        self.addCleanup(runner.close)
        runner.marker_mount='owned_app_restore'
        original={'services':{'api':{'environment':{'TUNNEX_APP_ACCESS_RESTORE_MARKER':restore.BARRIER},'volumes':[{'type':'volume','target':str(Path(restore.BARRIER).parent),'source':'app_restore','read_only':True}]},'app-proxy':{'volumes':[{'type':'volume','target':str(Path(restore.BARRIER).parent),'source':'app_restore','read_only':True}]}},'volumes':{'app_restore':{'name':'owned_app_restore'}}}
        calls=[]
        def command(args,**kwargs):
            calls.append(list(args))
            if 'config' in args:
                file=Path(args[args.index('-f')+1])
                return json.dumps(original).encode() if file.name=='compose.yml' else file.read_bytes()
            return b''
        with patch.object(restore,'command',command):
            for helper in ['verify','app-restore-begin','app-recovery']:
                runner.tool([helper])
                call=calls[-1]
                self.assertIn('--no-deps',call)
                self.assertNotIn('--service-ports',call)
                self.assertNotIn('--volume',call)
                called_snapshot=Path(call[call.index('-f')+1])
                effective=json.loads(called_snapshot.read_text())
                self.assertEqual(effective['services']['api']['volumes'][0]['read_only'],helper=='verify')
                self.assertTrue(effective['services']['app-proxy']['volumes'][0]['read_only'])
                self.assertNotIn('ports',effective['services']['api'])
            snapshot=Path(runner.compose[runner.compose.index('-f')+1])
            frozen=json.loads(snapshot.read_text())
            for service in ['api','app-proxy']:
                self.assertTrue(frozen['services'][service]['volumes'][0]['read_only'])
                self.assertTrue(original['services'][service]['volumes'][0]['read_only'])

class LocalEndpointAndHelper(unittest.TestCase):
    def test_remote_environment_removed(self):
        with patch.dict(restore.os.environ, {'DOCKER_HOST':'tcp://remote:2375','DOCKER_CONTEXT':'remote','DOCKER_TLS_VERIFY':'1','DOCKER_CERT_PATH':'/remote','COMPOSE_PROFILES':'foreign'}):
            environment=restore.local_environment()
            for key in ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','COMPOSE_PROFILES']:
                self.assertNotIn(key,environment)

    def test_only_canonical_unix_socket_accepted(self):
        import socket
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/'docker.sock'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(path))
                self.assertEqual(restore.local_socket(path),str(path))
                alias=Path(directory)/'alias';alias.symlink_to(path)
                for bad in [alias,Path(directory),Path('relative.sock')]:
                    with self.assertRaises((restore.RestoreError,OSError)):restore.local_socket(bad)

    def test_helper_rejects_changed_target_secret_mount_or_image(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            compose=Path(directory)/'compose.yml';compose.write_text('fixture')
            env={'DATABASE_URL':'postgres://owned/db','TUNNEX_APP_ACCESS_RESTORE_MARKER':restore.BARRIER}
            config={'services':{'api':{'image':'cached-image','environment':env,'volumes':[{'type':'volume','target':str(Path(restore.BARRIER).parent),'source':'app_restore'}]}},'volumes':{'app_restore':{'name':'owned_app_restore'}}}
            identity={'Config':{'Env':[key+'='+value for key,value in env.items()]},'Image':'sha256:owned','Mounts':[{'Destination':str(Path(restore.BARRIER).parent),'Type':'volume','Name':'owned_app_restore'}]}
            for mutation in ['valid','database','secret','mount','image']:
                with patch.object(restore,'local_socket',return_value='/fixture.sock'):
                    runner=restore.Runner('owned',directory,[compose], '/fixture.sock')
                runner.marker_mount='owned_app_restore';runner.api_identity=identity
                value=copy.deepcopy(config)
                if mutation=='database':value['services']['api']['environment']['DATABASE_URL']='postgres://foreign/db'
                if mutation=='secret':value['services']['api']['environment']['TUNNEX_MASTER_KEY']='foreign-secret'
                if mutation=='mount':value['services']['api']['volumes'].append({'type':'bind','target':'/var/lib/tunnex/secrets','source':'/foreign'})
                def command(args,**kwargs):
                    if 'config' in args:return json.dumps(value).encode()
                    return b'sha256:foreign' if mutation=='image' else b'sha256:owned'
                with self.subTest(mutation=mutation),patch.object(restore,'command',command):
                    try:
                        if mutation=='valid':
                            runner.validate_helper()
                            snapshot=json.loads(Path(runner.compose[-1]).read_text())
                            self.assertEqual(snapshot['services']['api']['image'],'sha256:owned')
                        else:
                            with self.assertRaises(restore.RestoreError):runner.validate_helper()
                    finally:runner.close()

if __name__=='__main__': unittest.main()
