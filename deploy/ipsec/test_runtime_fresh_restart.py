import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import runtime_restore_runner as runner

class FreshRestartTests(unittest.TestCase):
    def test_observation_exact_process_cgroup_namespace_and_gate(self):
        cid='a'*64
        before={'container':cid,'pid':1,'started':'2026-10-10T10:00:00Z','boot':'boot'}
        current={'id':cid,'state':{'Pid':2,'Running':True,'Restarting':False,'StartedAt':'2026-10-10T10:00:02Z'}}
        info=SimpleNamespace(st_uid=0,st_mode=0o100600,st_dev=1,st_ino=2)
        def observe(mutation=None):
            c=copy.deepcopy(current)
            cg='0::/docker/'+cid;ns='net:[41]';raw=b'owned'
            if mutation=='same_pid':c['state']['Pid']=1
            if mutation=='wrong_cgroup':cg='0::/foreign'
            if mutation=='wrong_ns':ns='net:[99]'
            if mutation=='wrong_gate':raw=b'foreign'
            again=copy.deepcopy(c)
            if mutation=='process_swap':again['state']['Pid']=3
            with patch.object(runner.proof,'boot',return_value='boot'),patch.object(runner.proof,'inspect',return_value=again),patch.object(runner.proof,'private_bytes',return_value=raw),patch.object(Path,'lstat',return_value=info),patch.object(Path,'read_text',autospec=True,side_effect=lambda p:cg if str(p).endswith('cgroup') else '2 (x) '+' '.join(['S']+['0']*18+['100'])),patch.object(runner.os,'readlink',return_value=ns):
                return runner.observe_fresh_runtime(before,b'stop',b'oldjournal',b'currentjournal',c,'net:[41]',Path('/gate'),b'owned',info)
        good=observe()
        self.assertEqual(good['pid_start_ticks'],100)
        self.assertEqual(good['current_journal_sha256'],hashlib.sha256(b'currentjournal').hexdigest())
        for mutation in ('same_pid','wrong_cgroup','wrong_ns','wrong_gate','process_swap'):
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):observe(mutation)

    def test_guard_metadata_advance_only_preserves_lineage(self):
        before={'Payload':{'Entries':[{'DeliveryID':'one'}],'OwnerID':'owner','Version':10,'Sequence':1,'Guards':[]},'Checksum':'old'}
        after=copy.deepcopy(before);after['Payload'].update(Sequence=2,Guards=[{'new':'metadata'}]);after['Checksum']='new'
        runner.journal_entries_unchanged(json.dumps(before),json.dumps(after))
        for key,value in [('Entries',[]),('OwnerID','foreign'),('Version',9),('Sequence',0)]:
            bad=copy.deepcopy(after);bad['Payload'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):runner.journal_entries_unchanged(json.dumps(before),json.dumps(bad))

if __name__=='__main__':unittest.main()

class ResumeEvidenceTests(unittest.TestCase):
    def test_resume_uses_original_stop_proof_without_second_stop_or_rewrite(self):
        import os
        import tempfile
        from test_runtime_restore_profiles import entry
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);original=root/'run-original';original.mkdir(mode=0o700)
            helper=root/'helper';helper.write_text('helper');helper.chmod(0o500)
            cid='a'*64
            document={'Payload':{'Entries':[entry('gcp-classic-static-ipv4-v1',4)],'OwnerID':'owner','Version':10,'Sequence':1,'Guards':[]}}
            raw=json.dumps(document).encode()
            journal=root/'journal.json';journal.write_bytes(raw)
            before={'container':cid,'pid':1,'started':'old','boot':'boot','state_mount':'exact'}
            stopped={'snapshot':before,'stopped_journal_raw_sha256':hashlib.sha256(raw).hexdigest()}
            for name,value in [('before.json',before),('stopped.json',stopped)]:
                (original/name).write_text(json.dumps(value));(original/name).chmod(0o600)
            (original/'stopped-journal.json').write_bytes(raw);(original/'stopped-journal.json').chmod(0o600)
            gate=root/'restoration-startup-gate'
            gate_raw=json.dumps({'Version':1,'SupervisorRun':original.name,'ContainerID':cid},sort_keys=True).encode()
            gate.write_bytes(gate_raw);gate.chmod(0o600)
            (original/'startup-gate.json').write_text(json.dumps({'file':str(gate),'sha256':hashlib.sha256(gate_raw).hexdigest()}));(original/'startup-gate.json').chmod(0o600)
            (root/'.restoration-supervisor.lock').write_text('');(root/'.restoration-supervisor.lock').chmod(0o600)
            args=SimpleNamespace(resume_evidence_dir=str(original),receipt_helper=str(helper),container=cid,journal=str(journal))
            saved={p.name:p.read_bytes() for p in original.iterdir()}
            real_lstat=Path.lstat
            real_fstat=os.fstat
            def root_metadata(path):
                info=real_lstat(path)
                if path in (original,helper):return SimpleNamespace(st_uid=0,st_mode=info.st_mode)
                return info
            def root_fd(fd):
                info=real_fstat(fd);return SimpleNamespace(st_uid=0,st_mode=info.st_mode)
            with patch.object(runner.os,'geteuid',return_value=0),patch.object(Path,'lstat',autospec=True,side_effect=root_metadata),patch.object(runner.os,'fstat',side_effect=root_fd),patch.object(runner.proof,'private_bytes',side_effect=lambda p:Path(p).read_bytes()),patch.object(runner.proof,'inspect',return_value={'id':cid}),patch.object(runner.proof,'state_mount',return_value='exact'),patch.object(runner.proof,'command',return_value='no') as commands,patch.object(runner,'finish_restoration',return_value={'resumed':True}) as finish:
                self.assertEqual(runner.resume(args),{'resumed':True})
                self.assertTrue(all(call.args[1] == 'inspect' for call in commands.call_args_list))
                self.assertEqual(finish.call_args.args[1],cid)
                self.assertEqual(finish.call_args.args[5],raw)
                for name,content in saved.items():self.assertEqual((original/name).read_bytes(),content)
                self.assertEqual(gate.read_bytes(),gate_raw)
                for mutation in ('entries','gate','stop_digest'):
                    journal.write_bytes(raw);gate.write_bytes(gate_raw);(original/'stopped.json').write_text(json.dumps(stopped))
                    if mutation=='entries':
                        changed=copy.deepcopy(document);changed['Payload']['Entries']=[];journal.write_text(json.dumps(changed))
                    if mutation=='gate':gate.write_bytes(b'foreign')
                    if mutation=='stop_digest':
                        changed=copy.deepcopy(stopped);changed['stopped_journal_raw_sha256']='wrong';(original/'stopped.json').write_text(json.dumps(changed))
                    with self.subTest(mutation=mutation),self.assertRaises(ValueError):runner.resume(args)

class BoundedAcceptanceTests(unittest.TestCase):
    def test_restoration_transition_waits_without_accepting(self):
        from test_runtime_restore_profiles import entry
        before=entry('gcp-classic-static-ipv4-v1',4)
        for phase in ('reserved','applying'):
            candidate=copy.deepcopy(before);candidate['Phase']=phase
            got=runner.poll_entry({'Payload':{'Entries':[candidate]}},before)
            self.assertEqual(got['Phase'],phase)
            self.assertFalse(runner.restored(before,got,'net:[1]'))
        for mutate in (lambda e:e.update(Phase='cleanup_pending'),lambda e:e.update(DeliveryID='foreign'),lambda e:e['Engines'][0]['Binding'].update(DesiredRevision=99),lambda e:e['Allocation'].update(ProfileID='foreign')):
            bad=copy.deepcopy(before);mutate(bad)
            with self.assertRaises(ValueError):runner.poll_entry({'Payload':{'Entries':[bad]}},before)

    def test_resume_wait_metric_is_not_outage_metric(self):
        from test_runtime_restore_profiles import entry
        before=entry('gcp-classic-static-ipv4-v1',4)
        after=entry('gcp-classic-static-ipv4-v1',4,'net:[2]');after['Restoration']={'Epoch':1}
        result=runner.acceptance_result(before,after,'start',1.0,resumed=True)
        self.assertIn('resume_wait_to_active_established_seconds',result)
        self.assertNotIn('stop_to_active_established_seconds',result)
        ordinary=runner.acceptance_result(before,after,'start',1.0,resumed=False)
        self.assertIn('stop_to_active_established_seconds',ordinary)
        self.assertNotIn('resume_wait_to_active_established_seconds',ordinary)
