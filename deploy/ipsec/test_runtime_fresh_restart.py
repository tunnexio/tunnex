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
            if mutation=='systemd':cg='0::/system.slice/docker-'+cid+'.scope'
            if mutation=='wrong_ns':ns='net:[99]'
            if mutation=='wrong_gate':raw=b'foreign'
            again=copy.deepcopy(c)
            if mutation=='process_swap':again['state']['Pid']=3
            with patch.object(runner.proof,'boot',return_value='boot'),patch.object(runner.proof,'inspect',return_value=again),patch.object(runner.proof,'private_bytes',return_value=raw),patch.object(Path,'lstat',autospec=True,side_effect=lambda p: SimpleNamespace(st_uid=0,st_mode=0o40755,st_dev=3,st_ino=4) if str(p).startswith('/sys/fs/cgroup') else info),patch.object(Path,'read_text',autospec=True,side_effect=lambda p:('999' if mutation=='missing_member' else '2') if str(p).endswith('cgroup.procs') else cg if str(p).endswith('cgroup') else '2 (x) '+' '.join(['S']+['0']*18+['100'])),patch.object(runner.os,'readlink',return_value=ns):
                return runner.observe_fresh_runtime(before,b'stop',b'oldjournal',b'currentjournal',c,'net:[41]',Path('/gate'),b'owned',info)
        good=observe()
        self.assertEqual(observe('systemd')['pid_start_ticks'],100)
        self.assertEqual(good['pid_start_ticks'],100)
        self.assertEqual(good['current_journal_sha256'],hashlib.sha256(b'currentjournal').hexdigest())
        for mutation in ('same_pid','wrong_cgroup','wrong_ns','wrong_gate','process_swap','missing_member'):
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):observe(mutation)

    def test_guard_metadata_advance_only_preserves_lineage(self):
        before={'Payload':{'Entries':[{'DeliveryID':'one'}],'OwnerID':'owner','Version':10,'Sequence':1,'Guards':[]},'Checksum':'old'}
        after=copy.deepcopy(before);after['Payload'].update(Sequence=2,Guards=[{'new':'metadata'}]);after['Checksum']='new'
        runner.journal_entries_unchanged(json.dumps(before),json.dumps(after))
        for key,value in [('Entries',[]),('OwnerID','foreign'),('Version',9),('Sequence',0)]:
            bad=copy.deepcopy(after);bad['Payload'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):runner.journal_entries_unchanged(json.dumps(before),json.dumps(bad))

if __name__=='__main__':unittest.main()

