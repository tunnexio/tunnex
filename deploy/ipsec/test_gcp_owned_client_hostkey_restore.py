import importlib.util,pathlib,json,hashlib,unittest,unittest.mock
spec=importlib.util.spec_from_file_location('restore',pathlib.Path(__file__).with_name('gcp-owned-client-hostkey-restore.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ExactRestore(unittest.TestCase):
    def test_all_original_items_and_exact_current_fingerprint(self):
        items=[{'key':'startup-script','value':'#!/bin/sh\noriginal\n'},{'key':'ssh-keys','value':'existing'},{'key':'other','value':'unaltered'}]
        original={'id':m.ID,'metadata':{'items':items,'fingerprint':'old'}};installed={'items':[{'key':'startup-script','value':'wrapped'}],'fingerprint':'installed'}
        current={'id':m.ID,'name':m.NAME,'status':'RUNNING','networkInterfaces':[{'networkIP':'10.70.0.10','network':'https://compute.googleapis.com/compute/v1/projects/'+m.PROJECT+'/global/networks/tn-gcps2s-20261010-peer'}],'metadata':installed}
        digest=hashlib.sha256(json.dumps(items,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        with unittest.mock.patch.object(m,'EXPECTED_ORIGINAL',digest):
            self.assertEqual(m.restore_body(original,installed,current),{'fingerprint':'installed','items':items})
            for changed in [dict(current,metadata=dict(installed,fingerprint='changed')),dict(current,id='foreign')]:
                with self.assertRaises(ValueError):m.restore_body(original,installed,changed)
            wrong={'id':m.ID,'metadata':{'items':items+[{'key':'extra','value':'bad'}]}}
            with self.assertRaises(ValueError):m.restore_body(wrong,installed,current)
if __name__=='__main__':unittest.main()
