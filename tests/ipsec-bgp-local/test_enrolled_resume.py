import unittest
from enrolled_approval import validate_resume
class ResumeTest(unittest.TestCase):
 def test_exact_pending_topology(self):
  r={'old_container_id':'old','new_container_id':'new','worker_released':False,'journal_sha256':'j','genuine_receipt_sha256':'r'};o={'gateway_id':'old','containers':{'peer':'p'}};c={**o,'gateway_id':'new'};p={**r,'finish_complete':False}
  validate_resume(p,r,o,c)
  for bad in [{**p,'worker_released':True},{**p,'journal_sha256':'foreign'},{**p,'extra':1}]:
   with self.assertRaises(AssertionError):validate_resume(bad,r,o,c)
  for bad in [o,{**c,'containers':{'peer':'foreign'}}]:
   with self.assertRaises(AssertionError):validate_resume(p,r,o,bad)
if __name__=='__main__':unittest.main()
