import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('owned_discovery',Path(__file__).resolve().parents[2]/'deploy/azure/discover-owned-profile.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


class OwnedResourceGuards(unittest.TestCase):
 def test_wrong_host_or_subscription_refused_before_any_az_call(self):
  for host,subscription in [('other-host',helper.SUBSCRIPTION),('bastion-host','00000000-0000-4000-8000-000000000001')]:
   with self.subTest(host=host),patch.object(helper.socket,'gethostname',return_value=host),patch.object(helper,'az') as az:
    with self.assertRaises(ValueError):helper.discover(subscription,'unused')
    az.assert_not_called()

 def test_private_output_parent_no_symlink_and_no_existing_file(self):
  with tempfile.TemporaryDirectory() as directory:
   parent=Path(directory).resolve();parent.chmod(0o700);output=parent/'new.json'
   helper.output_preflight(output)
   parent.chmod(0o755)
   with self.assertRaises(ValueError):helper.output_preflight(output)
   parent.chmod(0o700);output.touch()
   with self.assertRaises(ValueError):helper.output_preflight(output)
   output.unlink();link=parent/'link';link.symlink_to(parent,target_is_directory=True)
   with self.assertRaises(ValueError):helper.output_preflight(link/'new.json')

 def test_main_bad_parent_refuses_before_cli_or_mutation(self):
  with tempfile.TemporaryDirectory() as directory:
   parent=Path(directory).resolve();parent.chmod(0o755)
   args=['discover-owned-profile.py','aa-static','--subscription',helper.SUBSCRIPTION,'--connection-id','unused','--output',str(parent/'new.json')]
   with patch('sys.argv',args),patch.object(helper,'az') as az:
    with self.assertRaises(ValueError):helper.main()
    az.assert_not_called()

 def test_resource_id_is_exact_subscription_group_and_kind(self):
  subscription='00000000-0000-4000-8000-000000000001'
  value='/subscriptions/'+subscription+'/resourceGroups/tunnex-azure-s2s-20261010/providers/Microsoft.Network/connections/owned'
  self.assertEqual(helper.resource_id(value,subscription,'connections'),value)
  for bad in [value.replace(subscription,'00000000-0000-4000-8000-000000000002'),value.replace('tunnex-azure-s2s-20261010','other'),value+'/child',value.replace('/connections/','/virtualNetworkGateways/')]:
   with self.assertRaises(ValueError):helper.resource_id(bad,subscription,'connections')

 def test_owned_guard_requires_exact_id_and_owner(self):
  self.assertEqual(helper.owned({'id':'/OWNED','owner':helper.OWNER},'/owned')['owner'],helper.OWNER)
  for value in [{'id':'/owned','owner':'other'},{'id':'/other','owner':helper.OWNER}]:
   with self.assertRaises(ValueError):helper.owned(value,'/owned')


if __name__=='__main__':unittest.main()
