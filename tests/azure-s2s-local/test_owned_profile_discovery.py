import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('owned_discovery',Path(__file__).resolve().parents[2]/'deploy/azure/discover-owned-profile.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


class OwnedResourceGuards(unittest.TestCase):
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
