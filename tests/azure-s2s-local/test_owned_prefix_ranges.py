import copy
from datetime import datetime,timedelta,timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('range_collector',Path(__file__).parents[2]/'deploy/azure/collect-owned-prefix-ranges.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
NOW=datetime.now(timezone.utc)
CP={'id':m.prefix.CP,'desired_revision':34,'desired_intent':'enabled','application_state':'applied','cleanup_state':'not_required','profile_id':'azure-active-active-bgp-ipv4-v1','remote_prefixes':['10.231.0.0/16'],'maximum_prefixes':8}

def inventory(kind,ranges):
 value=m.envelope(kind,(NOW-timedelta(seconds=10)).isoformat(),[{'source':{'owned_api_ranges':'site_subnet','owned_kernel_ranges':'kernel_route','owned_azure_ranges':'azure_subnet'}[kind],'cidr':v} for v in ranges]);value['completed_at']=(NOW-timedelta(seconds=5)).isoformat();return value

def values():
 api=inventory('owned_api_ranges',['10.244.0.0/16','10.233.10.0/24']);api['normal_connection']=copy.deepcopy(CP)
 kernel=inventory('owned_kernel_ranges',['10.232.1.0/24']);kernel['namespace']={'device':4,'inode':9}
 azure=inventory('owned_azure_ranges',['10.231.0.0/16'])
 return [api,kernel,azure]

class Ranges(unittest.TestCase):
 def test_assembly_preserves_earliest_observation_and_hashes(self):
  inputs=values();inputs[1]['observed_at']=(NOW-timedelta(seconds=20)).isoformat()
  result=m.assemble(inputs,'10.235.77.0/24',4,9,NOW)
  self.assertEqual(result['observed_at'],inputs[1]['observed_at'])
  self.assertEqual(result['source_sha256'],[m.prefix.digest(v) for v in inputs])
  self.assertEqual(result['normal_connection']['desired_revision'],34)
 def test_overlap_each_source_refused(self):
  for index in range(3):
   inputs=values();inputs[index]['ranges'].append({'source':inputs[index]['ranges'][0]['source'],'cidr':'10.235.0.0/16'})
   with self.subTest(index=index),self.assertRaisesRegex(ValueError,'overlap'):m.assemble(inputs,'10.235.77.0/24',4,9,NOW)
 def test_stale_future_chronology_revision_and_namespace_refused(self):
  for scenario in ('stale','future','chronology','revision','namespace','owner','missing'):
   inputs=values()
   if scenario=='stale':inputs[2]['observed_at']=(NOW-timedelta(seconds=61)).isoformat()
   if scenario=='future':inputs[0]['completed_at']=(NOW+timedelta(seconds=1)).isoformat()
   if scenario=='chronology':inputs[1]['observed_at']=NOW.isoformat()
   if scenario=='revision':inputs[0]['normal_connection']['desired_revision']=33
   if scenario=='namespace':inputs[1]['namespace']['inode']=10
   if scenario=='owner':inputs[2]['owner']='foreign'
   if scenario=='missing':inputs.pop()
   with self.subTest(scenario=scenario),self.assertRaises(ValueError):m.assemble(inputs,'10.235.77.0/24',4,9,NOW)
 def test_payload_fields_not_exported(self):
  inputs=values();inputs[0]['ranges'][0]['raw']='not_exportable'
  with self.assertRaisesRegex(ValueError,'fields'):m.assemble(inputs,'10.235.77.0/24',4,9,NOW)
 def test_bastion_guard_precedes_any_azure_call(self):
  with patch.object(m.socket,'gethostname',return_value='other'),patch.object(m.prefix,'cloud_binding') as call:
   with self.assertRaisesRegex(ValueError,'bastion'):m.azure_collect()
   call.assert_not_called()
 def test_namespace_guard_precedes_any_kernel_command(self):
  class NS:st_dev=4;st_ino=8
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'stat',return_value=NS()),patch.object(m.subprocess,'run') as call:
   with self.assertRaisesRegex(ValueError,'namespace'):m.kernel_collect(4,9)
   call.assert_not_called()
 def test_output_parent_symlink_or_public_refused(self):
  with tempfile.TemporaryDirectory() as root:
   root=Path(root).resolve();(root/'safe').mkdir(mode=0o700);(root/'link').symlink_to(root/'safe',target_is_directory=True)
   self.assertEqual(m.parent(root/'safe'/'out'),root/'safe'/'out')
   with self.assertRaises(ValueError):m.parent(root/'link'/'out')
   (root/'safe').chmod(0o755)
   with self.assertRaises(ValueError):m.parent(root/'safe'/'out')
 def test_azure_exact_read_commands_and_foreign_peering_refusal(self):
  vnet={'id':m.prefix.VNET,'name':'azure-vnet','tags':{'owner':m.lab.OWNER},'provisioningState':'Succeeded','addressSpace':{'addressPrefixes':['10.231.0.0/16']},'dhcpOptions':{'dnsServers':['10.231.2.4']}}
  table={'id':m.prefix.BASE+'routeTables/owned-table','name':'owned-table','tags':{'owner':m.lab.OWNER},'provisioningState':'Succeeded'}
  calls=[];foreign=False
  def az(*args):
   calls.append(args)
   self.assertIn('--subscription',args);self.assertIn(m.lab.SUBSCRIPTION,args)
   if args[:3]==('network','vnet','list'):return [vnet]
   if args[:3]==('network','local-gateway','list'):return []
   if args[:4]==('network','vnet','subnet','list'):return [{'id':vnet['id']+'/subnets/target','addressPrefix':'10.231.1.0/24'}]
   if args[:4]==('network','vnet','peering','list'):
    if foreign:return [{'id':vnet['id']+'/virtualNetworkPeerings/foreign','remoteVirtualNetwork':{'id':m.prefix.BASE+'virtualNetworks/not-collected'}}]
    return []
   if args[:3]==('network','route-table','list'):return [table]
   if args[:4]==('network','route-table','route','list'):return [{'id':table['id']+'/routes/owned','addressPrefix':'10.232.1.0/24','nextHopIpAddress':'10.231.1.4'}]
   raise AssertionError(args)
  with patch.object(m.socket,'gethostname',return_value='bastion-host'),patch.object(m.prefix,'cloud_binding'),patch.object(m.lab,'az',side_effect=az):
   result=m.azure_collect();self.assertIn({'source':'azure_udr','cidr':'10.232.1.0/24'},result['ranges'])
   self.assertEqual(result['counts']['route_tables'],1)
   self.assertTrue(all('list' in c for c in calls))
   foreign=True
   with self.assertRaisesRegex(ValueError,'unreviewed remote'):m.azure_collect()
   foreign=False;vnet['tags']['owner']='foreign'
   with self.assertRaisesRegex(ValueError,'foreign cloud'):m.azure_collect()
 def test_kernel_actual_interface_normalization_and_default_route_count(self):
  class NS:st_dev=4;st_ino=9
  class Run:
   returncode=0
   def __init__(self,value):
    import json
    self.stdout=json.dumps(value)
  outputs=[Run([{'addr_info':[{'family':'inet','local':'10.233.10.1','prefixlen':24}]}]),Run([{'dst':'default','gateway':'10.232.1.1'},{'dst':'10.231.1.4','gateway':'10.232.1.1'}])]
  # Trusted binary validation remains a real file ownership check in production.
  class Binary:
   st_mode=0o100755;st_uid=0
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'stat',return_value=NS()),patch.object(m.Path,'resolve',return_value=m.Path('/sbin/ip')),patch.object(m.Path,'stat',return_value=Binary()),patch.object(m.subprocess,'run',side_effect=outputs) as call:
   result=m.kernel_collect(4,9)
  self.assertEqual(result['default_route_count'],1)
  self.assertIn({'source':'kernel_interface','cidr':'10.233.10.0/24'},result['ranges'])
  self.assertIn({'source':'kernel_route','cidr':'10.231.1.4/32'},result['ranges'])
  self.assertEqual(call.call_args_list[1].args[0],['/sbin/ip','-j','-4','route','show','table','all'])
 def test_api_actual_envelopes_tombstone_and_resolver404(self):
  setup={'org_id':'11111111-1111-4111-8111-111111111111','site_id':'22222222-2222-4222-8222-222222222222','gateway_id':'33333333-3333-4333-8333-333333333333'}
  connection=dict(CP,org_id=setup['org_id'],site_id=setup['site_id'],gateway_node_id=setup['gateway_id'],finalized_at=None)
  tomb={'id':'44444444-4444-4444-8444-444444444444','desired_intent':'deleted','finalized_at':NOW.isoformat()}
  config={'profile_id':CP['profile_id'],'configuration':{'local_prefixes':['10.233.10.0/24'],'remote_prefixes':['10.231.0.0/16'],'bgp':{'maximum_prefixes':8},'tunnels':[{'inside_cidr':'169.254.11.1/32'}]}}
  calls=[]
  class Client:
   def __init__(self,account):pass
   def call(self,method,path):
    calls.append((method,path));suffix=path.split(setup['org_id'])[-1]
    if path=='/api/v1/organizations':return [dict(id=setup['org_id'],slug='azure-s2s-local',pool_cidr='10.244.0.0/16')]
    if suffix=='/sites':return [{'id':setup['site_id']}]
    if suffix=='/nodes':return [{'id':setup['gateway_id']}]
    if suffix.endswith('/subnets'):return [{'cidr':'10.233.10.0/24'}]
    if suffix.endswith('/dns-forwards'):return [{'resolver_ip':'10.233.10.1'}]
    if suffix.startswith('/fqdn-resolver-contexts/'):raise m.enroll.LabError('not exported',404,'fqdn_resolver_config_not_found')
    if suffix=='/routed-ranges':return {'ranges':['10.233.10.0/24'],'forwards':[]}
    if suffix=='/resources':return [{'cidr':'10.231.1.4/32'}]
    if suffix=='/policies':return [{'src_cidr':'10.233.10.2/32'}]
    if suffix=='/ipsec/connections?limit=100':return {'items':[connection,tomb],'next_cursor':None}
    if suffix=='/ipsec/connections/'+m.prefix.CP:return connection
    if suffix=='/ipsec/connections/'+m.prefix.CP+'/configuration':return config
    if suffix.endswith(tomb['id']+'/configuration'):return {'profile_id':'old','configuration':None}
    raise AssertionError(path)
  with tempfile.TemporaryDirectory() as root:
   root=Path(root).resolve()
   import json
   (root/'ui-accounts.json').write_text(json.dumps({'owner':{'email':'browser-owner@azure-s2s.local','password':'fixture'}}));(root/'api-setup.json').write_text(json.dumps(setup))
   for f in root.iterdir():f.chmod(0o600)
   with patch.object(m.enroll,'Client',Client):result=m.api_collect(root)
  self.assertEqual(result['normal_connection']['desired_revision'],34)
  self.assertEqual(result['counts']['connections'],2)
  self.assertTrue(all(method=='GET' for method,path in calls))
  self.assertNotIn('fixture',str(result))

if __name__=='__main__':unittest.main()
