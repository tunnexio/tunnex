import importlib.util
import copy
import tempfile
import json
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
spec=importlib.util.spec_from_file_location('scheduled',Path(__file__).with_name('qualify-scheduled-rekey.py'))
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)

class SchedulerTests(unittest.TestCase):
 def test_only_parent_timer_changes_for_all_cardinalities(self):
  for count in (1,2):
   original=('    rekey_time = 28800s\n    children {\n      local_ts = 0.0.0.0/0\n      rekey_time = 3000s\n      life_time = 3600s\n    }\n')*count
   accelerated=q.accelerated(original,count)
   normalized=accelerated.replace('rekey_time = 120s','rekey_time = 28800s').replace('rekey_time = 150s','rekey_time = 28800s').replace('\n    rand_time = 0s\n    over_time = 2880s','')
   self.assertEqual(normalized,original)
 def test_child_default_jitter_and_observation_boundaries(self):
  # All 601 initial values allowed by pinned apply_jitter must qualify.
  for remaining in range(2400,3001):
   self.assertTrue(q.child_timer_fresh({'child_remaining_seconds':remaining},0))
  self.assertEqual(q.CHILD_INITIAL_MIN_SECONDS,2400)
  self.assertTrue(q.child_timer_fresh({'child_remaining_seconds':2333},66))
  self.assertFalse(q.child_timer_fresh({'child_remaining_seconds':2332},66))
  self.assertFalse(q.child_timer_fresh({'child_remaining_seconds':2400},-1))
  for remaining in (-1,0,2398,3001,3600):
   self.assertFalse(q.child_timer_fresh({'child_remaining_seconds':remaining},0))
  self.assertFalse(q.child_timer_fresh({},0))
 def test_fresh_accepts_default_maximum_child_jitter(self):
  engine={'name':'owned'};item={'ike_serial':2,'remaining_seconds':120,'child_remaining_seconds':2400}
  with patch.object(q,'check'),patch.object(q.common,'name',return_value='owned'),patch.object(q,'sample',side_effect=[{'owned':{'ike_serial':1}},{'owned':item}]),patch.object(q,'swan') as swan:
   self.assertEqual(q.fresh({},engine,120),item)
  self.assertEqual([call.args[1] for call in swan.call_args_list],['--terminate','--initiate'])
 def test_fresh_counts_initiation_and_readback_age(self):
  item={'ike_serial':2,'remaining_seconds':120,'child_remaining_seconds':2333}
  # Initiation takes 20s; final checks/readback cross the observation deadline.
  with patch.object(q,'check'),patch.object(q.common,'name',return_value='owned'),patch.object(q,'sample',side_effect=[{'owned':{'ike_serial':1}},{'owned':item}]),patch.object(q,'swan'),patch.object(q.time,'monotonic',side_effect=[100,120,121,166]):
   self.assertEqual(q.fresh({}, {},120),item)
 def test_native_control_ceiling_is_original_attempt_only(self):
  with patch.object(q.time,'monotonic',return_value=100):
   self.assertEqual(q.native_control_ceiling({'watchdog_monotonic_deadline':520}),520_000_000_000)
   for deadline in (None,100,99,521,float('inf'),float('nan')):
    with self.assertRaises(ValueError):q.native_control_ceiling({'watchdog_monotonic_deadline':deadline})
 def test_fixed_journal_refusal_classes(self):
  for stage in ('journal-reread','journal-context','journal-identity','journal-bytes','request-ceiling'):
   self.assertEqual(q.fixed_control_failure(('owned_scheduler_control_refused '+stage+'\n').encode()),stage)
 def test_pre_watchdog_verify_is_read_only_bounded(self):
  with patch.object(q.time,'monotonic',return_value=100):
   self.assertEqual(q.native_control_ceiling({},'verify'),130_000_000_000)
   self.assertEqual(q.native_control_ceiling({'watchdog_monotonic_deadline':120},'verify'),120_000_000_000)
   for action in ('initiate','terminate','load-accelerated','load-production'):
    with self.assertRaises(ValueError):q.native_control_ceiling({},action)
   for bad in (None,99,100,float('nan')):
    for action in ('verify','initiate'):
     with self.assertRaises(ValueError):q.native_control_ceiling({'watchdog_monotonic_deadline':bad},action)
 def test_initial_verify_dispatch_has_no_mutation_or_attempt_claim(self):
  native={'delivery':'d','retained_identity':'r','charon_pid':2,'charon_sha':'sha','charon_start_ticks':'1','config':'fixed'}
  authority=dict(org='o',gateway='g',connection='c',site='s',desired=52,configuration=1,profile='p')
  m=dict(native=native,authority=authority,node_sha='node',container='cid',container_helper='helper')
  result=Mock(returncode=0)
  with patch.object(q.Path,'read_text',return_value='boot'),patch.object(q.time,'monotonic',return_value=100),patch.object(q.subprocess,'run',return_value=result) as run:
   q.verify_conns(m)
  request=json.loads(run.call_args_list[0].kwargs['input'])
  self.assertEqual(request['Action'],'verify');self.assertTrue(request['PreflightReadOnly'])
  self.assertEqual(request['WatchdogMonotonicDeadlineNS'],130_000_000_000)
  self.assertNotIn('watchdog_monotonic_deadline',m)
  self.assertEqual(run.call_count,2)
 def test_unexpected_timers_refused(self):
  with self.assertRaises(ValueError):q.accelerated('rekey_time = 120s',1)
 def test_original_socket_identity_survives_response_timeout(self):
  connection=Mock();connection.sock.getsockname.return_value=('10.233.10.2',43123)
  def fail():
   connection.sock=None
   raise TimeoutError('private endpoint must not appear')
  connection.getresponse.side_effect=fail
  result=q.http_attempt(connection,43123)
  self.assertFalse(result['success']);self.assertEqual(result['local_port_before_attempt'],43123)
  self.assertTrue(result['original_socket_present']);self.assertNotIn('private endpoint',str(result))
  second=q.http_attempt(connection,43123)
  self.assertEqual(second['original_local_port'],43123);self.assertFalse(second['original_socket_present'])
  self.assertEqual(connection.request.call_count,1)
 def test_normal_authority_is_exact_and_read_only(self):
  setup={'org_id':'org','site_id':'site','gateway_id':'gateway'}
  connection={'id':'connection','org_id':'org','site_id':'site','gateway_node_id':'gateway','desired_intent':'enabled','application_state':'applied','deleted_at':None,'finalized_at':None,'desired_revision':34}
  config={'configuration_revision':1,'profile_id':'azure-active-standby-bgp-ipv4-v1','configuration':{'azure':{'ike_version':2}}}
  client=Mock();client.call.side_effect=[connection,config]
  m={'accounts':'accounts','setup':'setup','connection':'connection'}
  with patch.object(q.proof,'private_read',side_effect=[{'owner':{'email':'browser-owner@azure-s2s.local','password':'PRIVATE'}},setup]),patch.object(q.lab,'Client',return_value=client):
   projection=q.api_authority(m)
  self.assertEqual(projection['desired'],34)
  self.assertEqual([call.args[0] for call in client.call.call_args_list],['GET','GET'])
  client.call.reset_mock();client.call.side_effect=[connection,config];m['authority']=dict(projection,desired=33)
  with patch.object(q.proof,'private_read',side_effect=[{'owner':{'email':'browser-owner@azure-s2s.local'}},setup]),patch.object(q.lab,'Client',return_value=client),self.assertRaises(ValueError):q.api_authority(m)
 def test_pending_authority_refuses_before_mutation(self):
  client=Mock();client.call.side_effect=[{'id':'connection','org_id':'org','site_id':'site','gateway_node_id':'gateway','desired_intent':'enabled','application_state':'pending'},{}]
  with patch.object(q.proof,'private_read',side_effect=[{'owner':{'email':'browser-owner@azure-s2s.local'}},{'org_id':'org','site_id':'site','gateway_id':'gateway'}]),patch.object(q.lab,'Client',return_value=client),self.assertRaises(ValueError):q.api_authority({'accounts':'accounts','setup':'setup','connection':'connection'})
  self.assertEqual([call.args[0] for call in client.call.call_args_list],['GET','GET'])
 def test_lease_sequence_and_child_refresh_are_not_binding_changes(self):
  before={key:'fixed' for key in ('profile','delivery','binding','engines','config','charon_pid','charon_sha','charon_start_ticks','retained_identity')}
  before.update(children=[{'spi_in':10}],sequence=42,guard_revision=50)
  after=copy.deepcopy(before);after.update(children=[{'spi_in':20}],sequence=43,guard_revision=51)
  self.assertTrue(q.same_snapshot_authority(before,after))
  for key in ('delivery','binding','engines','config','retained_identity','charon_start_ticks'):
   changed=copy.deepcopy(after);changed[key]='different'
   self.assertFalse(q.same_snapshot_authority(before,changed),key)
 def test_missing_identity_field_is_not_refresh(self):
  self.assertFalse(q.same_snapshot_authority({},{}))
 def test_no_socket_does_not_reconnect(self):
  connection=Mock();connection.sock=None
  self.assertFalse(q.http_attempt(connection,43123)['success']);connection.connect.assert_not_called();connection.request.assert_not_called()

class RollbackAndPhaseTests(unittest.TestCase):
 def authority(self,state='pending',desired=42):
  setup={'org_id':'org','site_id':'site','gateway_id':'gateway'}
  account={'owner':{'email':'browser-owner@azure-s2s.local','password':'PRIVATE'}}
  connection={'id':'connection','org_id':'org','site_id':'site','gateway_node_id':'gateway','desired_intent':'enabled','application_state':state,'deleted_at':None,'finalized_at':None,'desired_revision':desired}
  config={'configuration_revision':1,'profile_id':'azure-active-standby-bgp-ipv4-v1','configuration':{'azure':{'ike_version':2}}}
  baseline={'org':'org','site':'site','gateway':'gateway','connection':'connection','desired':42,'configuration':1,'profile':config['profile_id'],'config':config['configuration']}
  m={'accounts':'accounts','setup':'setup','connection':'connection','authority':baseline,'_restoring':True}
  return account,setup,connection,config,m
 def test_transient_application_state_is_rollback_only(self):
  for state in ('pending','not_applied','applied'):
   account,setup,connection,config,m=self.authority(state)
   for rollback in (False,True):
    client=Mock();client.call.side_effect=[connection,config]
    with patch.object(q.proof,'private_read',side_effect=[account,setup]),patch.object(q.lab,'Client',return_value=client):
     if not rollback and state!='applied':
      with self.assertRaises(ValueError):q.api_authority(m)
     else:self.assertEqual(q.api_authority(m,rollback=rollback),m['authority'])
 def test_rollback_refuses_superseded_or_disabled_binding(self):
  for change in ('desired','config','intent','gateway','unknown_state','missing_baseline'):
   account,setup,connection,config,m=self.authority()
   if change=='desired':connection['desired_revision']=43
   if change=='config':config=copy.deepcopy(config);config['configuration']['azure']['ike_version']=1
   if change=='intent':connection['desired_intent']='disabled'
   if change=='gateway':connection['gateway_node_id']='other'
   if change=='unknown_state':connection['application_state']='unknown'
   if change=='missing_baseline':m.pop('authority')
   client=Mock();client.call.side_effect=[connection,config]
   with patch.object(q.proof,'private_read',side_effect=[account,setup]),patch.object(q.lab,'Client',return_value=client),self.assertRaises(ValueError):q.api_authority(m,rollback=True)
 def test_restoration_mutations_recheck_without_recursive_flock(self):
  with tempfile.TemporaryDirectory() as temporary:
   directory=Path(temporary);m={'original_sha':'fixed','engines':[{}]}
   def fresh(material,engine):
    q.swan(material,'--terminate','--ike','owned')
    q.swan(material,'--initiate','--ike','owned')
    return {'remaining_seconds':27000,'child_remaining_seconds':2900}
   with patch.object(q,'identity'),patch.object(q,'api_authority') as authority,patch.object(q,'verify_conns') as staged,patch.object(q,'digest_file',return_value='fixed'),patch.object(q.proof,'private_bytes',return_value=b'production'),patch.object(q,'marker'),patch.object(q.common,'put_config',return_value='/run/tunnex-ipsec/owned-production.conf'),patch.object(q,'owned_mutation') as commands,patch.object(q,'fresh',side_effect=fresh),patch.object(q.common,'name',return_value='owned'),patch.object(q,'snapshot') as strict,patch.object(q.fcntl,'flock') as lock:
    q.restore(m,directory)
   self.assertEqual(lock.call_count,1)
   self.assertEqual([call.args[1] for call in commands.call_args_list],['--load-conns','--terminate','--initiate'])
   self.assertTrue(all(call.kwargs.get('rollback') is True for call in authority.call_args_list))
   self.assertGreaterEqual(staged.call_count,4);strict.assert_called_once_with(m)
   self.assertNotIn('_restoring',m);self.assertTrue((directory/'restored.json').exists())
 def test_changed_authority_refuses_before_any_restoration_command(self):
  with tempfile.TemporaryDirectory() as temporary:
   directory=Path(temporary);m={}
   with patch.object(q,'identity'),patch.object(q,'api_authority',side_effect=ValueError('superseded')),patch.object(q,'marker'),patch.object(q.common,'swan') as commands,patch.object(q.fcntl,'flock'):
    with self.assertRaises(ValueError):q.restore(m,directory)
   commands.assert_not_called();self.assertNotIn('_restoring',m)
   self.assertTrue((directory/'recovery-required.json').exists());self.assertFalse((directory/'restored.json').exists())
 def phase_summary(self,*,baseline=True,socket_changed=False,watchdog=False,boundary=False):
  kinds=('existing_tcp','existing_udp','fresh_tcp','fresh_udp');samples=[]
  for start,success in ((20,True),(30,True),(40,True),(60,False),(70,False)):
   row={kind:{'success':success,'start_monotonic':start,'end_monotonic':start+.1} for kind in kinds}
   row['existing_tcp'].update(original_local_port=43123,local_port_before_attempt=43124 if socket_changed else 43123,original_socket_present=True)
   row['existing_udp'].update(original_local_port=43125,local_port=43125)
   samples.append(row)
  if boundary:samples.append({kind:{'success':True,'start_monotonic':49.9,'end_monotonic':50.1} for kind in kinds})
  values={'packets.json':{'samples':samples,'counts':{kind:{'success':sum(row[kind]['success'] is True for row in samples),'failure':sum(row[kind]['success'] is not True for row in samples)} for kind in kinds}},'packets-started.json':{'all_four_succeeded':baseline,'original_tcp_local_port':43123,'original_udp_local_port':43125}}
  for stage,value in (('bootstrap-started',0),('bootstrap-ended',10),('automatic-started',15),('automatic-ended',80 if watchdog else 50),('restoration-started',50),('restoration-ended',90)):
   values[stage+'.json']={'stage':stage,'monotonic':value}
  with tempfile.TemporaryDirectory() as temporary:
   directory=Path(temporary)
   for name in values:(directory/name).touch()
   with patch.object(q.proof,'private_read',side_effect=lambda path:values[Path(path).name]):return q.packet_phase_summary(directory,True)
 def test_forced_restoration_losses_are_separate_from_scheduler(self):
  for watchdog in (False,True):
   summary=self.phase_summary(watchdog=watchdog)
   self.assertTrue(summary['sampled_continuity_pass'])
   for kind in ('existing_tcp','existing_udp','fresh_tcp','fresh_udp'):
    self.assertEqual(summary['counts_by_phase']['automatic_observation'][kind],{'success':3,'failure':0})
    self.assertEqual(summary['counts_by_phase']['restoration'][kind],{'success':0,'failure':2})
    self.assertEqual(summary['all_window_counts'][kind],{'success':3,'failure':2})
 def test_boundary_attempts_are_preserved_but_excluded(self):
  summary=self.phase_summary(boundary=True)
  self.assertTrue(summary['sampled_continuity_pass'])
  for kind in ('existing_tcp','existing_udp','fresh_tcp','fresh_udp'):
   self.assertEqual(summary['counts_by_phase']['outside_or_boundary'][kind],{'success':1,'failure':0})
   self.assertEqual(summary['counts_by_phase']['automatic_observation'][kind],{'success':3,'failure':0})
   self.assertEqual(summary['all_window_counts'][kind],{'success':4,'failure':2})
 def test_missing_baseline_or_changed_original_socket_cannot_qualify(self):
  self.assertFalse(self.phase_summary(baseline=False)['sampled_continuity_pass'])
  self.assertFalse(self.phase_summary(socket_changed=True)['sampled_continuity_pass'])

if __name__=='__main__':unittest.main()

class OwnedControlTests(unittest.TestCase):
 def test_foreground_and_restoration_never_use_generic_mutation(self):
  for restoring in (False,True):
   with tempfile.TemporaryDirectory() as temporary:
    m={'evidence_dir':temporary,'_restoring':restoring}
    with patch.object(q,'identity'),patch.object(q,'api_authority') as authority,patch.object(q,'verify_conns'),patch.object(q,'owned_mutation') as owned,patch.object(q.common,'swan') as generic:
     q.swan(m,'--terminate','--ike','owned','--timeout','20')
    owned.assert_called_once();generic.assert_not_called()
    self.assertEqual(authority.call_args.kwargs.get('rollback',False),restoring)
 def test_no_arbitrary_command_or_unowned_config(self):
  with patch.object(q,'owned_control') as control,patch.object(q.common,'swan') as generic:
   for args in (('--rekey','--ike','owned'),('--unload-conns',),('--load-creds',)):
    with self.assertRaises(ValueError):q.swan({},*args)
   with self.assertRaises(ValueError):q.owned_mutation({'run_id':'owned'},'--load-conns','--file','/tmp/unowned.conf')
  control.assert_not_called();generic.assert_not_called()
 def test_load_and_restore_modes_are_pinned(self):
  for restoring,target in ((False,'accelerated'),(True,'production')):
   m={'run_id':'owned','_restoring':restoring}
   with patch.object(q,'owned_control') as control:q.owned_mutation(m,'--load-conns','--file','/run/tunnex-ipsec/owned-'+target+'.conf')
   control.assert_called_once_with(m,'load-'+target);self.assertEqual(m['timer_mode'],target)
 def test_failed_load_does_not_claim_timer_transition(self):
  m={'run_id':'owned','timer_mode':'production'}
  with patch.object(q,'owned_control',side_effect=ValueError('refused')):
   with self.assertRaises(ValueError):q.owned_mutation(m,'--load-conns','--file','/run/tunnex-ipsec/owned-accelerated.conf')
  self.assertEqual(m['timer_mode'],'production')

class ControlFailureProjectionTests(unittest.TestCase):
 def test_only_single_known_fixed_stage_is_projected(self):
  self.assertEqual(q.fixed_control_failure(b'file.go:100: owned_scheduler_control_refused journal-bracket\n'),'journal-bracket')
  for value in (b'private arbitrary response',b'owned_scheduler_control_refused private-selector\n',b'owned_scheduler_control_refused loaded-schema\nowned_scheduler_control_refused guard-read\n'):
   self.assertEqual(q.fixed_control_failure(value),'unclassified')
 def test_daemon_text_is_not_part_of_projection(self):
  result=q.fixed_control_failure(b'private hostname and payload\nfile.go:100: owned_scheduler_control_refused terminate-no-match\n')
  self.assertEqual(result,'terminate-no-match');self.assertNotIn('private',result)

class PairedHelperPathTests(unittest.TestCase):
 def test_default_preserved_and_uuid4_pair_accepted(self):
  self.assertEqual(q.container_helper_path(),'/run/tunnex-ipsec/azure-scheduler.test')
  value='/run/tunnex-ipsec/azure-scheduler-924fbe83-b84a-4fbe-bffe-4c8dcf435012.test'
  self.assertEqual(q.container_helper_path(value),value)
 def test_arbitrary_noncanonical_and_other_namespace_paths_refused(self):
  for value in ('/tmp/helper.test','/run/tunnex-ipsec/azure-scheduler-../../helper.test','/run/tunnex-ipsec/azure-scheduler-924FBE83-b84a-4fbe-bffe-4c8dcf435012.test','/run/tunnex-ipsec/azure-scheduler-00000000-0000-0000-0000-000000000000.test','/run/tunnex-ipsec/charon.test'):
   with self.assertRaises(ValueError):q.container_helper_path(value)
