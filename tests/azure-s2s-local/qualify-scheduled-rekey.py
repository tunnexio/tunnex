#!/usr/bin/env python3
"""Owned Azure accelerated IKE scheduler qualification, not a production soak.
No execution is authorized by the presence of this source. Linux Docker host root only.
"""
import argparse
import datetime
import fcntl
import hashlib
import http.client
import socket
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'deploy/ipsec'))
import runtime_stop_proof as proof
import qualify_scheduled_ike as common

def adjacent(name):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
lab=adjacent('enroll-local')
OWNER='azure-s2s-01a12505'
NAME='tunnex-azure-cloud-gateway'
PROFILES={f'azure-{topology}-{mode}-ipv4-v1':1 if topology=='active-standby' else 2 for topology in ('active-active','active-standby') for mode in ('bgp','static')}

def digest_file(path):
 return hashlib.sha256(proof.private_bytes(path)).hexdigest()

def container_helper_path(value=None):
 if value is None or value=='/run/tunnex-ipsec/azure-scheduler.test':return '/run/tunnex-ipsec/azure-scheduler.test'
 match=re.fullmatch(r'/run/tunnex-ipsec/azure-scheduler-([0-9a-f-]{36})\.test',value)
 if not match:raise ValueError('owned_helper_path_required')
 try:identifier=uuid.UUID(match.group(1))
 except ValueError:raise ValueError('owned_helper_path_required')
 if str(identifier)!=match.group(1) or identifier.version!=4 or identifier.variant!=uuid.RFC_4122:raise ValueError('owned_helper_path_required')
 return value

def identity(m):
 container_helper_path(m['container_helper'])
 value=proof.inspect(m['container'])
 owner=proof.command('docker','inspect','--format','{{index .Config.Labels "tunnex.owner"}}',m['container'])
 image=proof.command('docker','inspect','--format','{{.Image}}',m['container'])
 name=proof.command('docker','inspect','--format','{{.Name}}',m['container'])
 if value['id']!=m['container'] or name!='/'+NAME or owner!=OWNER or image!=m['image'] or not value['state']['Running']:
  raise ValueError('owned_identity_refused')
 if 'pid' in m and (value['state']['Pid']!=m['pid'] or value['state']['StartedAt']!=m['started']):raise ValueError('process_identity_changed')
 if digest_file(m['helper'])!=m['helper_sha']:raise ValueError('helper_changed')
 inside=proof.command('docker','exec',m['container'],'sha256sum',m['container_helper']).split()[0]
 if inside!=m['helper_sha']:raise ValueError('installed_helper_changed')
 node=proof.command('docker','exec',m['container'],'sha256sum','/proc/1/exe').split()[0]
 if node!=m['node_sha']:raise ValueError('node_binary_changed')
 if 'native' in m:
  charon_pid=proof.command('docker','exec',m['container'],'cat','/run/tunnex-ipsec/charon.pid')
  if charon_pid!=str(m['native']['charon_pid']):raise ValueError('daemon_pid_changed')
  executable=proof.command('docker','exec',m['container'],'sha256sum','/proc/'+charon_pid+'/exe').split()[0]
  stat=proof.command('docker','exec',m['container'],'cat','/proc/'+charon_pid+'/stat')
  fields=stat[stat.rfind(')')+1:].split()
  if executable!=m['native']['charon_sha'] or len(fields)<=19 or fields[19]!=m['native']['charon_start_ticks']:raise ValueError('daemon_identity_changed')
 return value

def api_authority(m,rollback=False):
 accounts=proof.private_read(m['accounts']);setup=proof.private_read(m['setup'])
 if accounts['owner']['email']!='browser-owner@azure-s2s.local':raise ValueError('owner_account_refused')
 client=lab.Client(accounts['owner']);base='/api/v1/organizations/'+setup['org_id']
 connection=client.call('GET',base+'/ipsec/connections/'+m['connection'])
 config=client.call('GET',base+'/ipsec/connections/'+m['connection']+'/configuration')
 if (connection['id']!=m['connection'] or connection['org_id']!=setup['org_id'] or connection['site_id']!=setup['site_id'] or connection['gateway_node_id']!=setup['gateway_id'] or connection['desired_intent']!='enabled' or connection['application_state'] not in ({'applied','pending','not_applied'} if rollback else {'applied'}) or connection['deleted_at'] is not None or connection['finalized_at'] is not None):raise ValueError('normal_enabled_applied_authority_refused')
 projection={'org':connection['org_id'],'site':connection['site_id'],'gateway':connection['gateway_node_id'],'connection':connection['id'],'desired':connection['desired_revision'],'configuration':config['configuration_revision'],'profile':config['profile_id'],'config':config['configuration']}
 if projection['profile'] not in PROFILES:raise ValueError('azure_profile_refused')
 if rollback and 'authority' not in m:raise ValueError('rollback_baseline_required')
 if 'authority' in m and projection!=m['authority']:raise ValueError('normal_authority_changed')
 return projection

def same_snapshot_authority(before,after):
 # Lease TTLs are not serialized in the journal. Journal sequence/guard refresh
 # and native CHILD identities are fresh evidence, not stable material identity.
 # DeliveryID remains stable for the same desired revision in RuntimeStore.Material.
 keys=('profile','delivery','binding','engines','config','charon_pid','charon_sha','charon_start_ticks','retained_identity')
 return all(key in before and key in after and before[key]==after[key] for key in keys)

def snapshot(m):
 identity(m);authority=api_authority(m)
 path='/run/tunnex-ipsec/azure-scheduler-'+str(uuid.uuid4())+'.json'
 # The helper binary is already installed privately by the operator; never run
 # a binary selected by journal data or copy a binary into a live container.
 expected={'OrgID':authority['org'],'GatewayID':authority['gateway'],'ConnectionID':authority['connection'],'SiteID':authority['site'],'DesiredRevision':authority['desired'],'ConfigurationRevision':authority['configuration'],'ProfileID':authority['profile']}
 result=subprocess.run(['docker','exec','-e','TUNNEX_AZURE_SCHEDULED_REKEY_BINDING='+json.dumps(expected,separators=(',',':')),'-e','TUNNEX_AZURE_SCHEDULED_REKEY_TIMER_MODE='+m.get('timer_mode','production'),'-e','TUNNEX_AZURE_SCHEDULED_REKEY_SNAPSHOT=1','-e','TUNNEX_AZURE_EXPECTED_NODE_SHA256='+m['node_sha'],'-e','TUNNEX_AZURE_SCHEDULED_REKEY_OUTPUT='+path,m['container'],m['container_helper'],'-test.run=^TestAzureOwnedScheduledRekeySnapshot$','-test.count=1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25)
 if result.returncode:raise ValueError('strict_native_snapshot_refused')
 raw=proof.command('docker','exec',m['container'],'cat',path)
 value=json.loads(raw)
 # Snapshot is nonsecret, but is retained only in the private manifest.
 if value['profile']!=authority['profile'] or value['strict_native'] is not True or value['full_guard'] is not True or len(value['engines'])!=PROFILES[value['profile']]:raise ValueError('native_profile_refused')
 binding=value['binding']
 if (binding['OrgID']!=authority['org'] or binding['GatewayID']!=authority['gateway'] or binding['ConnectionID']!=authority['connection'] or binding['DesiredRevision']!=authority['desired'] or binding['ConfigurationRevision']!=authority['configuration']):raise ValueError('native_authority_binding_refused')
 if 'native' in m and not same_snapshot_authority(m['native'],value):raise ValueError('native_material_changed')
 identity(m);api_authority(m)
 return value

def accelerated(config,count):
 # The input is solely the exact Go-generated connection tree. Only parent IKE
 # timers change; all CHILD/provider material remains byte-identical.
 if config.count('rekey_time = 28800s')!=count or config.count('rekey_time = 3000s')!=count or config.count('life_time = 3600s')!=count:raise ValueError('production_timer_shape_refused')
 for seconds in (120,150)[:count]:
  config=config.replace('rekey_time = 28800s',f'rekey_time = {seconds}s\n    rand_time = 0s\n    over_time = 2880s',1)
 return config

def swan(m,*args):
 if args==('--list-sas',):return common.swan(m,*args)
 if not args or args[0] not in ('--load-conns','--terminate','--initiate'):raise ValueError('fixed_scheduler_command_required')
 if m.get('_restoring'):
  # Caller holds restore.lock; never recursively acquire it. This projection
  # authorizes only rollback to the privately pinned production configuration.
  identity(m);api_authority(m,rollback=True);verify_conns(m)
  return owned_mutation(m,*args)
 directory=Path(m['evidence_dir'])
 fd=os.open(directory/'restore.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  fcntl.flock(fd,fcntl.LOCK_EX)
  if (directory/'restored.json').exists() or (directory/'recovery-required.json').exists():raise ValueError('restoration_already_started')
  identity(m);api_authority(m);verify_conns(m)
  return owned_mutation(m,*args)
 finally:os.close(fd)
def owned_control(m,action,slot=0):
 native=m['native'];authority=m['authority']
 binding={'OrgID':authority['org'],'GatewayID':authority['gateway'],'ConnectionID':authority['connection'],'SiteID':authority['site'],'DesiredRevision':authority['desired'],'ConfigurationRevision':authority['configuration'],'ProfileID':authority['profile']}
 request={'Binding':binding,'Delivery':native['delivery'],'RetainedIdentity':native['retained_identity'],'CharonPID':native['charon_pid'],'CharonSHA':native['charon_sha'],'CharonStart':native['charon_start_ticks'],'NodeSHA':m['node_sha'],'ConfigSHA':hashlib.sha256(native['config'].encode()).hexdigest(),'Action':action,'Mode':'rollback' if m.get('_restoring') else m.get('timer_mode','production'),'Slot':slot}
 path='/run/tunnex-ipsec/azure-scheduler-request-'+str(uuid.uuid4())+'.json'
 # Input remains root-owned 0600 inside the owned container. Neither stdout nor
 # argv carries request material. No arbitrary config or command is passed.
 subprocess.run(['docker','exec','-i',m['container'],'/bin/sh','-c','umask 077; cat > '+path],input=json.dumps(request).encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
 result=subprocess.run(['docker','exec','-e','TUNNEX_AZURE_SCHEDULED_REKEY_CONTROL=1','-e','TUNNEX_AZURE_SCHEDULED_REKEY_REQUEST='+path,m['container'],m['container_helper'],'-test.run=^TestAzureOwnedScheduledRekeyControl$','-test.count=1'],capture_output=True,timeout=40)
 if result.returncode:
  stage=fixed_control_failure(result.stdout)
  proof.private_write(Path(m['evidence_dir'])/('control-refused-'+str(uuid.uuid4())+'.json'),{'action':action,'stage':stage,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
  raise ValueError('owned_control_refused')

def fixed_control_failure(output):
 allowed={'request-path','request-private-read','request-decode','node-identity','journal-read','binding-history','render-identity','namespace','daemon-identity','guard-read','journal-bracket','loaded-request','loaded-context','loaded-schema','arguments','render','load-request','load-response','action-request','action-response','action-context','terminate-no-match','terminate-partial','control-refused'}
 matches=re.findall(rb'owned_scheduler_control_refused ([a-z-]+)(?:\s|$)',output)
 if len(matches)!=1:return 'unclassified'
 value=matches[0].decode('ascii')
 return value if value in allowed else 'unclassified'

def owned_mutation(m,*args):
 if args[0]=='--load-conns':
  if len(args)!=3 or args[1]!='--file':raise ValueError('fixed_load_required')
  target='production' if m.get('_restoring') else 'accelerated'
  expected='/run/tunnex-ipsec/'+m['run_id']+'-'+target+'.conf'
  if args[2]!=expected:raise ValueError('fixed_owned_config_required')
  owned_control(m,'load-'+target);m['timer_mode']=target
 elif args[0] in ('--terminate','--initiate'):
  names=[common.name(engine) for engine in m['engines']]
  if args[0]=='--terminate':
   if len(args)!=5 or args[1]!='--ike' or args[3:]!=('--timeout','20') or args[2] not in names:raise ValueError('fixed_terminate_required')
   slot=names.index(args[2])+1
  else:
   if len(args)!=7 or args[1]!='--child' or args[3]!='--ike' or args[2]!=args[4] or args[5:]!=('--timeout','20') or args[2] not in names:raise ValueError('fixed_initiate_required')
   slot=names.index(args[2])+1
  owned_control(m,args[0][2:],slot)
 else:raise ValueError('fixed_mutation_required')
 return ''
def verify_conns(m):return owned_control(m,'verify')
def parse_sample(text,engines):
 values=common.sample(text,engines)
 for block in re.split(r'(?m)(?=^tnx-ipsec-)',text):
  header=re.match(r'^(tnx-ipsec-[^:]+):',block)
  if not header or header.group(1) not in values:continue
  timers=re.findall(r'\brekeying in (\d+)s\b',block)
  # A settled single CHILD is required for independent timer restoration.
  if len(timers)==2:values[header.group(1)]['child_remaining_seconds']=int(timers[1])
 return values
def sample(m):return parse_sample(swan(m,'--list-sas'),m['engines'])
def check(m):identity(m);api_authority(m,rollback=m.get('_restoring') is True);verify_conns(m)
def fresh(m,engine,maximum=None):
 check(m);name=common.name(engine);before=sample(m).get(name,{}).get('ike_serial')
 swan(m,'--terminate','--ike',name,'--timeout','20');check(m)
 swan(m,'--initiate','--child',name,'--ike',name,'--timeout','20')
 end=time.monotonic()+45
 while time.monotonic()<end:
  check(m);item=sample(m).get(name)
  if item and item['ike_serial']!=before and (0<item['remaining_seconds']<=maximum if maximum else 25900<=item['remaining_seconds']<=28800) and 2690<=item.get('child_remaining_seconds',-1)<=3000:return item
  time.sleep(1)
 raise ValueError('fresh_timer_not_verified')

def marker(directory,stage):
 if stage not in ('bootstrap-started','bootstrap-ended','automatic-started','automatic-ended','restoration-started','restoration-ended'):raise ValueError('fixed_marker_required')
 path=directory/(stage+'.json')
 try:proof.private_write(path,{'stage':stage,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'monotonic':time.monotonic()})
 except FileExistsError:
  if proof.private_read(path)['stage']!=stage:raise ValueError('marker_identity_changed')
 return proof.private_read(path)

def packet_phase_summary(directory,scheduler_passed):
 packets=proof.private_read(directory/'packets.json');baseline=proof.private_read(directory/'packets-started.json')
 stages={}
 for stage in ('bootstrap-started','bootstrap-ended','automatic-started','automatic-ended','restoration-started','restoration-ended'):
  path=directory/(stage+'.json')
  if path.exists():
   value=proof.private_read(path)
   if value['stage']!=stage or not isinstance(value['monotonic'],(int,float)):raise ValueError('marker_identity_changed')
   stages[stage]=value['monotonic']
 automatic_end=min(stages.get('automatic-ended',float('inf')),stages.get('restoration-started',float('inf')))
 intervals={'bootstrap':(stages.get('bootstrap-started',float('inf')),stages.get('bootstrap-ended',float('-inf'))),'automatic_observation':(stages.get('automatic-started',float('inf')),automatic_end),'restoration':(stages.get('restoration-started',float('inf')),stages.get('restoration-ended',float('inf')))}
 kinds=('existing_tcp','existing_udp','fresh_tcp','fresh_udp')
 original_tcp=baseline.get('original_tcp_local_port');original_udp=baseline.get('original_udp_local_port')
 socket_consistent=all(type(port) is int and 1<=port<=65535 for port in (original_tcp,original_udp))
 counts={phase:{kind:{'success':0,'failure':0} for kind in kinds} for phase in (*intervals,'outside_or_boundary')}
 for row in packets['samples']:
  for kind in kinds:
   value=row[kind];start=value['start_monotonic'];end=value['end_monotonic']
   if not isinstance(start,(int,float)) or not isinstance(end,(int,float)) or end<start:raise ValueError('packet_time_refused')
   selected='outside_or_boundary'
   for phase,(begin,finish) in intervals.items():
    if begin<=start<=end<=finish:selected=phase;break
   counts[selected][kind]['success' if value['success'] is True else 'failure']+=1
   if selected=='automatic_observation':
    if kind=='existing_tcp':socket_consistent=socket_consistent and value.get('original_local_port')==original_tcp and value.get('local_port_before_attempt')==original_tcp and value.get('original_socket_present') is True
    if kind=='existing_udp':socket_consistent=socket_consistent and value.get('original_local_port')==original_udp and (value.get('success') is not True or value.get('local_port')==original_udp)
 automatic=counts['automatic_observation']
 observed=bool(scheduler_passed and socket_consistent and baseline['all_four_succeeded'] is True and all(v['failure']==0 and v['success']>=3 for v in automatic.values()))
 return {'scope':'sampled-automatic-observation-only','sampled_continuity_pass':observed,'original_socket_identity_consistent':bool(socket_consistent),'original_socket_baseline_succeeded':baseline['all_four_succeeded'] is True,'counts_by_phase':counts,'all_window_counts':packets['counts'],'production_duration_soak':False}

def restore(m,directory):
 fd=os.open(directory/'restore.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  fcntl.flock(fd,fcntl.LOCK_EX)
  if (directory/'restored.json').exists():return
  m['_restoring']=True
  marker(directory,'restoration-started')
  check(m)
  if digest_file(directory/'original.conf')!=m['original_sha']:raise ValueError('original_configuration_changed')
  path=common.put_config(m,'production',proof.private_bytes(directory/'original.conf').decode())
  swan(m,'--load-conns','--file',path)
  sessions={common.name(e):fresh(m,e) for e in m['engines']}
  # Restore acceptance remains strict; transient normal pending is tolerated
  # only for the rollback commands, never as successful native/permit evidence.
  end=time.monotonic()+45
  while True:
   check(m)
   try:snapshot(m);break
   except Exception:
    if time.monotonic()>=end:raise ValueError('restored_strict_proof_missing')
    time.sleep(1)
  marker(directory,'restoration-ended')
  proof.private_write(directory/'restored.json',{'production_timers_verified':True,'sessions':sessions,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
 except Exception:
  if not (directory/'recovery-required.json').exists():proof.private_write(directory/'recovery-required.json',{'restored':False,'category':'authority_or_native_restoration_refused'})
  raise
 finally:
  m.pop('_restoring',None)
  os.close(fd)

def watchdog(directory):
 m=proof.private_read(directory/'manifest.json')
 identity(m)
 proof.private_write(directory/'watchdog-ready.json',{'armed':True})
 while time.monotonic()<m['watchdog_monotonic_deadline'] and not (directory/'restored.json').exists():time.sleep(1)
 if not (directory/'restored.json').exists():restore(m,directory)

def run(args):
 if os.geteuid()!=0:raise ValueError('host_root_required')
 helper_path=container_helper_path(getattr(args,'container_helper',None))
 directory=Path(args.evidence_dir)
 if not directory.is_absolute() or directory.parent.resolve()!=directory.parent:raise ValueError('canonical_directory_required')
 directory.mkdir(mode=0o700,exist_ok=False)
 if directory.is_symlink() or directory.parent.is_symlink():raise ValueError('private_directory_refused')
 m=vars(args).copy();m.pop('watchdog');m['container_helper']=helper_path;m['swanctl']='/opt/tunnex-ipsec/sbin/swanctl';m['vici']='unix:///run/tunnex-ipsec/charon.vici';m['strongswan_conf']='/run/tunnex-ipsec/strongswan.conf'
 value=identity(m);m.update(pid=value['state']['Pid'],started=value['state']['StartedAt'],run_id='azure-scheduler-'+str(uuid.uuid4()))
 inside=proof.command('docker','exec',m['container'],'sha256sum',m['container_helper']).split()[0]
 if inside!=m['helper_sha']:raise ValueError('installed_helper_changed')
 m['authority']=api_authority(m);m['native']=snapshot(m);m['engines']=m['native']['engines'];verify_conns(m)
 common_text=m['native']['config'];proof.private_write(directory/'original.json',{'config':common_text})
 fd=os.open(directory/'original.conf',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as stream:stream.write(common_text);stream.flush();os.fsync(stream.fileno())
 m['original_sha']=digest_file(directory/'original.conf');m['watchdog_monotonic_deadline']=time.monotonic()+420
 proof.private_write(directory/'manifest.json',m)
 log=os.open(directory/'watchdog.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--watchdog',str(directory)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True);os.close(log)
 end=time.monotonic()+10
 while not (directory/'watchdog-ready.json').exists():
  if time.monotonic()>end:raise ValueError('watchdog_not_armed')
  time.sleep(.1)
 events=None;packets=None;passed=False;observations=[]
 try:
  marker(directory,'bootstrap-started')
  check(m);path=common.put_config(m,'accelerated',accelerated(common_text,len(m['engines'])));swan(m,'--load-conns','--file',path)
  seeded={}
  for i,e in enumerate(m['engines']):seeded[common.name(e)]={'sample':fresh(m,e,(120,150)[i]),'monotonic':time.monotonic()}
  baseline_native=snapshot(m);marker(directory,'bootstrap-ended');proof.private_write(directory/'bootstrap-excluded.json',{'sessions':seeded,'children':baseline_native['children'],'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
  packets=subprocess.Popen(['ip','netns','exec','azure-s2s-client',sys.executable,str(Path(__file__).resolve()),'--packet-receipt',str(directory/'packets.json')],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  ready=directory/'packets-started.json';packet_deadline=time.monotonic()+10
  while not ready.exists():
   if packets.poll() is not None or time.monotonic()>packet_deadline:raise ValueError('packet_baseline_missing')
   time.sleep(.1)
  if proof.private_read(ready)['all_four_succeeded'] is not True:raise ValueError('packet_baseline_denied')
  events=common.RekeyEvents(m['pid'],m['vici'])
  import struct
  peer,uid,_=struct.unpack('3i',events.socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
  # Convert container PID to its host identity via NSpid, then attest executable.
  peer_status=Path(f'/proc/{peer}/status').read_text()
  match=re.search(r'^NSpid:\s+(.*)$',peer_status,re.M)
  if uid!=0 or not match or int(match.group(1).split()[-1])!=m['native']['charon_pid'] or hashlib.sha256(Path(f'/proc/{peer}/exe').read_bytes()).hexdigest()!=m['native']['charon_sha']:raise ValueError('event_peer_refused')
  marker(directory,'automatic-started')
  renewed=set();end=time.monotonic()+220
  while time.monotonic()<end:
   check(m);current=sample(m);native=snapshot(m);now=time.monotonic()
   if events.error:raise ValueError('event_monitor_refused')
   observations.append({'elapsed':now-min(x['monotonic'] for x in seeded.values()),'strict_native':True,'children':native['children']})
   for i,e in enumerate(m['engines']):
    name=common.name(e);old=seeded[name];item=current.get(name)
    if item and item['ike_serial']!=old['sample']['ike_serial']:
     elapsed=now-old['monotonic']
     if elapsed<(120,150)[i]-10 or not 0<item['remaining_seconds']<=(120,150)[i]:raise ValueError('unscheduled_replacement_refused')
     if any(event['connection']==name and event['old_id']==old['sample']['ike_serial'] and event['new_id']==item['ike_serial'] and event['new_state']=='ESTABLISHED' and event['monotonic']>=old['monotonic'] for event in events.events):renewed.add(name)
   if len(renewed)==len(m['engines']):passed=True;break
   time.sleep(2)
  if not passed:raise ValueError('scheduled_rekey_not_observed')
 finally:
  marker(directory,'automatic-ended')
  if events:events.close();proof.private_write(directory/'ike-events.json',events.events)
  proof.private_write(directory/'scheduler-result.json',{'scope':'accelerated-scheduled-IKE-only','pass':passed,'production_duration_soak':False,'packet_continuity_verified':False,'observations':observations})
  try:restore(m,directory)
  finally:
   if packets:
    try:packets.wait(timeout=260)
    except subprocess.TimeoutExpired:packets.terminate();packets.wait(timeout=5)
    if (directory/'packets.json').exists():proof.private_write(directory/'packet-phases.json',packet_phase_summary(directory,passed))
 print('Accelerated scheduler complete; production timers restored. Packet continuity and production-duration soak are separate.')

def http_attempt(connection,original_port):
 # Capture identity BEFORE request/getresponse; HTTPConnection may close its
 # socket internally on a timeout. Never reconnect the original flow.
 before=connection.sock.getsockname()[1] if connection.sock else original_port
 result={'success':False,'original_local_port':original_port,'local_port_before_attempt':before,'original_socket_present':connection.sock is not None}
 if connection.sock is None:return result
 try:
  connection.request('GET','/',headers={'Host':'app.azure-s2s.test'})
  response=connection.getresponse();body=response.read(16385)
  identity=adjacent('probe-packets').observed_http_identity(body,'10.233.10.2')
  result.update(identity)
  result['success']=response.status==200 and not response.will_close and identity['owned_service_confirmed'] and identity['source_preservation']=='preserved'
 except Exception:result['category']='http_exchange_failed'
 return result

def timed_packet(operation):
 start=time.monotonic();utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
 value=operation()
 return {**value,'start_monotonic':start,'end_monotonic':time.monotonic(),'started_utc':utc,'ended_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}

def packet_probe(path):
 if os.geteuid()!=0 or not path.is_absolute() or path.parent.resolve()!=path.parent:raise ValueError('private_packet_path_required')
 probe=adjacent('probe-packets');rows=[];tcp=None;udp=None
 try:
  tcp=http.client.HTTPConnection('10.231.1.4',8080,timeout=.5,source_address=('10.233.10.2',0));tcp.connect();tcp_port=tcp.sock.getsockname()[1]
  udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('10.233.10.2',0));udp.connect(('10.231.1.4',8081));udp.settimeout(.5);udp_port=udp.getsockname()[1]
  deadline=time.monotonic()+240;index=0
  while time.monotonic()<deadline:
   row={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'existing_tcp':timed_packet(lambda:http_attempt(tcp,tcp_port))}
   row['existing_udp']=timed_packet(lambda:{'original_local_port':udp_port,**probe.udp_echo(udp,probe.udp_payload(64,index))});index+=1
   fresh=http.client.HTTPConnection('10.231.1.4',8080,timeout=.5,source_address=('10.233.10.2',0))
   def fresh_tcp():
    try:fresh.connect();return http_attempt(fresh,fresh.sock.getsockname()[1])
    except Exception:return {'success':False,'category':'http_connect_failed'}
    finally:fresh.close()
   row['fresh_tcp']=timed_packet(fresh_tcp)
   fresh_udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
   def fresh_udp_attempt():
    try:
     fresh_udp.bind(('10.233.10.2',0));fresh_udp.connect(('10.231.1.4',8081));fresh_udp.settimeout(.5)
     return probe.udp_echo(fresh_udp,probe.udp_payload(64,index))
    except Exception:return {'success':False,'category':'udp_connect_failed'}
    finally:fresh_udp.close()
   row['fresh_udp']=timed_packet(fresh_udp_attempt);index+=1
   rows.append(row)
   if len(rows)==1:proof.private_write(path.with_name('packets-started.json'),{'all_four_succeeded':all(row[kind]['success'] is True for kind in ('existing_tcp','existing_udp','fresh_tcp','fresh_udp')),'original_tcp_local_port':tcp_port,'original_udp_local_port':udp_port})
   time.sleep(.5)
 finally:
  if tcp:tcp.close()
  if udp:udp.close()
  counts={kind:{'success':sum(r[kind]['success'] is True for r in rows),'failure':sum(r[kind]['success'] is not True for r in rows)} for kind in ('existing_tcp','existing_udp','fresh_tcp','fresh_udp')}
  proof.private_write(path,{'scope':'owned_source2_existing_application_only','counts':counts,'samples':rows,'production_duration_soak':False})

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--watchdog');p.add_argument('--packet-receipt');p.add_argument('--container-helper')
 for name in ('container','image','node-sha','helper','helper-sha','accounts','setup','connection','evidence-dir'):p.add_argument('--'+name)
 a=p.parse_args()
 try:
  if a.packet_receipt:packet_probe(Path(a.packet_receipt))
  elif a.watchdog:watchdog(Path(a.watchdog))
  else:
   if any(getattr(a,key) is None for key in ('container','image','node_sha','helper','helper_sha','accounts','setup','connection','evidence_dir')):raise ValueError('explicit_inputs_required')
   if not re.fullmatch('[0-9a-f]{64}',a.container) or not re.fullmatch('sha256:[0-9a-f]{64}',a.image) or any(not re.fullmatch('[0-9a-f]{64}',value) for value in (a.node_sha,a.helper_sha)):raise ValueError('exact_identity_required')
   uuid.UUID(a.connection);run(a)
 except Exception:
  print('Owned Azure scheduler qualification refused; inspect private fixed-category receipts. No production-soak claim.',file=sys.stderr);return 1
 return 0
if __name__=='__main__':raise SystemExit(main())
