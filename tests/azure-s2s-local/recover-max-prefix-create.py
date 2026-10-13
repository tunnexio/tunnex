#!/usr/bin/env python3
"""One reviewed same-ID recovery after a root-attested HTTP409; default read-only.

The original reservation and request identities remain unchanged. Unknown HTTP
outcomes never authorize this path. Root must separately verify the deployed API
and node source pair, migrate safely, and provide newly observed native absence.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket

spec=importlib.util.spec_from_file_location('owned_max_recovery',Path(__file__).with_name('qualify-max-prefix-api.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
INITIAL_API={'container_id':'693e00780062508d0620e5f7fdbba3cc5958007f428172ba633514df6898968f','image':'sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6','started_at':'2026-10-10T23:34:03.336943013Z','executable_sha256':'70bf3b43812466135018bcae5bae61670836e9b4c6117063838889d3df7f985b'}

def digest(raw,pin):
 if not isinstance(pin,str) or not re.fullmatch('[0-9a-f]{64}',pin) or hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('externally attested bytes required')

def refused_request(evidence,state,state_bytes):
 if state.get('version')!=1 or state.get('purpose')!='limit' or state.get('stage')!='create_reserved' or state['prior']['id']!=m.ORIGINAL:raise ValueError('exact original limit reservation')
 target=state['target'];ids=[m.life.identifier(v) for v in target['tunnel_ids']]
 if len(ids)!=2 or len(set(ids+[m.life.identifier(target['id']),m.ORIGINAL]))!=4:raise ValueError('same distinct reserved identities')
 if evidence['saved_stage']!=state['stage'] or evidence['target']!=target or evidence['state_sha256']!=hashlib.sha256(state_bytes).hexdigest() or evidence['cleanup_revision']!=state['cleanup_revision']:raise ValueError('actual unchanged reservation binding')
 if evidence['creation_marker'] is not True or evidence['phase_log_generic_refusal_verified'] is not True or evidence['unparsed_lines']!=0 or evidence['api_identity']!=INITIAL_API:raise ValueError('root-attested original dispatch required')
 if not re.fullmatch('max-prefix-phase-create-[0-9a-f-]{36}',evidence['phase_run_id']) or not re.fullmatch('[0-9a-f]{64}',evidence['private_raw_log_sha256']):raise ValueError('actual private evidence identity')
 rows=evidence['selected_http_rows']
 if len(rows)!=2 or [(v['event'],v['path_kind'],v['method'],v['status']) for v in rows]!=[('http_request','configuration_check','POST',200),('http_request','create','POST',409)]:raise ValueError('confirmed HTTP409 only; ambiguity never replayed')
 marker=m.instant(evidence['creation_marker_mtime']);check=m.instant(rows[0]['time']);post=m.instant(rows[1]['time']);end=m.instant(evidence['phase_log_mtime']);observed=m.instant(evidence['observed_at'])
 if not 0<=(post-check).total_seconds()<=5 or not 0<=(post-marker).total_seconds()<=5 or abs((post-end).total_seconds())>1 or post>observed:raise ValueError('bounded original request chronology')
 return target

def gateway_ready(client,setup):
 path='/api/v1/organizations/'+setup['org_id']+'/ipsec/eligibility?site_id='+setup['site_id']+'&gateway_node_id='+setup['gateway_id']
 raw=client.call('GET',path);gate=raw.get('azure_bgp_recreation')
 if not isinstance(gate,dict) or gate.get('eligible') is not True or gate.get('reason')!='eligible':raise ValueError('fresh explicit Azure BGP recreation capability required')

def current_binding(binding,binding_bytes,binding_hash,prior,node_hash):
 digest(binding_bytes,binding_hash)
 if json.loads(binding_bytes)!=binding or not isinstance(node_hash,str) or not re.fullmatch('[0-9a-f]{64}',node_hash):raise ValueError('root-attested current native source binding')
 if set(binding)!=set(prior) or 'node_executable_sha256' not in prior or binding['node_executable_sha256']!=node_hash:raise ValueError('current source-paired native executable')
 # A reviewed source replacement does not rewrite the historical delete proof.
 # Every normal/native/namespace/history field remains exact; only the current
 # independently attested executable may differ from the historical executable.
 if any(binding[k]!=v for k,v in prior.items() if k!='node_executable_sha256'):raise ValueError('original native context changed')

def recover(client,setup,state_path,evidence,evidence_bytes,evidence_hash,absence,absence_bytes,absence_hash,binding,binding_bytes,binding_hash,node_hash,psk,discovery,execute=False):
 digest(evidence_bytes,evidence_hash)
 if json.loads(evidence_bytes)!=evidence:raise ValueError('refusal byte binding')
 state_bytes=m.secure.read(state_path);state=json.loads(state_bytes)
 if state['setup']!=setup:raise ValueError('current owned setup')
 target=refused_request(evidence,state,state_bytes)
 if m.secure.read(state_path.with_name(state_path.name+'.create-reserved'))!=b'owned maximum-prefix operation reserved\n':raise ValueError('original durable marker')
 # This makes real fresh same-ID404 and finalized-prior/metadata/policy reads.
 prior=m.operate('reserved-prior-read',client,setup,state_path)
 if prior['reserved_target_absence']['id']!=target['id']:raise ValueError('same reserved target')
 current_binding(binding,binding_bytes,binding_hash,state['native_binding'],node_hash)
 if absence.get('node_executable_sha256')!=node_hash:raise ValueError('fresh actual native proof executable provenance')
 if type(absence.get('configuration_revision'))!=int or absence['configuration_revision']!=binding.get('configuration_revision') or binding['configuration_revision']!=state['original_configuration']['configuration_revision']:raise ValueError('exact archived/native configuration revision')
 m.native_absence(absence,absence_bytes,absence_hash,binding,setup,m.ORIGINAL,state['cleanup_revision'])
 gateway_ready(client,setup)
 config=m.checked_create_configuration(state,client,setup,'limit',psk,discovery)
 if m.secure.read(state_path)!=state_bytes:raise ValueError('saved reservation changed')
 recovery_marker=state_path.with_name(state_path.name+'.same-id-recovery-reserved')
 if recovery_marker.exists() or recovery_marker.is_symlink():raise ValueError('recovery outcome must be read; no second dispatch')
 result={'version':1,'phase':'same-id-recovery-preflight','observed_at':datetime.now(timezone.utc).isoformat(),'target_id':target['id'],'root_refusal_evidence_sha256':evidence_hash,'dispatch_sent':False,'scope':'Fresh same-ID404, finalized-prior, explicit capability, configuration and independently supplied native absence checks only; no creation or native health inferred'}
 if not execute:return result
 # One exclusive recovery marker, never a new connection/tunnel allocation.
 m.reserve(recovery_marker)
 m.native_absence(absence,absence_bytes,absence_hash,binding,setup,m.ORIGINAL,state['cleanup_revision'])
 m.fresh(discovery['observed_at'],datetime.now(timezone.utc))
 gateway_ready(client,setup)
 m.operate('reserved-prior-read',client,setup,state_path)
 if m.secure.read(state_path)!=state_bytes:raise ValueError('saved reservation changed before dispatch')
 m.native_absence(absence,absence_bytes,absence_hash,binding,setup,m.ORIGINAL,state['cleanup_revision'])
 m.fresh(discovery['observed_at'],datetime.now(timezone.utc))
 result['phase']='same-id-recovery-dispatch';result['dispatch_sent']=True
 base='/api/v1/organizations/'+setup['org_id']+'/ipsec/connections'
 result['outcome_stage']='create_http'
 try:
  raw=client.call('POST',base,{**target,'name':'Azure owned maximum-prefix limit','site_id':setup['site_id'],'gateway_node_id':setup['gateway_id'],'configuration':config})
  result['outcome_stage']='create_response'
  row=m.life.connection_projection(raw,setup,target['id'])
  if row['desired_revision']!=1 or row['desired_intent']!='disabled':raise ValueError('same-ID initial disabled response')
  result['outcome_stage']='configuration_readback'
  actual=client.call('GET',base+'/'+target['id']+'/configuration');expected=m.configuration(state['original_configuration'],'limit');expected.pop('profile_id')
  if actual['profile_id']!=m.PROFILE or actual['configuration']!=expected:raise ValueError('exact immutable recovered configuration')
  result['outcome_stage']='policy_readback'
  m.no_grants(client,'/api/v1/organizations/'+setup['org_id'])
  result['outcome_stage']='saved_state_readback'
  if m.secure.read(state_path)!=state_bytes:raise ValueError('saved reservation changed after dispatch')
 except m.api.APIError as error:
  result.update(category='outcome_requires_read_no_replay',http_status=error.status,api_code=error.code)
  return result
 except (http.client.HTTPException,ValueError,KeyError,TypeError,OSError):
  result.update(category='outcome_requires_read_no_replay',failure_class='post_dispatch_response_or_readback_unknown')
  return result
 result['outcome_stage']='readback_complete'
 result.update(category='same_id_disabled_created_requires_independent_read',normal_connection={**m.contract(actual,target['id']),**row},policy_count=0)
 result['scope']='One exact original same-ID request after source-reviewed HTTP409 recovery; disabled normal API/config response only, no runtime/packet/native acceptance'
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('private-root','state','refusal','native-absence','native-binding','psk-file','discovery','output'):p.add_argument('--'+name,type=Path,required=True)
 for name in ('refusal-sha256','native-sha256','native-binding-sha256','node-executable-sha256'):p.add_argument('--'+name,required=True)
 p.add_argument('--execute',action='store_true');a=p.parse_args();os.umask(0o077)
 if os.getuid()!=1000 or socket.gethostname()!='tunnex-peer':raise ValueError('owned normal API peer')
 root=m.secure.private_root(str(a.private_root))
 for path in (a.state,a.refusal,a.native_absence,a.native_binding,a.psk_file,a.discovery,a.output):
  if path.parent!=root or path.resolve()!=path:raise ValueError('exact private input')
 if a.output.exists() or a.output.is_symlink():raise ValueError('exclusive separate output')
 m.reserve(a.output.with_name(a.output.name+'.output-reserved'))
 setup=json.loads(m.secure.read(root/'api-setup.json'));accounts=json.loads(m.secure.read(root/'ui-accounts.json'))
 accounts=accounts.get('accounts',list(accounts.values())) if isinstance(accounts,dict) else accounts
 owners=[v for v in accounts if v.get('email')=='browser-owner@azure-s2s.local']
 if len(owners)!=1:raise ValueError('exact owner login')
 client=m.api.Client();client.call('POST','/api/v1/auth/login',{'email':owners[0]['email'],'password':owners[0]['password']})
 refusal=m.secure.read(a.refusal);native=m.secure.read(a.native_absence);binding=m.secure.read(a.native_binding)
 result=recover(client,setup,a.state,json.loads(refusal),refusal,a.refusal_sha256,json.loads(native),native,a.native_sha256,json.loads(binding),binding,a.native_binding_sha256,a.node_executable_sha256,m.secure.key(a.psk_file),json.loads(m.secure.read(a.discovery)),a.execute)
 m.secure.write(a.output,result);print(json.dumps(result))
 if result.get('category')=='outcome_requires_read_no_replay':raise SystemExit(1)

if __name__=='__main__':
 try:main()
 except (ValueError,TypeError,KeyError,OSError,m.api.APIError):raise SystemExit('Owned same-ID create recovery refused; preserve every reservation and use normal read.')
