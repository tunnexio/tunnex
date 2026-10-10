#!/usr/bin/env python3
"""Copy only exact independently observed typed absence/binding to normal API input ownership."""
import argparse
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import uuid
s=importlib.util.spec_from_file_location('observer',Path(__file__).with_name('run-max-prefix-observer.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

def verify(receipt,binding,state,clock):
 allowed={'version','kind','observed_at','org_id','site_id','gateway_id','connection_id','desired_revision','configuration_revision','journal_sha256','journal_entries','scope','azure_connection_id','guard_retained','namespace_device','namespace_inode','owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes','historical_boot_entry_count','traffic_counters_monotonic_advanced','historical_proof_sha256','historical_stopped_journal_sha256','host_machine_identity_source'}
 if set(receipt)-allowed or receipt.get('version')!=1 or receipt.get('kind')!='owned_native_cleanup_absence' or receipt.get('guard_retained') is not True or binding['mode']!='absence' or receipt['scope']!='Independent bracketed native observation only; no authority, synthetic acknowledgement or packet readiness':raise ValueError('exact typed absence')
 if not 0<=(clock-m.p.timestamp(receipt['observed_at'])).total_seconds()<=60:raise ValueError('fresh receipt')
 for key in ('org_id','site_id','gateway_id'):
  if receipt[key]!=state['setup'][key] or binding[key]!=receipt[key]:raise ValueError('owned identity')
 if receipt['connection_id']!=state['prior']['id']:raise ValueError('prior identity')
 for key in ('connection_id','desired_revision','configuration_revision','namespace_device','namespace_inode'):
  if binding[key]!=receipt[key]:raise ValueError('bound absence')
 if 'cleanup_revision' in state and state['cleanup_revision']!=receipt['desired_revision']:raise ValueError('saved cleanup revision')
 for key in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes'):
  if type(receipt[key])!=int or receipt[key]!=0:raise ValueError('objects remain')
 if receipt['azure_connection_id']!='/subscriptions/34e2f259-b462-40bf-8f4a-06a3930d99e6/resourceGroups/tunnex-azure-s2s-20261010/providers/Microsoft.Network/connections/tunnex-connection':raise ValueError('ARM identity')
 if not re.fullmatch('[0-9a-f]{64}',receipt['journal_sha256']) or type(receipt['journal_entries'])!=int or not 1<=receipt['journal_entries']<=256:raise ValueError('whole journal metadata')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run-id',required=True);p.add_argument('--state',type=Path,required=True);p.add_argument('--receipt-sha256',required=True);p.add_argument('--binding-sha256',required=True);a=p.parse_args();os.umask(0o077)
 try:
  if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer' or not re.fullmatch('maxproof-window-[0-9a-f-]{36}',a.run_id):raise ValueError('owned copy')
  identifier=a.run_id[len('maxproof-window-'):]
  if str(uuid.UUID(identifier))!=identifier or uuid.UUID(identifier).version!=4:raise ValueError('exact run')
  if a.state.parent!=m.PRIVATE:raise ValueError('private state')
  parent=m.PRIVATE.stat()
  if parent.st_uid!=1000 or stat.S_IMODE(parent.st_mode)!=0o700:raise ValueError('normal private parent')
  directory=m.PRIVATE/a.run_id;proof=m.read_owned(directory/'native-receipt.json',0);binding=m.read_owned(directory/'binding.json',0);state=json.loads(m.read_owned(a.state,1000))
  for raw,pin in ((proof,a.receipt_sha256),(binding,a.binding_sha256)):
   if not re.fullmatch('[0-9a-f]{64}',pin) or hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('externally attested bytes')
  verify(json.loads(proof),json.loads(binding),state,datetime.now(timezone.utc))
  operation='max-prefix-typed-copy-'+str(uuid.uuid4())
  for name,raw in (('absence',proof),('binding',binding)):
   path=m.PRIVATE/(operation+'-'+name+'.json');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as f:os.fchown(f.fileno(),1000,1000);f.write(raw);f.flush();os.fsync(f.fileno())
  print(json.dumps({'category':'typed_absence_inputs_copied','private_run_id':operation,'receipt_sha256':a.receipt_sha256,'binding_sha256':a.binding_sha256,'scope':'Exact bytes/ownership copy only; no new observations or freshness extension'}))
 except (ValueError,TypeError,KeyError,OSError):raise SystemExit('typed_absence_copy_refused')
if __name__=='__main__':main()
