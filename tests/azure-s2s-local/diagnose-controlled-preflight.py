#!/usr/bin/env python3
"""Key-free read-only diagnosis of the exact failed owned restart preflight."""
import argparse
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import time
spec=importlib.util.spec_from_file_location('restart',Path(__file__).with_name('restart-owned-anchored-runtime.py'))
restart=importlib.util.module_from_spec(spec);spec.loader.exec_module(restart)

def changed_paths(before,after,path=''):
 if type(before)!=type(after):return [path or '/']
 if isinstance(before,dict):
  output=[]
  for key in sorted(set(before)|set(after)):
   # Only known product schema keys; arbitrary IDs/map keys never enter stdout.
   child=path+'/'+key if key in ALLOWED else path+'/<map-key>'
   if key not in before or key not in after:output.append(child)
   else:output.extend(changed_paths(before[key],after[key],child))
  return output
 if isinstance(before,list):
  if len(before)!=len(after):return [path+'/length']
  return [item for index,(b,a) in enumerate(zip(before,after)) for item in changed_paths(b,a,path+'/'+str(index))]
 return [] if before==after else [path]
ALLOWED=set('Payload Entries Sequence Version Checksum OwnerID Phase ContractVersion DeliveryID Revision Allocation Restoration Recovery Observed BGP Guard Config TunnelStatus Diagnostic Status Proof Source Plan Processes Retired Namespace BootID Epoch Generation Hash EvidenceDigest TransportProfile PeerAddressBits GuardState Stage SelectedSlot PendingFrom PendingTo Accepted Installed Routes Peers Process PID StartTicks ConfigHash InterfaceIndex InterfaceName IfID Slot MTU SourceBudget Address Prefix SourceRoute LeaseID ExpiresAt ConfigVersion StatusSequence AppliedRevision ConnectionID GatewayNodeID OrgID SiteID ProfileID RemotePrefixes LocalPrefixes CreatedAt UpdatedAt LastObserved LastRefresh ObservedAt RouteSelection Lease Deadline'.split())
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('journal','evidence-dir','private-root','lifecycle-helper'):p.add_argument('--'+name,required=True)
 a=p.parse_args();stage='prerequisites'
 try:
  if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer':raise ValueError('owned root host')
  directory=Path(a.evidence_dir);restart.evidence_parent(directory,Path(a.private_root));restart.gated.private_directory(directory)
  journal=Path(a.journal);restart.gated.private_directory(journal.parent)
  keys=('before-health.json','baseline-packets.json','before.json','stopped.json','stopped-journal.json')
  output={'stage':'read_only_preflight_diagnosis','files_present':{key:(directory/key).exists() for key in keys},'gate_present':os.path.lexists(journal.parent/'restoration-startup-gate')}
  helper=Path(a.lifecycle_helper);info=helper.lstat()
  if not helper.is_absolute() or helper.resolve()!=helper or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('reviewed API helper ownership')
  stage='normal_api_health'
  result=subprocess.run(['sudo','-u','#1000','--','python3',a.lifecycle_helper,'read','--private-root',a.private_root],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
  output['api_exit_success']=result.returncode==0
  output['fresh_both_up_established_route']=False
  if result.returncode==0:
   try:restart.healthy(json.loads(result.stdout),datetime.now(timezone.utc));output['fresh_both_up_established_route']=True
   except (ValueError,KeyError,TypeError):pass
  stage='journal_paths_only'
  first=json.loads(restart.gated.private_bytes(journal,16<<20));time.sleep(1)
  second=json.loads(restart.gated.private_bytes(journal,16<<20))
  output['journal_changed_paths']=sorted(set(changed_paths(first,second)))[:128]
  print(json.dumps(output,sort_keys=True));return 0
 except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
  print(json.dumps({'stage':stage,'error_code':'preflight_diagnosis_refused'}));return 1
if __name__=='__main__':raise SystemExit(main())
