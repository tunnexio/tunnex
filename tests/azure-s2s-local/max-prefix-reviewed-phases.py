#!/usr/bin/env python3
"""Reviewed one-phase dispatcher; never automatically repeat mutations or change cloud."""
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import uuid
SOURCE=Path('/home/ubuntu/tunnex-azure-lab/reviewed-max-prefix-observer-v4-finalized54')
PRIVATE=Path('/home/ubuntu/tunnex-azure-lab/tests/azure-s2s-local/.runtime')
M=PRIVATE/'maximum-prefix-M-20261010-8eb31c7e.json'
D=PRIVATE/'dns-profile-transition-9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99.json'
PHASES=('dns-read','dns-revoke','read','restore-read','finalized-read','disable','delete','create','enable','baseline-prepare','baseline-read','baseline-finalized-read','baseline-disable','baseline-delete','baseline-create','baseline-enable','dns-rebind','dns-reconcile','dns-sync-grants')

def private_file(path):
 if path is None or path.parent!=PRIVATE or path.resolve()!=path:raise ValueError('private input')
 s=path.stat()
 if s.st_uid!=1000 or stat.S_IMODE(s.st_mode)!=0o600 or not stat.S_ISREG(s.st_mode):raise ValueError('private input owner')
 return path

def argv(a,output):
 phase=a.phase
 if phase.startswith('dns-'):
  if any(getattr(a,k) is not None for k in ('absence','absence_sha256','binding','psk','discovery')):raise ValueError('unrelated inputs')
  command=['python3',str(SOURCE/'tests/azure-s2s-local/rebind-profile-dns.py'),phase[4:],'--private-root',str(PRIVATE),'--state-file',str(private_file(D))]
  if phase in ('dns-rebind','dns-reconcile'):command+=['--transition-file',str(private_file(a.restored_state))]
  elif a.restored_state is not None:raise ValueError('unexpected restored state')
  return command
 baseline=phase.startswith('baseline-');native=phase[9:] if baseline else phase
 state=a.restored_state if baseline else M
 if baseline:
  if state is None or state.parent!=PRIVATE or state.resolve()!=state or state in (M,D):raise ValueError('new separate baseline state')
  if native!='prepare':private_file(state)
  elif state.exists():raise ValueError('baseline prepare is exclusive')
 elif a.restored_state is not None:raise ValueError('unrelated baseline state')
 private_file(M)
 command=['python3',str(SOURCE/'tests/azure-s2s-local/qualify-max-prefix-api.py'),native,'--private-root',str(PRIVATE),'--state',str(state),'--purpose','baseline' if baseline else 'limit','--output',str(output)]
 if native=='prepare':command+=['--allocation',str(M),'--baseline-state',str(M)]
 if native in ('delete','create'):
  import re
  if not isinstance(a.absence_sha256,str) or not re.fullmatch('[0-9a-f]{64}',a.absence_sha256):raise ValueError('root attested actual absence digest')
  command+=['--native-absence',str(private_file(a.absence)),'--native-sha256',a.absence_sha256,'--native-binding',str(private_file(a.binding))]
 elif any(getattr(a,k) is not None for k in ('absence','absence_sha256','binding')):raise ValueError('unexpected absence inputs')
 if native=='create':command+=['--psk-file',str(private_file(a.psk)),'--discovery',str(private_file(a.discovery))]
 elif a.psk is not None or a.discovery is not None:raise ValueError('unexpected secret/topology inputs')
 return command

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=PHASES)
 for name in ('absence','binding','psk','discovery','restored-state'):p.add_argument('--'+name,type=Path)
 p.add_argument('--absence-sha256');a=p.parse_args();os.umask(0o077)
 try:
  if os.getuid()!=1000 or socket.gethostname()!='tunnex-peer' or PRIVATE.resolve()!=PRIVATE:raise ValueError('owned peer')
  st=PRIVATE.stat()
  if st.st_uid!=1000 or stat.S_IMODE(st.st_mode)!=0o700:raise ValueError('private runtime')
  private_file(D)
  operation='max-prefix-phase-'+a.phase+'-'+str(uuid.uuid4());output=PRIVATE/(operation+'.json');log=PRIVATE/(operation+'.log')
  command=argv(a,output)
  # Exclusive private log reservation precedes the single child invocation. A new log never authorizes replay.
  fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as stream:
   try:r=subprocess.run(command,stdout=stream,stderr=stream,timeout=90)
   except subprocess.TimeoutExpired:print(json.dumps({'category':'phase_outcome_unknown_no_replay','phase':a.phase,'private_run_id':operation}));raise SystemExit(1)
  if r.returncode!=0:print(json.dumps({'category':'phase_refused_or_unknown_no_replay','phase':a.phase,'private_run_id':operation}));raise SystemExit(1)
  print(json.dumps({'category':'phase_helper_returned_success_requires_actual_readback','phase':a.phase,'private_run_id':operation,'scope':'No native cleanup, packet or cloud proof inferred'}))
 except (ValueError,TypeError,KeyError,OSError):raise SystemExit('reviewed_phase_dispatch_refused')
if __name__=='__main__':main()
