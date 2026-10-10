#!/usr/bin/env python3
"""Bastion-only protected VNet add/restore for a new owned maximum-prefix connection."""
import argparse
from datetime import datetime,timezone
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import subprocess


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
prefix=load('max_cloud_prefix',Path(__file__).with_name('qualify-owned-unapproved-prefix.py'))
collector=load('max_cloud_collector',Path(__file__).with_name('collect-owned-prefix-ranges.py'))
api=load('max_api',Path(__file__).resolve().parents[2]/'tests/azure-s2s-local/qualify-max-prefix-api.py')
helpers=prefix.helpers


def normal(receipt,clock,expected=None):
 if receipt.get('version')!=1 or receipt.get('purpose')!='limit':raise ValueError('normal maximum-prefix receipt')
 helpers.fresh(receipt['observed_at'],clock)
 value=receipt['normal_connection'];wanted={key:value[key] for key in ('id','desired_revision','configuration_revision','profile_id','remote_prefixes','maximum_prefixes')};collector.expected_contract(wanted)
 if wanted['id']==prefix.CP:raise ValueError('new maximum-prefix target required')
 if value.get('desired_intent') not in ('enabled','disabled') or value.get('application_state') not in ('applied','pending','not_applied') or receipt.get('policy_count')!=0:raise ValueError('owned nongranted normal status')
 if expected is not None and any(wanted[key]!=expected[key] for key in ('id','configuration_revision','profile_id','remote_prefixes','maximum_prefixes')):raise ValueError('test connection immutable binding changed')
 return wanted


def baseline(proof,current,namespace,clock):
 if proof.get('version')!=1 or proof.get('kind')!='owned_max_prefix_baseline':raise ValueError('independent actual baseline proof required')
 helpers.fresh(proof['observed_at'],clock)
 if any(proof.get(key)!=value for key,value in [('connection_id',current['id']),('desired_revision',current['desired_revision']),('configuration_revision',current['configuration_revision']),('namespace',namespace)]):raise ValueError('baseline proof identity')
 if proof.get('native')!={'sad':4,'spd_in':2,'spd_out':2,'spd_fwd':2}:raise ValueError('strict baseline native counts')
 if proof.get('tunnels')!=[{'slot':1,'state':'up','owned_ike':1,'owned_installed_children':1},{'slot':2,'state':'up','owned_ike':1,'owned_installed_children':1}]:raise ValueError('strict owned tunnel baseline')
 if proof.get('bgp')!={'peers':[{'slot':1,'state':'established','accepted_prefixes':1},{'slot':2,'state':'established','accepted_prefixes':1}],'routes':['10.231.0.0/16']}:raise ValueError('actual one-prefix BGP baseline')


def evidence(review,candidate,clock,receipt,proof):
 current=normal(receipt,clock)
 if receipt['normal_connection'].get('desired_intent')!='enabled' or receipt['normal_connection'].get('application_state')!='applied':raise ValueError('enabled Applied baseline required for add')
 if candidate!='10.235.77.0/24' or review.get('version')!=1 or review.get('kind')!='owned_prefix_range_review':raise ValueError('review kind/candidate')
 for key,value in [('subscription',prefix.lab.SUBSCRIPTION),('resource_group',prefix.lab.RG),('owner',prefix.lab.OWNER),('vnet_id',prefix.VNET),('candidate',candidate)]:
  if review.get(key)!=value:raise ValueError('fresh range review ownership')
 helpers.fresh(review['observed_at'],clock)
 if any(review['normal_connection'].get(key)!=value for key,value in current.items()) or review['normal_connection'].get('desired_intent')!='enabled' or review['normal_connection'].get('application_state')!='applied':raise ValueError('range review current revision')
 if review.get('candidate_reservation')!={'connection_id':current['id'],'configuration_revision':current['configuration_revision'],'prefix':candidate}:raise ValueError('only intended approved reservation')
 hashes=review.get('source_sha256')
 if not isinstance(hashes,list) or len(hashes)!=3 or any(not isinstance(v,str) or len(v)!=64 or any(c not in '0123456789abcdef' for c in v) for v in hashes):raise ValueError('review source hashes')
 namespace=review.get('namespace')
 if not isinstance(namespace,dict) or set(namespace)!=set(('device','inode')) or any(type(v)!=int or v<1 for v in namespace.values()):raise ValueError('actual namespace binding')
 ranges=review['ranges']
 if not isinstance(ranges,list) or not 1<=len(ranges)<=512:raise ValueError('reviewed range bounds')
 for value in ranges:
  if ipaddress.ip_network(candidate).overlaps(ipaddress.ip_network(value,strict=True)):raise ValueError('candidate range overlap')
 baseline(proof,current,namespace,clock)
 return current


def run(phase,state_path,receipt,review=None,proof=None):
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 if state_path.exists() or state_path.is_symlink():helpers.private_read(state_path)
 else:prefix.lab.output_preflight(state_path)
 clock=datetime.now(timezone.utc);current=normal(receipt,clock)
 if phase!='prepare':
  saved=json.loads(helpers.private_read(state_path))
  if saved.get('qualification')!='owned_maximum_prefix' or not isinstance(saved.get('normal_binding'),dict):raise ValueError('separate maximum-prefix state required')
  normal(receipt,clock,saved['normal_binding'])
 def check(r,c,t):return evidence(r,c,t,receipt,proof)
 def reservation(action,state):
  if state.get('qualification')!='owned_maximum_prefix':raise ValueError('exclusive owned experiment binding')
  normal(receipt,datetime.now(timezone.utc),state['normal_binding'])
  api.reserve(state_path.with_name(state_path.name+'.'+action+'-reserved'))
 result=prefix.run(phase,state_path,review,evidence_check=check,reservation=reservation)
 if phase=='prepare':
  saved=json.loads(helpers.private_read(state_path));saved['qualification']='owned_maximum_prefix';saved['normal_binding']=current;prefix.private_write(state_path,saved)
 result['scope']='Owned maximum-prefix cloud list readback only; PfxCt/NLRI/withdrawal and native authority must be independently observed'
 return result


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('prepare','add','read','reconcile','restore'));parser.add_argument('--state',type=Path,required=True);parser.add_argument('--normal-receipt',type=Path,required=True);parser.add_argument('--range-review',type=Path);parser.add_argument('--baseline-proof',type=Path);args=parser.parse_args()
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 result=run(args.phase,args.state,json.loads(helpers.private_read(args.normal_receipt)),json.loads(helpers.private_read(args.range_review)) if args.range_review else None,json.loads(helpers.private_read(args.baseline_proof)) if args.baseline_proof else None)
 print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):raise SystemExit('Owned maximum-prefix cloud operation refused; reconcile without blind mutation replay.')
