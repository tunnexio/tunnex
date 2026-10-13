"""Pure disabled QA request preparation. Never performs API or cloud I/O."""
import copy,ipaddress,uuid
SITE='01a12500-95ae-7728-b901-54f20df98cc1'
NODE='01a125fa-32f3-762b-83d4-d368447bf6ed'
NAME='GCP disabled CAS qualification 20261010'
ACTIVE={'80c20667-8d84-4dd8-8e51-ae4a10445cbb','b79d7eda-fafe-41cf-af2c-4115d4ef32c6'}
TEMPLATE={'id':None,'name':NAME,'site_id':SITE,'gateway_node_id':NODE,'tunnel_ids':[None],'configuration':{'profile_id':'gcp-classic-static-ipv4-v1','mode':'ipv4-static','customer_outside_address':'34.131.136.132','local_prefixes':['10.70.0.0/24'],'remote_prefixes':['10.82.0.0/24'],'tunnels':[{'outside_address':'34.131.121.30','inside_cidr':'','customer_inside_address':'','cloud_inside_address':''}]}}
def identifier(value):
 if not isinstance(value,str)or str(uuid.UUID(value))!=value or uuid.UUID(value).int==0 or value in ACTIVE:raise ValueError('fresh disposable UUID required')
 return value
def range_preflight(ranges,complete):
 # Read-only collection must include full normal inventory, not one page or
 # routed-ranges alone. This is advisory; CreateDisabled transaction performs
 # authoritative subnetguard.Collect/checkProviderRanges under organization lock.
 if complete is not True:raise ValueError('complete normal inventory required')
 remote=ipaddress.ip_network('10.82.0.0/24')
 for raw in ranges:
  network=ipaddress.ip_network(raw,strict=True)
  if network.version==4 and remote.overlaps(network):raise ValueError('QA remote reservation overlap')
def create_plan(connection_id,tunnel_id,existing_ids,existing_names,ranges,complete,settings,eligibility):
 cid=identifier(connection_id);tid=identifier(tunnel_id)
 if cid==tid or cid in existing_ids or tid in existing_ids or NAME in existing_names:raise ValueError('existing identity/name refused; no replay')
 if settings.get('enabled')is not True or eligibility.get('eligible')is not True:raise ValueError('normal admission unavailable')
 range_preflight(ranges,complete)
 body=copy.deepcopy(TEMPLATE);body['id']=cid;body['tunnel_ids']=[tid]
 return body
def private_create(keyfree,psk):
 if not isinstance(psk,str)or not 8<=len(psk.encode('utf-8'))<=64 or not psk.strip()or any(ord(c)<32 or ord(c)==127 for c in psk):raise ValueError('bounded fresh private PSK required')
 out=copy.deepcopy(keyfree);out['configuration']['tunnels'][0]['psk']=psk
 return out # Caller sends in memory only; never serialize/log request to receipt.
def rotation_body(tunnel_id,psk):
 # Both actual UI dialogs capture1; no refetch/retry is inserted before stale send.
 private_create(TEMPLATE,psk)
 return {'expected_desired_revision':1,'tunnels':[{'tunnel_id':identifier(tunnel_id),'psk':psk}]}
def delete_plan(connection,configuration):
 identifier(connection['id'])
 if connection.get('name')!=NAME or connection.get('site_id')!=SITE or connection.get('gateway_node_id')!=NODE or connection.get('desired_intent')!='disabled' or connection.get('cleanup_state')!='not_required' or connection.get('application_state')!='not_applied':raise ValueError('never-applied owned QA object required')
 if configuration.get('profile_id')!='gcp-classic-static-ipv4-v1' or configuration.get('configuration',{}).get('remote_prefixes')!=['10.82.0.0/24']:raise ValueError('exact QA remote/profile required')
 revision=connection.get('desired_revision')
 if type(revision)is not int or revision not in (1,2):raise ValueError('unexpected revision; no cleanup mutation')
 return {'If-Match':'"'+str(revision)+'"'}
