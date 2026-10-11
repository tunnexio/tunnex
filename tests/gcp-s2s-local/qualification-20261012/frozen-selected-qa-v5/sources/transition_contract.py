"""Observation-only zero-authority readiness contract. No I/O or packet admission."""
import datetime,re,hashlib,json,math
IDENTITY={'boot_id':'9617762e-19db-4a21-bdee-909dfb31e501','container_id':'5ed2a7643f2756b58c2920e7f9f74cf68078c5a794cc128e8a6a112684ce283e','image_id':'sha256:b8f7ccba5b01cc9dd8ca0337c780c69d72e8037fcd5f16adfe98c53af4285ded','namespace':'net:[4026531840]','node_sha256':'cbfabf16f1561f8dfb9d01cc49fad92a8ef2a8fed98dcd96b3e48a5533370bde','pid':3703875,'pid_start_ticks':10383458,'source_commit':'5121dc3374656449dd53dab9abd248216d5d5581','started_at':'2026-10-11T19:00:23.223646733Z'}
def unique(pairs):
 out={}
 for k,v in pairs:
  if k in out:raise ValueError('duplicate JSON field')
  out[k]=v
 return out
def decode(raw):return json.loads(raw,object_pairs_hook=unique)
def utc(value):
 if not isinstance(value,str)or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z',value):raise ValueError('strict UTC')
 normalized=re.sub(r'\.(\d{1,9})Z$',lambda m:'.'+m[1].ljust(6,'0')[:6]+'Z',value)
 return datetime.datetime.fromisoformat(normalized[:-1]+'+00:00').timestamp()
def identity(v):
 if not isinstance(v,dict)or set(v)!=set(IDENTITY)or type(v.get('pid'))is not int or type(v.get('pid_start_ticks'))is not int or v!=IDENTITY:raise ValueError('exact typed nine-field identity')
 return v
def mutation_context(context,state,state_sha,phase,protocol,read_checked):
 # Context is emitted only after the existing whole normal API mutation validator succeeds.
 if not isinstance(context,dict)or set(context)!={'phase','protocol','grant_id','state_sha256','result_path','result_sha256','attempt_path','attempt_sha256','response_path','response_sha256','confirmed_monotonic','fixture_end_monotonic'}:raise ValueError('confirmed mutation context')
 expected='create-grant'if phase=='allow'else'delete-grant'
 if context['phase']!=expected or context['protocol']!=protocol or context['state_sha256']!=state_sha:raise ValueError('phase/state mutation mismatch')
 gid=context['grant_id']
 if not isinstance(gid,str)or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',gid):raise ValueError('canonical grant ID')
 result=decode(read_checked(context['result_path'],context['result_sha256']));attempt=decode(read_checked(context['attempt_path'],context['attempt_sha256']));response=decode(read_checked(context['response_path'],context['response_sha256']))
 if result.get('completed')is not True or result.get('baseline_preserved')is not True or result.get('mutation_attempted')is not True or type(result.get('mutations'))is not int or result['mutations']!=1:raise ValueError('mutation not confirmed')
 if attempt.get('replay_forbidden')is not True or set(attempt)!={'method','path','replay_forbidden'}:raise ValueError('exact original mutation intent')
 if set(state.get('resources',{}))!={'tcp','udp'}or set(state.get('grants',{}))!=({protocol}if phase=='allow'else set()):raise ValueError('selected current graph')
 if phase=='allow':
  grant=state['grants'][protocol]
  if attempt['method']!='POST'or attempt['path']!='/policies'or type(response.get('status'))is not int or response['status']!=201 or response.get('body')!=grant or grant.get('id')!=gid or grant.get('dst_fqdn_resource_id')!=state['resources'][protocol]['id'] or grant.get('enabled')is not True:raise ValueError('exact returned selected grant')
 else:
  if attempt['method']!='DELETE'or attempt['path']!='/policies/'+gid or type(response.get('status'))is not int or response['status']!=204 or response.get('body')is not None:raise ValueError('exact confirmed delete')
 return context

def pending(raw,native,empty,ha,phase,protocol):
 c=decode(raw);n=identity(native['identity'])
 if native.get('completed')is not True or not isinstance(native.get('journal_projection'),dict)or not native['journal_projection']:raise ValueError('full native ownership')
 expected={'source_commit':n['source_commit'],'container_id':n['container_id'],'image_id':n['image_id'],'boot_id':n['boot_id'],'namespace_before':n['namespace'],'namespace_after':n['namespace'],'host_namespace_before':n['namespace'],'host_namespace_after':n['namespace']}
 if any(c.get(k)!=v for k,v in expected.items())or c.get('guard_identity_stable')is not True or c.get('reader_sha256')!='7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f':raise ValueError('same complete guard capture')
 sha=hashlib.sha256(raw).hexdigest()
 if empty.get('completed')is not True or empty.get('guard_transition_qualified')is not True or empty.get('packet_authority')is not False or empty.get('capture_sha256')!=sha or empty.get('source')!=n['source_commit']:raise ValueError('full canonical zero-authority proof')
 if set(ha)!={'ha_tcp','ha_udp','ha_dns_tcp','ha_dns_udp'}:raise ValueError('full four unrelated positives')
 for key,v in ha.items():
  o=v.get('observation',{})
  if v.get('completed')is not True or v.get('capture_sha256')!=sha or o.get('expect')!='allow'or o.get('protocol')!=key.rsplit('_',1)[1]or o.get('source')!=n['source_commit']or o.get('readback')!='positive'or o.get('guard_revision')!=c['expected_guard']['Revision']or o.get('guard_digest')!=c['expected_guard']['Digest']:raise ValueError('same-capture HA positive')
 # Positive executables are invoked with -expect allow and their exact pinned source/artifacts.
 if phase not in ('allow','deny')or protocol not in ('tcp','udp'):raise ValueError('typed phase')
 return {'completed':False,'known_transition_pending':True,'packet_authority':False,'capture_sha256':sha,'phase':phase,'selected_protocol':protocol,'native_before_identity':n,'identity_scope':'original nine-field native before/after brackets; capture fields SOURCE/CID/IMAGE/BOOT/namespaces bound to native before','guard_revision':c['expected_guard']['Revision'],'scope':'full canonical Classic three-empty denial; HA positive and native ownership; final full eight/selected/provenance proof still required'}
