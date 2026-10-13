"""Known2 observation-only capture settle; full verifier remains authoritative."""
import json,re,time,math
class KnownPendingCapture(Exception):
 def __init__(self,receipt):self.receipt=receipt
SOURCE='5121dc3374656449dd53dab9abd248216d5d5581';CID='5ed2a7643f2756b58c2920e7f9f74cf68078c5a794cc128e8a6a112684ce283e';IMAGE='sha256:b8f7ccba5b01cc9dd8ca0337c780c69d72e8037fcd5f16adfe98c53af4285ded'
def pending_metadata(v):
 expected={'completed','guard_publication_pending','guard_count','templates','source_commit','container_id','image_id','namespace_before','namespace_after','reader_sha256','scope'}
 if not isinstance(v,dict)or set(v)!=expected or v['completed']is not False or v['guard_publication_pending']is not True or type(v['guard_count'])is not int or v['guard_count']!=2 or v['source_commit']!=SOURCE or v['container_id']!=CID or v['image_id']!=IMAGE or v['namespace_before']!='net:[4026531840]'or v['namespace_after']!=v['namespace_before']or v['reader_sha256']!='7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f'or v['scope']!='partial metadata only; no full guard proof or packet acceptance':raise ValueError('unknown publication refusal')
 gs=v['templates']
 if not isinstance(gs,list)or len(gs)!=2:raise ValueError('pending two templates')
 for g in gs:
  if not isinstance(g,dict)or set(g)!={'Namespace','Digest','Revision'}or g['Namespace']!='net:[4026531840]'or type(g['Revision'])is not int or g['Revision']<=0 or not isinstance(g['Digest'],str)or not re.fullmatch('[0-9a-f]{64}',g['Digest']):raise ValueError('pending template grammar')
 if len({g['Digest']for g in gs})!=2 or len({g['Revision']for g in gs})!=2:raise ValueError('pending template uniqueness')
 return v
def settle_capture(capture_once,verify_all,record_partial,clock=time.monotonic,sleep=time.sleep,outer_deadline=None):
 if outer_deadline is not None and (type(outer_deadline)not in(int,float) or not math.isfinite(outer_deadline)):raise ValueError("original deadline")
 end=min(clock()+10,outer_deadline) if outer_deadline is not None else clock()+10
 while True:
  remaining=end-clock()
  if remaining<=0:raise TimeoutError('capture settle aggregate deadline')
  rc,raw=capture_once(remaining)
  if clock()>=end:raise TimeoutError('capture returned outside settle deadline')
  if rc==2:
   def unique(pairs):
    out={}
    for k,v in pairs:
     if k in out:raise ValueError('duplicate pending JSON field')
     out[k]=v
    return out
   v=pending_metadata(json.loads(raw,object_pairs_hook=unique));record_partial(v)
   remaining=end-clock()
   if remaining<=0:raise TimeoutError('pending outside settle deadline')
   sleep(min(1,remaining));continue
  if rc!=0:raise ValueError('full capture refusal')
  try:verify_all(raw,end)
  except KnownPendingCapture as pending:
   v=pending.receipt
   if v.get("known_transition_pending")is not True or v.get("packet_authority")is not False:raise ValueError("unknown transition refusal")
   record_partial(v)
   remaining=end-clock()
   if remaining<=0:raise TimeoutError("transition outside settle deadline")
   sleep(min(1,remaining));continue
  if clock()>=end:raise TimeoutError('full verification outside settle deadline')
  return raw

