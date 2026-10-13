"""QA-only ACK budget clipped by unchanged shared20/outer80 and samegeneration reserve."""
import datetime,math,re

def strict_utc(value):
 if not isinstance(value,str)or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z',value):raise ValueError('typed generation expiry')
 normalized=re.sub(r'\.(\d{1,9})Z$',lambda m:'.'+m[1].ljust(6,'0')[:6]+'Z',value)
 return datetime.datetime.fromisoformat(normalized[:-1]+'+00:00').timestamp()

def wait_ack_same_generation(wait_read,ack_once,identity,shared_until,outer_until,clock,utc_now,record):
 expiry=strict_utc(identity['fresh_until_at']);start=clock();wall=utc_now()
 if any(type(v)not in(int,float)or not math.isfinite(v)for v in (start,wall,shared_until,outer_until,expiry)):raise ValueError('finite original ACK clocks')
 before=expiry-wall;until=min(shared_until,outer_until,start+before-19)
 pending=0;accepted=False
 def read_once():
  nonlocal pending
  status=ack_once()
  if status=='pending':pending+=1
  return status
 try:
  if until<=start:raise TimeoutError('same generation ACK reserve exhausted')
  wait_read(read_once,until-start,until)
  accepted=True
 finally:
  record({'completed':accepted,'scope':'QA read-only ACK observation; no five-second convergence guarantee','ack_elapsed_seconds':clock()-start,'pending_samples':pending,'before_generation_remaining_seconds':before,'after_generation_remaining_seconds':expiry-utc_now(),'post_generation_reserve_seconds':19,'same_generation_fresh_until_at':identity['fresh_until_at'],'shared_window_extended':False,'outer_window_extended':False})
