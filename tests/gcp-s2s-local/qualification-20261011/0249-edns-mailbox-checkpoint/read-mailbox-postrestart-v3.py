import os,pathlib,subprocess,json,hashlib,stat
P=pathlib.Path('/Users/pawangupta/.codex/worktrees/gcp-s2s/tunnex/tests/gcp-s2s-local/.runtime/compose.env')
st=P.lstat()
if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o600:raise ValueError('private input')
raw=P.read_text();lines=[l for l in raw.splitlines() if l and not l.startswith('#')]
if len(lines)!=1 or not lines[0].startswith('GCP_DB_PASSWORD='):raise ValueError('input schema')
env=os.environ.copy();env['PGPASSWORD']=lines[0].split('=',1)[1];env['PGCONNECT_TIMEOUT']='3'
q="""BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms'; SELECT coalesce(json_agg(t),'[]'::json) FROM (SELECT request_id,resource_id,created_at,deadline,state,completed_at,expired_at,resolver_config_id,resolver_config_version,resolver_profile_id,resolver_match_suffix,hostname,protocol_version,response->>'resolver_config_id' AS response_config_id,response->>'resolver_config_version' AS response_config_version,response->>'resolver_profile_id' AS response_profile_id,response->>'status' AS response_status,response->>'error_code' AS response_error_code,response->>'observed_at' AS response_observed_at FROM fqdn_gateway_dns_requests WHERE org_id='01a124e7-60c7-78ca-aa85-d3a5025d9764' AND gateway_id='01a125fa-32f3-762b-83d4-d368447bf6ed' AND resource_id IN ('01a127b1-ba33-7941-9bdf-58dbaca5ab12','01a127b1-ba4c-74bf-bbb5-38339ea6c516','01a127b1-ba5d-7b7d-a885-4230f29ee67b') AND created_at >= now()-interval '30 minutes' ORDER BY created_at DESC LIMIT 100) t; COMMIT;"""
root=pathlib.Path('/private/tmp/gcp-fqdn-mailbox-diagnostic-20261011');fd=os.open(root/'mailbox-postrestart-v3.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
out={'started':True,'scope':'fixed owned metadata readonly'}
try:
 r=subprocess.run(['/opt/homebrew/bin/psql','-X','-q','-t','-A','-h','127.0.0.1','-p','35440','-U','gcps2s','-d','gcps2s','-v','ON_ERROR_STOP=1'],input=q.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=10)
 out.update(completed=r.returncode==0,returncode=r.returncode,stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest())
 if r.returncode==0:out['rows']=json.loads(r.stdout)
except Exception as e:out.update(completed=False,error_type=type(e).__name__)
finally:
 with os.fdopen(fd,'w') as f:json.dump(out,f,indent=2);f.flush();os.fsync(f.fileno())
print(json.dumps({'completed':out.get('completed'),'rows':len(out.get('rows',[])),'receipt':str(root/'mailbox-postrestart-v3.json')}))
