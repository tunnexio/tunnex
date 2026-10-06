#!/usr/bin/env python3
"""Owned real enrollment + baseline mTLS tenancy/purpose proof; no secret output."""
import datetime,http.client,json,os,runpy,socket,ssl,subprocess,tempfile,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parent
PRIMARY='01a109d9-382b-7bc1-82c9-2b0bf036139c'
ADMIN='11111111-1111-4111-8111-111111111181'
HELPER=runpy.run_path('/private/tmp/sa-http-fixture.py')
USER_FILE=Path('/private/tmp/tunnex-sa0-spike/terminal-users.json')
class Control(http.client.HTTPSConnection):
 def connect(self):
  raw=socket.create_connection(('127.0.0.1',18546),timeout=self.timeout)
  self.sock=self._context.wrap_socket(raw,server_hostname='tunnex-control')
def sql(text):
 result=subprocess.run([str(ROOT/'run.sh'),'exec','-T','postgres','psql','-X','-U','aa0','-d','aa0','-v','ON_ERROR_STOP=1','-At'],input=text,text=True,capture_output=True)
 if result.returncode:raise RuntimeError('Owned identity SQL operation failed')
 return result.stdout.strip()
def mtls(context,method,path,body=None,purpose=None):
 c=Control('tunnex-control',18546,context=context,timeout=4)
 headers={'Content-Type':'application/json'}
 if purpose:headers['X-Tunnex-Purpose']=purpose
 try:
  c.request(method,path,None if body is None else json.dumps(body),headers);r=c.getresponse();data=r.read(65536)
  try:parsed=json.loads(data) if data else {}
  except ValueError:parsed={}
  return r.status,parsed
 finally:c.close()
def main():
 users=json.loads(USER_FILE.read_text());admin=HELPER['restored'](users[0]);member=HELPER['restored'](users[1])
 assert sql("SELECT count(*) FROM organizations WHERE id='"+PRIMARY+"' AND name='SA-0 local qualification';")=='1'
 foreign=str(uuid.uuid4());name='SA9 owned identity '+foreign;slug='sa9-identity-'+foreign
 nodes=[];contexts={};foreign_created=False
 private=Path(tempfile.mkdtemp(prefix='tunnex-sa9-enrolled-',dir='/private/tmp'));os.chmod(private,0o700)
 proof=[]
 old_url=HELPER['Client'].rpc.__globals__['URL']
 try:
  sql("BEGIN; INSERT INTO organizations(id,name,slug) VALUES('"+foreign+"','"+name+"','"+slug+"'); INSERT INTO memberships(org_id,user_id,role,roles) VALUES('"+foreign+"','"+ADMIN+"','owner',ARRAY['owner']); COMMIT;");foreign_created=True
  workspace=admin.rpc('GET','/api/v1/organizations/'+PRIMARY+'/server-access');session=next(s for s in workspace['sessions'] if s['kind']=='terminal')['id']
  for kind,org in [('same_org_other_gateway',PRIMARY),('foreign_org_gateway',foreign)]:
   folder=private/kind;folder.mkdir(mode=0o700)
   subprocess.run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(folder/'key.pem'),'-out',str(folder/'csr.pem'),'-subj','/CN=sa9-identity'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   HELPER['Client'].rpc.__globals__['URL']='http://127.0.0.1:15189'
   token=admin.rpc('POST','/api/v1/organizations/'+org+'/nodes/join-token',{'node_name':'sa9-identity-'+kind+'-'+foreign[:8],'enrols_kind':'gateway'},want=201)
   enrolled=admin.rpc('POST','/api/v1/agent/enroll',{'join_token':token['join_token'],'csr':(folder/'csr.pem').read_text(),'node_name':'sa9-identity-'+kind+'-'+foreign[:8],'agent_version':'sa9-owned-proof','protocol_version':1})
   HELPER['Client'].rpc.__globals__['URL']=old_url
   nodes.append((org,enrolled['node_id']))
   for filename,field in [('cert.pem','certificate'),('ca.pem','ca_certificate')]:
    (folder/filename).write_text(enrolled[field]);os.chmod(folder/filename,0o600)
   os.chmod(folder/'key.pem',0o600)
   context=ssl.create_default_context(cafile=str(folder/'ca.pem'));context.load_cert_chain(str(folder/'cert.pem'),str(folder/'key.pem'))
   contexts[enrolled['node_id']]=context
   status,desired=mtls(context,'GET','/agent/server-access/desired-state');assert status==200 and desired==[],'Enrolled gateway was not authenticated/scoped'
   for operation in ['material','lease','status']:
    body={'public_key':'ssh-ed25519 AAAA intended-binding-denial'} if operation=='material' else {'result':'failed'} if operation=='status' else None
    status,error=mtls(context,'POST','/agent/server-access/sessions/'+session+'/'+operation,body)
    assert status==(403 if org==PRIMARY else 404),'Gateway credential crossed session authority boundary'
    assert error['error']['code']==('gateway_binding_mismatch' if org==PRIMARY else 'server_access_not_found')
   status,error=mtls(context,'CONNECT','/agent/server-access/sessions/'+session+'/channel',purpose='app_access_http_v1')
   assert status==403 and error['error']['code']=='invalid_channel_purpose','Wrong credential purpose accepted'
   status,error=mtls(context,'CONNECT','/agent/server-access/sessions/'+session+'/channel',purpose='server_access_terminal_v1')
   assert status==(403 if org==PRIMARY else 404),'Cross-bound channel attached'
   proof.append({'identity':kind,'actual_enrollment_and_baseline_mtls':True,'desired_state_empty':True,'material_lease_status_channel_denied':True,'wrong_purpose_denied':True})
  status,error=member.rpc('GET','/api/v1/organizations/'+foreign+'/server-access',want=404),None
  proof.append({'foreign_human_workspace_denied':True,'retained_inert_org_id':foreign,'retained_inert_org_name':name})
 finally:
  HELPER['Client'].rpc.__globals__['URL']=old_url
  for org,node in reversed(nodes):
   admin.rpc('POST','/api/v1/organizations/'+org+'/nodes/'+node+'/revoke',{},want=204)
   if node in contexts:
    revoked_status,_=mtls(contexts[node],'GET','/agent/server-access/desired-state')
    assert revoked_status==401,'Revoked enrolled credential still authenticated'
    proof.append({'revoked_enrolled_certificate_denied':True})
  if foreign_created:
   sql("DELETE FROM memberships WHERE org_id='"+foreign+"' AND user_id='"+ADMIN+"'; UPDATE node_join_tokens SET consumed_at=COALESCE(consumed_at,now()) WHERE org_id='"+foreign+"';")
  # Remove only credential files generated under this private fixture directory.
  for child in private.iterdir():
   for file in child.iterdir():file.unlink()
   child.rmdir()
  private.rmdir()
 assert sql("SELECT count(*) FROM memberships WHERE org_id='"+foreign+"';")=='0','Fixture membership cleanup failed'
 assert sql("SELECT count(*) FROM nodes WHERE name LIKE 'sa9-identity-%' AND status='active';")=='0','Temporary gateway credentials remain active'
 (ROOT/'.runtime'/'enrolled-identity-results.json').write_text(json.dumps(proof,indent=2))
 print('Real enrollment/mTLS foreign-org, cross-gateway and wrong-purpose boundaries PASS; fixture org retained inert for append-only audit evidence and generated credentials revoked/deleted')
if __name__=='__main__':main()
