"""Pure current Classic FQDN plans. No API writes or synthetic DNS reports."""
import datetime,uuid
SITE='01a12500-95ae-7728-b901-54f20df98cc1';NODE='01a125fa-32f3-762b-83d4-d368447bf6ed'
CONFIG='01a126a0-2f4a-707e-9bcf-d6608754c079';PROFILE='cb7a9520-0fdc-4ddf-a4d4-1ec4b8102e80'
CONNECTION='b79d7eda-fafe-41cf-af2c-4115d4ef32c6';ZONE='classic.gcp.s2s-qa.tunnex.app'
def context(config):
 if any(config.get(k)!=v for k,v in {'id':CONFIG,'site_id':SITE,'gateway_id':NODE,'state':'active','version':1}.items()):raise ValueError('exact current context')
 profiles=config.get('profiles',[])
 if len(profiles)!=1:raise ValueError('exact single Classic profile')
 p=profiles[0]
 if p.get('id')!=PROFILE or p.get('zone_suffixes')!=[ZONE]or p.get('ipsec_path')!={'connection_id':CONNECTION,'configuration_revision':1,'source_address':'10.70.0.2'}:raise ValueError('exact saved resolver path')
 if p.get('provider_hint')!='google_cloud'or p.get('legacy_default')is not False or p.get('endpoints')!=[{'address':'10.81.0.2','port':53,'transport':'tcp'},{'address':'10.81.0.2','port':53,'transport':'udp'}]:raise ValueError('exact authority/endpoints')
def create(config,label,existing_names):
 context(config)
 if label not in ['app','alias','nx-qualification']:raise ValueError('three bounded diagnostic cases only; no large generations')
 name='GCP Classic FQDN qualification '+label+' 20261010'
 if name in existing_names:raise ValueError('existing name; no duplicate create')
 return {'name':name,'fqdn':label+'.'+ZONE,'protocol':'tcp','port_low':8080,'port_high':8080,'label':'Owned Classic selected-gateway DNS qualification; no grant implied','resolver_context':{'site_id':SITE,'gateway_id':NODE},'expected_impact_token':None}
def generation(detail,label,now):
 r=detail['resource'];selection=r.get('resolver_profile_selection',{});c=r.get('resolver_context',{})
 if r.get('fqdn')!=label+'.'+ZONE or c.get('site_id')!=SITE or c.get('gateway_id')!=NODE or c.get('resolver_config',{}).get('id')!=CONFIG:raise ValueError('actual resource/config binding')
 if selection.get('id')!=PROFILE or selection.get('config_version')!=1 or selection.get('matched_suffix')!=ZONE:raise ValueError('actual generation profile binding')
 if label=='nx-qualification':return r.get('state')=='nxdomain'and detail.get('server_reason')=='NXDOMAIN'and detail.get('active_answer_addresses')==[]
 if label not in ['app','alias']:raise ValueError('no large generation')
 fresh=datetime.datetime.fromisoformat(detail['fresh_until_at'].replace('Z','+00:00'))
 return r.get('state')=='healthy'and r.get('generation',0)>0 and detail.get('status_source')=='active_generation'and detail.get('active_answer_addresses')==['10.81.0.10']and fresh>now

def enforcement_body(impact):
 # Server-minted token is carried unchanged, never computed or substituted.
 if impact.get('enabled')is not True or impact.get('entitlement_available')is not True or not isinstance(impact.get('expected_impact_token'),str)or not impact['expected_impact_token']:raise ValueError('fresh existing opt-in/entitlement/token required; no opt-out toggle')
 return {'enabled':True,'expected_impact_token':impact['expected_impact_token']}
def app_grant(resource):
 if resource.get('name')!='GCP Classic FQDN qualification app 20261010'or resource.get('fqdn')!='app.'+ZONE:raise ValueError('only exact app grant proposed')
 rid=resource['id']
 if str(uuid.UUID(rid))!=rid or uuid.UUID(rid).int==0:raise ValueError('actual allocated resource ID')
 return {'src_kind':'site','src_site_id':SITE,'dst_kind':'fqdn_resource','dst_fqdn_resource_id':rid,'expires_at':None}
