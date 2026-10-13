#!/usr/bin/env python3
"""Pure key-free FQDN payload preparation; no API/network/write operations."""
SITE='01a12500-95ae-7728-b901-54f20df98cc1';NODE='01a125fa-32f3-762b-83d4-d368447bf6ed'
def prepare(profile,context):
 if profile not in ('ha','classic'):raise ValueError('exact QA profile required')
 zone=profile+'.gcp.s2s-qa.tunnex.app';endpoint='10.80.0.2' if profile=='ha' else '10.81.0.2'
 if context.get('site_id')!=SITE or context.get('gateway_id')!=NODE or context.get('state')!='active':raise ValueError('actual active context required')
 matches=[p for p in context['profiles'] if p.get('zone_suffixes')==[zone] and p.get('provider_hint')=='google_cloud']
 if len(matches)!=1:raise ValueError('exact actual saved profile required')
 p=matches[0];path=p.get('ipsec_path',{})
 if path.get('source_address')!='10.70.0.2' or type(path.get('configuration_revision')) is not int or path['configuration_revision']<1 or not path.get('connection_id'):raise ValueError('actual bound configuration required')
 if {(e['address'],e['port'],e['transport']) for e in p['endpoints']}!={(endpoint,53,'udp'),(endpoint,53,'tcp')}:raise ValueError('exact DNS endpoints required')
 # No application grants for alias/NXDOMAIN/large diagnostics. A 404/NXDOMAIN report is evidence, not success.
 return [{'name':'GCP cloud QA '+profile+' '+name,'fqdn':name+'.'+zone,'protocol':'tcp','port_low':8080,'port_high':8080,'label':'Owned QA DNS diagnostic; no policy grant implied','resolver_context':{'site_id':SITE,'gateway_id':NODE},'expected_impact_token':None} for name in ('app','alias','missing-owned-1010','large')]
