#!/usr/bin/env python3
"""Generate ONLY a private synthetic disabled API fixture from exact owned public config.
No network/API calls; no AWS PSKs, no activation; parent captures seed through normal GET.
VGW/TGW label is test provenance, not a distinct public profile field.
"""
import argparse,copy,hashlib,ipaddress,json,os,pathlib,secrets,stat,uuid
ORG='01a1161a-906c-7074-9e80-dd318fc2c1eb';SITE='01a119e8-fb58-72d9-bbd2-8de0fe7bfd1e';GW='01a1161a-9529-7478-b62f-a27f25222aa0'
SOURCE_PROVIDER='9d9f98e2-cd96-456d-b020-a5a79f688040'
EXPECTED={'configuration':{'bgp':{'local_asn':65000,'maximum_prefixes':1,'remote_asn':64512,'router_id':'10.84.2.1'},'customer_outside_address':'13.63.169.255','local_prefixes':['10.84.2.0/24'],'mode':'ipv4-bgp','remote_prefixes':['10.85.0.0/16'],'tunnels':[{'cloud_inside_address':'169.254.16.81','customer_inside_address':'169.254.16.82','inside_cidr':'169.254.16.80/30','outside_address':'13.50.7.159'},{'cloud_inside_address':'169.254.98.189','customer_inside_address':'169.254.98.190','inside_cidr':'169.254.98.188/30','outside_address':'51.20.220.141'}]},'configuration_revision':1,'profile_id':'aws-bgp-ipv4-v1'}
PROFILES=['vgw-bgp','tgw-bgp','vgw-static','tgw-static']
def generate(seed,profile,digest):
 assert seed=={'provider_id':SOURCE_PROVIDER,'org_id':ORG,'site_id':SITE,'gateway_node_id':GW,'public_configuration':EXPECTED},'Seed must be exact normally-read owned VGW public configuration; no foreign configuration accepted'
 assert profile in PROFILES;index=PROFILES.index(profile);c=copy.deepcopy(EXPECTED['configuration']);c['remote_prefixes']=['10.88.'+str(index+1)+'.0/24'];c['mode']='ipv4-bgp'if profile.endswith('-bgp')else'ipv4-static'
 if c['mode']=='ipv4-static':c.pop('bgp')
 endpoints={'vgw':['3.67.173.125','52.58.98.231'],'tgw':['3.65.241.160','63.189.108.24']}[profile.split('-')[0]]
 for slot,t in enumerate(c['tunnels']):
  t['outside_address']=endpoints[slot]
  prefix=ipaddress.ip_network('169.254.125.'+str(index*8+slot*4)+'/30');t.update(inside_cidr=str(prefix),cloud_inside_address=str(prefix.network_address+1),customer_inside_address=str(prefix.network_address+2),psk='S'+secrets.token_hex(24))
 return {'body':{'id':str(uuid.uuid4()),'name':'Customer API disabled fixture '+profile+' '+secrets.token_hex(4),'site_id':SITE,'gateway_node_id':GW,'tunnel_ids':[str(uuid.uuid4()),str(uuid.uuid4())],'configuration':c},'owned_config_source_sha256':digest,'expected_org':ORG,'expected_site':SITE,'expected_gateway':GW}
def main():
 p=argparse.ArgumentParser();p.add_argument('--seed',type=pathlib.Path,required=True);p.add_argument('--profile',choices=PROFILES,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();assert os.getuid()==0;os.umask(0o077)
 fd=os.open(a.seed,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 with os.fdopen(fd,'rb')as f:raw=f.read(65537)
 assert len(raw)<=65536;fixture=generate(json.loads(raw),a.profile,hashlib.sha256(raw).hexdigest());parent=a.out.parent;assert parent.is_dir()and not parent.is_symlink()and parent.stat().st_uid==0 and stat.S_IMODE(parent.stat().st_mode)==0o700
 fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w')as f:json.dump(fixture,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);print(json.dumps({'fixture_id':fixture['body']['id'],'profile_label':a.profile,'synthetic_disabled_only':True,'output':str(a.out),'fixture_sha256':hashlib.sha256(a.out.read_bytes()).hexdigest()}))
if __name__=='__main__':main()
