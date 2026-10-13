#!/usr/bin/env python3
"""Fresh private normal-API inputs; performs no API/Docker action."""
import argparse,json,os,pathlib,secrets,stat
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--scenario',choices=['limits','static'],required=True);p.add_argument('--base-private-config',type=pathlib.Path,required=True);p.add_argument('--directory',type=pathlib.Path,required=True);a=p.parse_args()
assert stat.S_IMODE(a.base_private_config.stat().st_mode)==0o600
assert not a.directory.exists(),'Fresh private directory required'
c=json.loads(a.base_private_config.read_text());old=pathlib.Path(c['provider_config_file']);assert stat.S_IMODE(old.stat().st_mode)==0o600
provider=json.loads(old.read_text());assert provider['mode']=='ipv4-bgp' and provider['local_prefixes']==['10.10.0.0/24'] and provider['remote_prefixes']==['10.20.0.0/24']
a.directory.mkdir(mode=0o700,parents=True)
if a.scenario=='limits':
 name='BGP limit qualification';prefixes=['10.30.0.0/24','10.31.0.0/24'];outside=['13.50.7.160','51.20.220.142'];inside=84;provider['bgp']['maximum_prefixes']=1
else:
 name='Static regression qualification';prefixes=['10.32.0.0/24'];outside=['13.50.7.161','51.20.220.143'];inside=88;provider['mode']='ipv4-static';provider.pop('bgp',None)
provider['remote_prefixes']=prefixes
for i,t in enumerate(provider['tunnels']):
 t['outside_address']=outside[i];t['inside_cidr']=f'169.254.{inside}.{i*4}/30';t['customer_inside_address']=f'169.254.{inside}.{i*4+1}';t['cloud_inside_address']=f'169.254.{inside}.{i*4+2}';t['psk']='S'+secrets.token_hex(24)
providerfile=a.directory/'provider.json';providerfile.write_text(json.dumps(provider,indent=2)+'\n');os.chmod(providerfile,0o600)
c.update(fixture_name=name,provider_connection_name=name,provider_config_file=str(providerfile.resolve()),target_prefix=prefixes[0].replace('.0/24','.2/32'))
private=a.directory/'api.json';private.write_text(json.dumps(c,indent=2)+'\n');os.chmod(private,0o600)
print('Prepared fresh private '+a.scenario+' normal API fixture; no activation or API write')
