#!/usr/bin/env python3
"""Disabled-only Azure configuration qualification through actual local role APIs."""
import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import sys
from datetime import datetime, timezone
import uuid
spec = importlib.util.spec_from_file_location("azure_enrollment", Path(__file__).with_name("enroll-local.py"))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

def expect_error(client,method,path,status,body=None,headers=None):
    try:
        client.call(method,path,body,headers)
    except lab.LabError as error:
        if error.status == status:
            return
        raise
    raise lab.LabError("Expected role/validation/CAS refusal was accepted")

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root",type=Path,required=True)
    parser.add_argument("--api-source",required=True,help="Exact reviewed source of running CP; never inferred from script branch")
    args=parser.parse_args();private=args.private_root.resolve()
    account_path=private/"ui-accounts.json"
    if account_path.stat().st_mode&0o077:raise lab.LabError("Role credentials must be private")
    accounts=json.loads(account_path.read_text());state=json.loads((private/"api-setup.json").read_text())
    if "gateway_id" not in state:raise lab.LabError("Bind a real enrolled gateway first")
    clients={role:lab.Client(accounts[role]) for role in ("owner","admin","member")}
    prefix=f"/api/v1/organizations/{state['org_id']}/ipsec"
    results=[]
    for topology in ("active-active","active-standby"):
        for routing in ("bgp","static"):
            profile=f"azure-{topology}-{routing}-ipv4-v1";count=2 if topology=="active-active" else 1
            psk="syntheticAzure"+secrets.token_hex(12)
            config={"profile_id":profile,"azure":{"gateway_sku":"VpnGw1AZ","vpn_type":"RouteBased","ike_version":2,"custom_policy":"aes256-sha256-dh14-pfs2048","use_policy_based_traffic_selectors":False,"nat_enabled":False},"mode":"ipv4-"+routing,"customer_outside_address":"9.9.9.9","local_prefixes":[state['local_prefix']],"remote_prefixes":["10.242.10.0/24"],"tunnels":[]}
            for i in range(count):
                config["tunnels"].append({"outside_address":("8.8.8.8","8.8.4.4")[i],"inside_cidr":"169.254.20.1/32" if routing=="bgp" else f"169.254.{30+i}.0/30","customer_inside_address":"169.254.20.1" if routing=="bgp" else f"169.254.{30+i}.1","cloud_inside_address":f"169.254.{21+i}.2" if routing=="bgp" else f"169.254.{30+i}.2","psk":psk})
            if routing=="bgp":config["bgp"]={"local_asn":13335,"remote_asn":65515,"router_id":"10.241.10.1","maximum_prefixes":8}
            for role in ("owner","admin"):clients[role].call("POST",prefix+"/configuration-check",config)
            expect_error(clients["member"],"POST",prefix+"/configuration-check",403,config)
            invalid=json.loads(json.dumps(config));invalid['azure']['gateway_sku']='Basic'
            expect_error(clients["owner"],"POST",prefix+"/configuration-check",400,invalid)
            identifiers=[str(uuid.uuid4()) for _ in range(count)]
            body={"id":str(uuid.uuid4()),"name":"Azure owned disabled HTTP qualification "+profile,"site_id":state['site_id'],"gateway_node_id":state['gateway_id'],"tunnel_ids":identifiers,"configuration":config}
            expect_error(clients["member"],"POST",prefix+"/connections",403,body)
            # These public endpoint fixtures never receive traffic: intent remains disabled.
            connection=clients["owner"].call("POST",prefix+"/connections",body)
            path=prefix+"/connections/"+connection['id'];revision=connection['desired_revision']
            try:
                for role in ("owner","admin","member"):
                    stored=clients[role].call("GET",path+"/configuration")
                    rendered=json.dumps(stored)
                    if psk in rendered or 'psk' in rendered.lower() or stored['configuration']['azure']!=config['azure'] or len(stored['configuration']['tunnels'])!=count:raise lab.LabError("Nonsecret provider readback contract failed")
                    status=clients[role].call("GET",path+"/status")
                    if len(status['tunnels'])!=count or any(tunnel['status']!='unknown' for tunnel in status['tunnels']):raise lab.LabError("Disabled synthetic fixture claimed observed health")
                replacement="replacementAzure"+secrets.token_hex(12)
                rotation={"expected_desired_revision":revision,"tunnels":[{"tunnel_id":tid,"psk":replacement} for tid in identifiers]}
                expect_error(clients["member"],"POST",path+"/rotate-psks",403,rotation)
                if count==2:
                    partial={**rotation,"tunnels":rotation['tunnels'][:1]}
                    expect_error(clients["admin"],"POST",path+"/rotate-psks",400,partial)
                rotated=clients['admin'].call('POST',path+'/rotate-psks',rotation);revision=rotated['desired_revision']
                expect_error(clients['owner'],'POST',path+'/rotate-psks',409,rotation)
                expect_error(clients['member'],'DELETE',path,403,headers={'If-Match':f'"{revision}"'})
                expect_error(clients['owner'],'DELETE',path,409,headers={'If-Match':f'"{revision-1}"'})
                results.append({'profile':profile,'role_readback':'owner/admin/member passed','write_roles':'owner/admin passed; member refused','cas':'stale rotation/delete refused','keys':'shared atomic rotation; no public secret fields','health':'unknown with disabled synthetic endpoints'})
            finally:
                deleted=clients['owner'].call('DELETE',path,headers={'If-Match':f'"{revision}"'})
                if deleted.get('finalized_at') is None:raise lab.LabError('Never-delivered fixture deletion did not finalize')
    evidence={'observed_at':datetime.now(timezone.utc).isoformat(),'api_source':args.api_source,'api_origin':lab.API,'scope':'actual local HTTP role/configuration qualification only; disabled synthetic endpoints; no Azure tunnel traffic or live cloud claims','gateway_identity':state['gateway_id'],'results':results}
    lab.private_write(private/'http-qualification.json',json.dumps(evidence,indent=2))
    print('PASS: four Azure profiles through actual owner/admin/member HTTP paths, readback/unknown health, shared-key rotation, CAS and finalized cleanup; no tunnel activation.')

if __name__=='__main__':
    try:main()
    except (lab.LabError,KeyError,OSError,ValueError):
        error=sys.exc_info()[1]
        print(str(error) if isinstance(error,lab.LabError) else 'Owned private input or API shape invalid',file=sys.stderr)
        raise SystemExit(1)
