#!/usr/bin/env python3
"""Print exact next TGW actions for review; never executes infrastructure commands."""
import json
plan={
 'execution_performed':False,'aws_cli_host':'ubuntu@16.170.207.192','ledger':'/home/ubuntu/tunnex-bgp-tgw-20261008/ledger.jsonl','canonical_ledger_order':'physical JSONL line ordinal; retain ledger-order-audit.json and original bytes',
 'instance_resume':[
 'Read exact ServiceQuota ec2/L-1216C47A current Value>=12 (request CASE_OPENED alone is insufficient), OR separately reviewed root capacity-remedy proof.',
 'Resolve original target-instance-intent.json only: exact request SHA/clienttoken+tgw ownership; describe-instances clienttoken tunnex-bgp-tgw-20261008-target must return zero instances. If nonzero require exact ownership+launch parameters and independently record result; never repeat uncertain creation.',
 'Append fsynced known-refusal resolution bound to original immutable intent and quota/current noinstance readback; original pending is retained unchanged.',
 'Launch same exact target request with original unique ClientToken; record instance/ENI/volume/public/private/tags before readiness/SSH actions. Client uses its own unique ClientToken tunnex-bgp-tgw-20261008-client and same durable intent/result rule.',
 'Use existing exact host-only SSH key /home/ubuntu/tunnex-bgp-20261007/lab-key from designatedbastion to newpublicIPs. Record pinned SSH hostkeys and actual instance IDs before connection; independent targetlocalhost8080 nonce proof with response SHA; no HTTP public8080 ingress.'
 ],
 'sg_attachment':{'eni':'eni-0fbe6981ac51bb28e','instance':'i-09d129f71f43119c7','previous_exact_groups':['sg-026e49d0f7558609a'],'add_exact_owned_group':'sg-03ca9cb5b3b36d17a','command':['aws','ec2','modify-network-interface-attribute','--network-interface-id','eni-0fbe6981ac51bb28e','--groups','sg-026e49d0f7558609a','sg-03ca9cb5b3b36d17a'],'conditions':'Root release first; re-read ENI instance identity/current singleton; verify newSG TunnexLabtunnex-bgp-tgw-20261008 + UDP500/4500 ONLY16.170.188.113/32 and16.192.130.237/32 +TCP8080 ONLY84.3/24; immutable prior and pending before call, exact2group readback before next action; preserve originalSGrules.'},
 'gateway_readonly_snapshot':{'public':'13.63.169.255','private':'10.84.1.10','host_interface':'enp39s0','host_interface_index':2,'host_interface_mac':'06:ff:c9:e7:22:9f','bridge':'tnxbgplab0','bridge_ipv4':'172.30.88.1/24','container_name':'tunnex-bgp-20261007-gateway','observed_container_short_id':'382b1763ae4b','container_eth0':'172.30.88.2/24','container_eth0_index':2,'host_ip_forward':1,'container_ip_forward':1,'host_rp_filter':2,'container_rp_filter':2,'host_main_rules':[0,32766,32767]},
 'host_namespace_routes':[
 {'scope':'host','destination':'10.86.0.0/16','gateway':'172.30.88.2','device':'tnxbgplab0','table':254,'protocol':242,'metric':51086,'add':['sudo','-n','ip','route','add','10.86.0.0/16','via','172.30.88.2','dev','tnxbgplab0','table','254','proto','242','metric','51086']},
 {'scope':'exact current gateway container','destination':'10.84.3.0/24','gateway':'172.30.88.1','device':'eth0','table':254,'protocol':'static','metric':51084,'add':['sudo','-n','docker','exec','EXACT_APPROVED_CID','ip','route','add','10.84.3.0/24','via','172.30.88.1','dev','eth0','table','254','proto','static','metric','51084']}
 ],
 'host_forward_rules':[
 ['sudo','-n','iptables','-I','DOCKER-USER','1','-s','10.84.3.10/32','-d','10.86.1.10/32','-i','enp39s0','-o','tnxbgplab0','-p','tcp','--dport','8080','-m','conntrack','--ctstate','NEW,ESTABLISHED','-m','comment','--comment','tunnex-bgp-tgw-20261008-http','-j','ACCEPT'],
 ['sudo','-n','iptables','-I','DOCKER-USER','1','-s','10.86.1.10/32','-d','10.84.3.10/32','-i','tnxbgplab0','-o','enp39s0','-p','tcp','--sport','8080','-m','conntrack','--ctstate','ESTABLISHED','-m','comment','--comment','tunnex-bgp-tgw-20261008-return','-j','ACCEPT']
 ],
 'route_forward_safety':'No execute until root review. Bind exact current fullCID/image/mountednodeSHA/netns and physical link/MAC/address readback; before additions destination routes/rules must be absent, persist full tuples/ruleargv+allforeign snapshots first; ip add only, no replace/upsert, no flush, no NAT, no sysctl changes (already1/2); exact readback and routeget source required. Existinghost85via172.30.88.2 proto242 and container84.2via172.30.88.1 plus original3DOCKERUSERrules remain byte/tuple unchanged. Cleanup deletes only exact newlyreadback-owned tuples/rules with recorded identities.',
 'product_authority':'Hostfixture routes/forwarding do not create product grant or permission. Normal newTGWprovider local84.3 remote86/16/AS65000/64512 and exact8080CPgrant separate root actions; no VGWprovider/lease rewrite.'
}
if __name__=='__main__':print(json.dumps(plan,indent=2))
