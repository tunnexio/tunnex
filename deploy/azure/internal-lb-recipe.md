Source-only recipe, verified against official Azure CLI references on2026-10-10. Root reviews and runs these commands ONLY through the authorized bastion in the owned subscription. No Azure CLI/cloud commands were executed by the provider agent. This adds one internal Standard Load Balancer using the existing target VM; one backend qualifies a managed frontend path, not backend HA or multi-instance balancing.

Microsoft documents the [internal Standard LB workflow](https://learn.microsoft.com/en-us/azure/load-balancer/quickstart-load-balancer-standard-internal-cli), [explicit private IP/no-public-IP options](https://learn.microsoft.com/en-us/cli/azure/network/lb?view=azure-cli-latest), [NIC pool attachment](https://learn.microsoft.com/en-us/cli/azure/network/nic/ip-config/address-pool?view=azure-cli-latest), [TCP probes](https://learn.microsoft.com/en-us/cli/azure/network/lb/probe?view=azure-cli-latest), [rule/SNAT options](https://learn.microsoft.com/en-us/cli/azure/network/lb/rule?view=azure-cli-latest), and [private A records](https://learn.microsoft.com/en-us/cli/azure/network/private-dns/record-set/a?view=azure-cli-latest). On the bastion, confirm installed syntax using each corresponding `az ... create --help`, `az network nic ip-config address-pool add --help`, and `az network private-dns record-set a add-record --help` before mutation.

Discovery/guards first; stop on any unexpected ownership, NIC count, subnet, existing LB/DNS record or occupied frontend. The NIC/ip-config name is discovered from the ACTUAL existing VM, never assumed from provisioning scripts. Retain the discovered IDs and readback as reviewed receipts.

```bash
set -euo pipefail
rg=tunnex-azure-s2s-20261010
owner=azure-s2s-01a12505
vnet=azure-vnet
vm=azure-target
lb=azure-private-app-lb
frontend=private-app-frontend
pool=existing-target-backend
probe=target-tcp8080-probe
rule=private-tcp8080
zone=azure-s2s.test
az account show --query '{subscription:id,name:name}' -o json
[[ $(az group show -n "$rg" --query tags.owner -o tsv) == "$owner" ]]
[[ $(az network vnet show -g "$rg" -n "$vnet" --query tags.owner -o tsv) == "$owner" ]]
[[ $(az vm show -g "$rg" -n "$vm" --query tags.owner -o tsv) == "$owner" ]]
[[ $(az vm show -g "$rg" -n "$vm" --query 'length(networkProfile.networkInterfaces)' -o tsv) == 1 ]]
nic_id=$(az vm show -g "$rg" -n "$vm" --query 'networkProfile.networkInterfaces[0].id' -o tsv)
[[ "$nic_id" == */resourceGroups/"$rg"/providers/Microsoft.Network/networkInterfaces/* ]]
[[ $(az network nic show --ids "$nic_id" --query tags.owner -o tsv) == "$owner" ]]
nic_name=$(az network nic show --ids "$nic_id" --query name -o tsv)
[[ $(az network nic show --ids "$nic_id" --query "length(ipConfigurations[?privateIPAddress=='10.231.1.4'])" -o tsv) == 1 ]]
ip_config=$(az network nic show --ids "$nic_id" --query "ipConfigurations[?privateIPAddress=='10.231.1.4'] | [0].name" -o tsv)
subnet_id=$(az network vnet subnet show -g "$rg" --vnet-name "$vnet" -n workload --query id -o tsv)
[[ $(az network vnet subnet show -g "$rg" --vnet-name "$vnet" -n workload --query addressPrefix -o tsv) == 10.231.1.0/24 ]]
[[ $(az network nic show --ids "$nic_id" --query "ipConfigurations[?name=='$ip_config'] | [0].subnet.id" -o tsv) == "$subnet_id" ]]
[[ $(az network vnet check-ip-address -g "$rg" -n "$vnet" --ip-address 10.231.1.10 --query available -o tsv) == true ]]
[[ $(az network lb list -g "$rg" --query "[?name=='$lb'] | length(@)" -o tsv) == 0 ]]
[[ $(az network private-dns zone show -g "$rg" -n "$zone" --query tags.owner -o tsv) == "$owner" ]]
[[ $(az network private-dns record-set list -g "$rg" -z "$zone" --query "[?name=='lbapp'] | length(@)" -o tsv) == 0 ]]
location=$(az network vnet show -g "$rg" -n "$vnet" --query location -o tsv)
az network nic show --ids "$nic_id" --query '{name:name,nsg:networkSecurityGroup.id,ipConfigurations:ipConfigurations[].{name:name,address:privateIPAddress,subnet:subnet.id,pools:loadBalancerBackendAddressPools[].id}}' -o json
az network vnet subnet show -g "$rg" --vnet-name "$vnet" -n workload --query '{id:id,nsg:networkSecurityGroup.id,routeTable:routeTable.id}' -o json
```

Preserve the existing NIC/subnet NSG and its default `AzureLoadBalancer` probe allowance. Root reviews any higher-priority denies and target firewall before proceeding: [Azure probes originate at168.63.129.16](https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-custom-probe-overview) and need TCP8080. Existing narrowly authorized LAN10.233.10.2 application traffic must still reach the backend. This recipe creates no NSG, VM, outbound rule, public IP, NAT gateway or broad allow; it does not replace existing NIC pools.

```bash
az network lb create -g "$rg" -n "$lb" -l "$location" --sku Standard \
  --subnet "$subnet_id" --private-ip-address 10.231.1.10 \
  --public-ip-address '' --frontend-ip-name "$frontend" --backend-pool-name "$pool" \
  --tags owner="$owner" purpose=owned-s2s-test -o none
az network lb probe create -g "$rg" --lb-name "$lb" -n "$probe" \
  --protocol Tcp --port 8080 --interval 5 --threshold 2 -o none
az network lb rule create -g "$rg" --lb-name "$lb" -n "$rule" \
  --protocol Tcp --frontend-port 8080 --backend-port 8080 \
  --frontend-ip-name "$frontend" --backend-pool-name "$pool" --probe-name "$probe" \
  --disable-outbound-snat true --floating-ip false --enable-tcp-reset true --idle-timeout 4 -o none
az network nic ip-config address-pool add -g "$rg" --nic-name "$nic_name" \
  --ip-config-name "$ip_config" --lb-name "$lb" --address-pool "$pool" -o none
az network private-dns record-set a create -g "$rg" -z "$zone" -n lbapp \
  --ttl 30 --metadata owner="$owner" purpose=owned-s2s-test -o none
az network private-dns record-set a add-record -g "$rg" -z "$zone" -n lbapp -a 10.231.1.10 -o none
az network lb show -g "$rg" -n "$lb" \
  --query '{id:id,sku:sku.name,state:provisioningState,frontends:frontendIPConfigurations[].{address:privateIPAddress,allocation:privateIPAllocationMethod,subnet:subnet.id,publicIP:publicIPAddress.id},pools:backendAddressPools[].{name:name,interfaces:backendIPConfigurations[].id},probes:probes[].{protocol:protocol,port:port},rules:loadBalancingRules[].{protocol:protocol,frontendPort:frontendPort,backendPort:backendPort,disableOutboundSnat:disableOutboundSnat,floatingIP:enableFloatingIP},outboundRules:outboundRules}' -o json
az network private-dns record-set a show -g "$rg" -z "$zone" -n lbapp \
  --query '{name:name,ttl:ttl,addresses:aRecords[].ipv4Address,metadata:metadata}' -o json
```

Accept only static10.231.1.10 in the verified workload subnet, Standard SKU, no frontend public IP, no outbound rules, disableOutboundSnat=true, floatingIP=false, TCP8080 probe/rule, and exactly the discovered target NIC ip-config in the pool. Azure provisioning success is configuration evidence; collect actual backend health/packet evidence separately. Partial failure stops this recipe; inspect owned resources before retrying rather than overwriting existing DNS or pool state.

Then normal Tunnex API qualification must use a DISTINCT TCP8080 resource for10.231.1.10/32 and grant only source10.233.10.2/32. Existing backend10.231.1.4 grant is insufficient for the LB destination. Prove default-deny, narrow grant, fresh/persistent HTTP through the actual frontend, target-observed client source, revocation, and resolution of lbapp.azure-s2s.test through the selected private resolvers. For FQDN enforcement use a separate bound lbapp FQDN resource/impact-reviewed opt-in; do not relabel direct target probes as LB proof. Existing packet helper is intentionally bounded to the direct target, so root must use a separately reviewed LB probe or explicit bounded command rather than silently substituting its destination. One backend cannot demonstrate backend redundancy.
