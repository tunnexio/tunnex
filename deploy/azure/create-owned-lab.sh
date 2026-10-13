#!/usr/bin/env bash
# Execute only on the authorized Azure bastion. No secret output.
set -euo pipefail
[[ $(hostname) == bastion-host ]] || { echo 'Run only on the designated Azure bastion'; exit 1; }
subscription=34e2f259-b462-40bf-8f4a-06a3930d99e6
[[ $(az account show --query id -o tsv) == "$subscription" ]] || { echo 'Unexpected selected subscription'; exit 1; }
rg=tunnex-azure-s2s-20261010
location=southindia
owner=azure-s2s-01a12505
if [[ $(az group exists -n "$rg") == true ]]; then
  [[ $(az group show -n "$rg" --query tags.owner -o tsv) == "$owner" ]] || { echo 'Foreign group refused'; exit 1; }
else
  az group create -n "$rg" -l "$location" --tags owner="$owner" purpose=owned-s2s-test created=2026-10-10 -o none
fi
az network vnet create -g "$rg" -n azure-vnet -l "$location" --address-prefixes 10.231.0.0/16 --subnet-name workload --subnet-prefixes 10.231.1.0/24 --tags owner="$owner" purpose=owned-s2s-test -o none
az network vnet subnet create -g "$rg" --vnet-name azure-vnet -n GatewaySubnet --address-prefixes 10.231.255.0/27 -o none
az network vnet subnet create -g "$rg" --vnet-name azure-vnet -n resolver-inbound --address-prefixes 10.231.2.0/28 --delegations Microsoft.Network/dnsResolvers -o none
az network vnet create -g "$rg" -n peer-vnet -l "$location" --address-prefixes 10.232.0.0/16 --subnet-name peer --subnet-prefixes 10.232.1.0/24 --tags owner="$owner" purpose=owned-s2s-test -o none
for pip in gateway-ip1 gateway-ip2; do
  az network public-ip create -g "$rg" -n "$pip" -l "$location" --sku Standard --allocation-method Static --tags owner="$owner" purpose=owned-s2s-test -o none
done
az network vnet-gateway create -g "$rg" -n azure-vpn -l "$location" --vnet azure-vnet --public-ip-addresses gateway-ip1 gateway-ip2 --gateway-type Vpn --vpn-type RouteBased --sku VpnGw1AZ --vpn-gateway-generation Generation1 --asn 65515 --tags owner="$owner" purpose=owned-s2s-test --no-wait -o none
printf '%s\n' 'Owned networks created; gateway provisioning requested (not tunnel acceptance)'
