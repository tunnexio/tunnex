#!/usr/bin/env bash
# Bastion-only private DNS lab; no public fallback or managed LB IP copying.
set -euo pipefail
[[ $(hostname) == bastion-host ]] || exit 1
rg=tunnex-azure-s2s-20261010
owner=azure-s2s-01a12505
[[ $(az group show -n "$rg" --query tags.owner -o tsv) == "$owner" ]] || exit 1
vnet=$(az network vnet show -g "$rg" -n azure-vnet --query id -o tsv)
az network vnet subnet create -g "$rg" --vnet-name azure-vnet -n resolver-inbound2 --address-prefixes 10.231.2.16/28 --delegations Microsoft.Network/dnsResolvers -o none
az resource create -g "$rg" -n azure-resolver --resource-type Microsoft.Network/dnsResolvers --api-version 2022-07-01 -l southindia --properties "{\"virtualNetwork\":{\"id\":\"$vnet\"}}" --tags owner="$owner" purpose=owned-s2s-test -o none
for slot in 1 2; do
  subnet=resolver-inbound; ip=10.231.2.4
  if [[ "$slot" == 2 ]]; then subnet=resolver-inbound2; ip=10.231.2.20; fi
  sid=$(az network vnet subnet show -g "$rg" --vnet-name azure-vnet -n "$subnet" --query id -o tsv)
  az resource create -g "$rg" -n "azure-resolver/inbound$slot" --resource-type Microsoft.Network/dnsResolvers/inboundEndpoints --api-version 2022-07-01 -l southindia --properties "{\"ipConfigurations\":[{\"privateIpAllocationMethod\":\"Static\",\"privateIpAddress\":\"$ip\",\"subnet\":{\"id\":\"$sid\"}}]}" --tags owner="$owner" purpose=owned-s2s-test -o none
done
az network private-dns zone create -g "$rg" -n azure-s2s.test --tags owner="$owner" purpose=owned-s2s-test -o none
az network private-dns link vnet create -g "$rg" -z azure-s2s.test -n azure-vnet-link -v "$vnet" -e false --tags owner="$owner" purpose=owned-s2s-test -o none
az network private-dns record-set a add-record -g "$rg" -z azure-s2s.test -n app -a 10.231.1.4 -o none
az network private-dns record-set cname set-record -g "$rg" -z azure-s2s.test -n service -c app.azure-s2s.test -o none
printf '%s\n' 'Owned private resolver endpoints and private service records created; tunnel DNS acceptance pending'
