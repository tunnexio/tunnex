#!/usr/bin/env bash
# Bastion-only, isolated owned lab. Never touches existing bastion SSH keys.
set -euo pipefail
[[ $(hostname) == bastion-host ]] || exit 1
rg=tunnex-azure-s2s-20261010
owner=azure-s2s-01a12505
[[ $(az group show -n "$rg" --query tags.owner -o tsv) == "$owner" ]] || { echo 'Foreign scope refused'; exit 1; }
state="$HOME/.tunnex-azure-s2s-01a12505"
install -d -m 700 "$state"
if [[ ! -f "$state/lab-ssh" ]]; then ssh-keygen -q -t ed25519 -N '' -f "$state/lab-ssh"; fi
az network vnet create -g "$rg" -n peer-vnet-ci -l centralindia --address-prefixes 10.232.0.0/16 --subnet-name peer --subnet-prefixes 10.232.1.0/24 --tags owner="$owner" purpose=owned-s2s-test -o none
az network nsg create -g "$rg" -l centralindia -n peer-nsg-ci --tags owner="$owner" purpose=owned-s2s-test -o none
az network nsg rule create -g "$rg" --nsg-name peer-nsg-ci -n bastion-ssh --priority 100 --source-address-prefixes 104.211.219.1/32 --destination-port-ranges 22 --protocol Tcp --access Allow -o none
for slot in 1 2; do
  ip=$(az network public-ip show -g "$rg" -n gateway-ip$slot --query ipAddress -o tsv)
  [[ -n "$ip" ]] || { echo 'Gateway public IP pending'; exit 1; }
  az network nsg rule create -g "$rg" --nsg-name peer-nsg-ci -n "azure-ike-$slot" --priority "$((110+slot))" --source-address-prefixes "$ip/32" --destination-port-ranges 500 4500 --protocol Udp --access Allow -o none
done
az network public-ip create -g "$rg" -n peer-ip -l centralindia --sku Standard --allocation-method Static --tags owner="$owner" purpose=owned-s2s-test -o none
az network nic create -g "$rg" -n peer-nic -l centralindia --vnet-name peer-vnet-ci --subnet peer --network-security-group peer-nsg-ci --public-ip-address peer-ip --private-ip-address 10.232.1.4 --ip-forwarding true --tags owner="$owner" purpose=owned-s2s-test -o none
az vm create -g "$rg" -n tunnex-peer -l centralindia --nics peer-nic --image Ubuntu2204 --size Standard_D2s_v5 --admin-username ubuntu --ssh-key-values "$state/lab-ssh.pub" --os-disk-size-gb 30 --tags owner="$owner" purpose=owned-s2s-test --no-wait -o none
az network nsg create -g "$rg" -n target-nsg --tags owner="$owner" purpose=owned-s2s-test -o none
az network nsg rule create -g "$rg" --nsg-name target-nsg -n tunnel-app --priority 100 --source-address-prefixes 10.232.1.0/24 --destination-port-ranges 8080 8081 --protocol '*' --access Allow -o none
az network nic create -g "$rg" -n target-nic --vnet-name azure-vnet --subnet workload --network-security-group target-nsg --private-ip-address 10.231.1.4 --tags owner="$owner" purpose=owned-s2s-test -o none
az vm create -g "$rg" -n azure-target --nics target-nic --image Ubuntu2204 --size Standard_D2s_v5 --admin-username ubuntu --ssh-key-values "$state/lab-ssh.pub" --os-disk-size-gb 30 --tags owner="$owner" purpose=owned-s2s-test --no-wait -o none
printf '%s\n' 'Two owned minimum available two-core VM requests submitted; private target has no public IP'
