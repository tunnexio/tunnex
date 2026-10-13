#!/usr/bin/env python3
"""Check source-bound Azure receipt integrity; never execute tests or certify claims."""
import argparse
import json
import pathlib
from check_cloud_walk import check_walk
from check_gcp_walk import COMMON_CHECKS

AZURE_COMMON = COMMON_CHECKS + (
    'azure_resource_ownership', 'azure_gateway_identity_status',
    'azure_custom_ipsec_policy', 'dns_private_resolver_linked_zone',
    'dns_resolver_failover', 'dns_no_public_wan_fallback',
)
PROFILE_CHECKS = {}
for topology in ('active-active', 'active-standby'):
    for mode in ('bgp', 'static'):
        checks = AZURE_COMMON + ('fresh_existing_flow_downtime',)
        if mode == 'bgp':
            checks += ('bgp_exact_prefix_import_export', 'bgp_default_subprefix_refusal',
                'bgp_max_prefix', 'per_prefix_path_selection', 'azure_apipa_peer_initiation')
        else:
            checks += ('static_exact_routes_selectors', 'static_return_route')
        checks += (('tunnel_1_failure', 'tunnel_2_failure', 'both_tunnels_failure',
            'return_path_independence') if topology == 'active-active' else ('tunnel_loss_recovery',))
        PROFILE_CHECKS[f'azure-{topology}-{mode}-ipv4-v1'] = checks


def check(document, root):
    if not isinstance(document, dict) or document.get('profile') not in PROFILE_CHECKS:
        return ['unsupported Azure profile']
    profile = document['profile']
    return check_walk(document, root, profile=profile, environment='live-azure',
        checks_required=PROFILE_CHECKS[profile], environment_error='live Azure evidence required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt', type=pathlib.Path)
    args = parser.parse_args()
    try:
        errors = check(json.loads(args.receipt.read_text()), args.receipt.parent)
    except (ValueError, OSError):
        errors = ['cannot read receipt JSON']
    for error in errors:
        print(error)
    if not errors:
        print('Evidence complete and hashes match. Technical and secret review remain required; this does not certify Azure support.')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
