#!/usr/bin/env python3
"""Check source-bound GCP receipt integrity; never run cloud tests or certify claims."""
import argparse
import json
import pathlib
from check_cloud_walk import check_walk

COMMON_CHECKS = (
    'behind_host_tcp_udp', 'policy_allow_deny', 'bad_key_refusal',
    'return_route_failure', 'spoof_refusal', 'lease_expiry_recovery',
    'mtu_mss_pmtud_df_fragmentation', 'lower_mtu_both_directions',
    'restart_recovery', 'host_reboot', 'protocol_rekey', 'maintenance_rotation',
    'disable_cleanup', 'delete_finalized_recreate_enable', 'foreign_resource_preservation',
    'two_tab_revision_refusal', 'dns_udp_tcp', 'dns_a_cname_nxdomain',
    'dns_truncated_udp_tcp', 'dns_policy_expiry_denial', 'private_application_packets',
    'role_mobile_ui',
)
PROFILE_CHECKS = {
    'gcp-ha-bgp-ipv4-v1': COMMON_CHECKS + (
        'bgp_exact_prefix_import_export', 'bgp_default_subprefix_refusal',
        'bgp_max_prefix', 'per_prefix_path_selection', 'tunnel_1_failure',
        'tunnel_2_failure', 'both_tunnels_failure', 'return_path_independence',
        'fresh_existing_flow_downtime',
    ),
    'gcp-classic-static-ipv4-v1': COMMON_CHECKS + (
        'single_tunnel_static_route', 'tunnel_loss_recovery',
        'fresh_existing_flow_downtime',
    ),
}


def check(document, root):
    if not isinstance(document, dict) or document.get('profile') not in PROFILE_CHECKS:
        return ['unsupported GCP profile']
    profile = document['profile']
    return check_walk(document, root, profile=profile, environment='live-gcp',
        checks_required=PROFILE_CHECKS[profile], environment_error='live GCP evidence required')


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
        print('Evidence complete and hashes match. Technical and secret review remain required; this does not certify GCP support.')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
