#!/usr/bin/env python3
"""Normal API authority for one owned private LB /32; no packet/readiness claim."""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
import json
import re
from pathlib import Path
import uuid

spec = importlib.util.spec_from_file_location('azure_enrollment', Path(__file__).with_name('enroll-local.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
STAGE = 'inputs'

def saved_resource(client, path, ident):
    values = client.call('GET', path)
    if not isinstance(values, list):
        raise lab.LabError('Normal resource list required')
    matches = [value for value in values if isinstance(value, dict) and value.get('id') == ident]
    if len(matches) != 1:
        raise lab.LabError('Exact singular saved resource required')
    return matches[0]

def safe_diagnostic(error):
    result = 'Owned LB API failed at stage=' + STAGE
    if isinstance(error, lab.LabError):
        if isinstance(error.status, int) and 100 <= error.status <= 599:
            result += ' status=' + str(error.status)
        if isinstance(error.code, str) and re.fullmatch(r'[a-z0-9_]{1,64}', error.code):
            result += ' code=' + error.code
    return result

def protected_ids(state):
    result = []
    for key, count in (('dns_rules', 4), ('app_rules', 2), ('reverse_rules', 2)):
        values = state.get(key)
        if not isinstance(values, list) or len(values) != count:
            raise lab.LabError('Expected existing DNS/application/reverse rules required')
        result.extend(values)
    if len(set(result)) != 8:
        raise lab.LabError('Existing rule identities must be distinct')
    return set(result)

def resource_body():
    return {'name': 'Azure owned private LB TCP', 'cidr': '10.231.1.10/32',
            'protocol': 'tcp', 'port_low': 8080, 'port_high': 8080}

def selected_profile(context, connection_id, revision):
    host = 'lbapp.azure-s2s.test'
    matches = [(len(suffix.split('.')), profile) for profile in context['profiles'] for suffix in profile['zone_suffixes']
               if host == suffix or host.endswith('.' + suffix)]
    if not matches:
        raise lab.LabError('Actual private suffix profile required')
    longest = max(length for length, _ in matches)
    selected = {p['id']: p for length, p in matches if length == longest}
    if len(selected) != 1:
        raise lab.LabError('Unambiguous most-specific DNS profile required')
    profile = next(iter(selected.values()))
    expected = {(ip, 53, transport) for ip in ('10.231.2.4', '10.231.2.20') for transport in ('udp', 'tcp')}
    actual = {(e['address'], e['port'], e['transport']) for e in profile['endpoints']}
    if context['state'] != 'active' or profile['provider_hint'] != 'azure' or profile['legacy_default'] or profile['zone_suffixes'] != ['azure-s2s.test'] or actual != expected or len(profile['endpoints']) != 4:
        raise lab.LabError('Exact shared owned Azure private resolver profile required')
    if profile.get('ipsec_path') != {'connection_id': connection_id, 'configuration_revision': revision, 'source_address': '10.233.10.1'}:
        raise lab.LabError('Current IPsec revision and actual gateway DNS source binding required')
    return profile

def fqdn_detail_projection(detail, setup, state, binding, now):
    resource = detail['resource']
    context = resource.get('resolver_context')
    if not isinstance(context, dict) or context.get('site_id') != setup['site_id'] or context.get('gateway_id') != setup['gateway_id']:
        raise lab.LabError('FQDN resource context identity changed')
    config = context.get('resolver_config')
    if not isinstance(config, dict) or config.get('id') != binding['context_id'] or config.get('version') != binding['context_version']:
        raise lab.LabError('FQDN nested resolver configuration changed')
    profile = selected_profile(config, state['connection_id'], binding['configuration_revision'])
    if profile['id'] != binding['profile_id'] or resource.get('id') != state['fqdn_resource_id'] or resource.get('org_id') != setup['org_id'] or resource.get('fqdn') != 'lbapp.azure-s2s.test' or resource.get('destination_kind') != 'fqdn' or resource.get('protocol') != 'tcp' or resource.get('port_low') != 8080 or resource.get('port_high') != 8080:
        raise lab.LabError('Stored distinct LB FQDN resource changed')
    value = {'resource_id': state['fqdn_resource_id'], 'resolver_config_id': binding['context_id'], 'resolver_config_version': binding['context_version'], 'resolver_profile_id': binding['profile_id'], 'configuration_revision': binding['configuration_revision'], 'dns_source_address': '10.233.10.1', 'ready': False}
    if resource.get('state') not in ('draft', 'unconfigured', 'resolving', 'healthy', 'stale', 'failed', 'nxdomain') or detail.get('status_source') not in ('resource_configuration', 'resolver_configuration', 'latest_generation', 'active_generation'):
        raise lab.LabError('Unknown FQDN status contract')
    value.update(state=resource['state'], status_source=detail['status_source'])
    # Public detail exposes persisted failure as server_reason, not a mailbox
    # failure_code/status alias. Only the stable lifecycle vocabulary is safe.
    reason = detail.get('server_reason')
    reasons = {'nxdomain', 'servfail', 'timeout', 'disagreement', 'overflow', 'last_good_expired', 'invalid_answer', 'unbound_context', 'NXDOMAIN', 'SERVFAIL'}
    if isinstance(reason, str) and reason in reasons:
        value['failure_code'] = reason
    elif reason is not None:
        value['failure_code'] = 'unrecognized_server_reason'
    if resource['state'] != 'healthy' or detail['status_source'] != 'active_generation' or detail.get('resolver_ready') is not True:
        return value
    generation = resource.get('generation')
    selection = resource.get('resolver_profile_selection')
    addresses = detail.get('active_answer_addresses')
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0 or resource.get('answer_count') != 1 or addresses != ['10.231.1.10']:
        raise lab.LabError('Exact actual active LB generation required')
    if not isinstance(selection, dict) or selection.get('id') != binding['profile_id'] or selection.get('config_version') != binding['context_version'] or selection.get('matched_suffix') != 'azure-s2s.test' or selection.get('provider_hint') != 'azure':
        raise lab.LabError('Active generation profile provenance changed')
    if not isinstance(detail.get('fresh_until_at'), str) or not isinstance(detail.get('observed_at'), str):
        raise lab.LabError('Actual generation timestamps required')
    fresh = datetime.fromisoformat(detail['fresh_until_at'].replace('Z', '+00:00'))
    observed = datetime.fromisoformat(detail['observed_at'].replace('Z', '+00:00'))
    if fresh.tzinfo is None or observed.tzinfo is None or observed > now or fresh <= now:
        raise lab.LabError('Fresh actual generation required')
    value.update(ready=True, generation=generation, active_answer_addresses=['10.231.1.10'], observed_at=observed.isoformat(), fresh_until_at=fresh.isoformat())
    return value

def main():
    global STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'grant', 'revoke', 'read', 'fqdn-prepare', 'fqdn-enable', 'fqdn-read', 'fqdn-grant', 'fqdn-revoke'))
    parser.add_argument('--private-root', type=Path, required=True)
    parser.add_argument('--connection-id', required=True)
    parser.add_argument('--expiry-seconds', type=int, default=90)
    args = parser.parse_args()
    STAGE = 'inputs'
    if not 30 <= args.expiry_seconds <= 300 or str(uuid.UUID(args.connection_id)) != args.connection_id:
        raise lab.LabError('Canonical connection and bounded expiry required')
    private = args.private_root.resolve()
    loaded = {}
    for name in ('ui-accounts.json', 'api-setup.json', 'dns-api-setup.json'):
        path = private / name
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise lab.LabError('Private owned inputs required')
        loaded[name] = json.loads(path.read_text())
    accounts, setup, dns = (loaded[name] for name in ('ui-accounts.json', 'api-setup.json', 'dns-api-setup.json'))
    if accounts['owner']['email'] != 'browser-owner@azure-s2s.local' or dns['connection_id'] != args.connection_id or dns['source_address'] != '10.233.10.2':
        raise lab.LabError('Owned Azure source and connection required')
    protected = protected_ids(dns)
    STAGE = 'owned_authority_read'
    client = lab.Client(accounts['owner'])
    orgs = client.call('GET', '/api/v1/organizations')
    if not any(o['id'] == setup['org_id'] and o['slug'] == 'azure-s2s-local' for o in orgs):
        raise lab.LabError('Owned Azure organization required')
    base = '/api/v1/organizations/' + setup['org_id']
    connection = client.call('GET', base + '/ipsec/connections/' + args.connection_id)
    if connection['site_id'] != setup['site_id'] or connection['gateway_node_id'] != setup['gateway_id'] or connection['desired_intent'] != 'enabled':
        raise lab.LabError('Enabled owned connection required; restore/readiness is a separate lead gate')
    config_view = client.call('GET', base + '/ipsec/connections/' + args.connection_id + '/configuration')
    config = config_view['configuration']
    if '10.233.10.0/24' not in config['local_prefixes'] or not any(ipaddress.ip_address('10.231.1.10') in ipaddress.ip_network(p) for p in config['remote_prefixes']):
        raise lab.LabError('Actual owned source/LB prefixes required')
    statepath = private / 'lb-api-setup.json'
    if statepath.is_symlink() or (statepath.exists() and statepath.stat().st_mode & 0o077):
        raise lab.LabError('Private LB state required')
    state = json.loads(statepath.read_text()) if statepath.exists() else {'connection_id': args.connection_id, 'source_address': '10.233.10.2', 'resource_body': resource_body(), 'rule_id': None, 'protected_policy_ids': sorted(protected)}
    if state['connection_id'] != args.connection_id or state['source_address'] != '10.233.10.2' or state['resource_body'] != resource_body() or set(state['protected_policy_ids']) != protected:
        raise lab.LabError('Existing LB qualification identity changed')
    def save():
        lab.private_write(statepath, json.dumps(state, indent=2))
    def verify_protected():
        policies = client.call('GET', base + '/policies')
        if not protected <= {p['id'] for p in policies}:
            raise lab.LabError('Existing DNS/application/reverse rules missing; no mutation allowed')
        return policies
    verify_protected()
    if args.phase.startswith('fqdn-'):
        STAGE = 'fqdn_binding_read'
        if state['rule_id']:
            raise lab.LabError('Explicitly revoke LB IP grant before separate FQDN proof')
        context = client.call('GET', base + '/fqdn-resolver-contexts/' + setup['site_id'] + '/' + setup['gateway_id'])
        if context['org_id'] != setup['org_id'] or context['site_id'] != setup['site_id'] or context['gateway_id'] != setup['gateway_id']:
            raise lab.LabError('Actual shared resolver context identity required')
        profile = selected_profile(context, args.connection_id, config_view['configuration_revision'])
        binding = {'context_id': context['id'], 'context_version': context['version'], 'profile_id': profile['id'], 'configuration_revision': config_view['configuration_revision'], 'source_address': '10.233.10.1'}
        if state.get('fqdn_binding', binding) != binding:
            raise lab.LabError('Resolver/profile/revision changed; review before new FQDN proof')
        if args.phase == 'fqdn-prepare':
            STAGE = 'fqdn_resource_prepare'
            if state.get('fqdn_resource_id'):
                raise lab.LabError('LB FQDN already prepared')
            resource = client.call('POST', base + '/fqdn-resources', {'name': 'Azure owned private LB FQDN', 'fqdn': 'lbapp.azure-s2s.test', 'protocol': 'tcp', 'port_low': 8080, 'port_high': 8080, 'resolver_context': {'site_id': setup['site_id'], 'gateway_id': setup['gateway_id']}})
            state.update(fqdn_resource_id=resource['id'], fqdn_binding=binding, fqdn_rule_id=None)
            save()
        elif args.phase == 'fqdn-enable':
            STAGE = 'fqdn_opt_in'
            impact = client.call('GET', base + '/fqdn-resources/setting/impact')
            if not impact['entitlement_available']:
                raise lab.LabError('Genuine current FQDN entitlement unavailable')
            client.call('PUT', base + '/fqdn-resources/setting', {'enabled': True, 'expected_impact_token': impact['expected_impact_token']})
        elif args.phase in ('fqdn-read', 'fqdn-grant'):
            STAGE = 'fqdn_resource_validation'
            if not state.get('fqdn_resource_id') or args.phase == 'fqdn-grant' and state.get('fqdn_rule_id'):
                raise lab.LabError('Prepared FQDN without previous rule required')
            detail = client.call('GET', base + '/fqdn-resources/' + state['fqdn_resource_id'])
            state['fqdn_observation'] = fqdn_detail_projection(detail, setup, state, binding, datetime.now(timezone.utc))
            save()
            if args.phase == 'fqdn-read':
                verify_protected()
                observation = state['fqdn_observation']
                print(json.dumps({key: observation[key] for key in ('ready', 'state', 'status_source', 'failure_code') if key in observation}))
                return
            if not state['fqdn_observation']['ready']:
                raise lab.LabError('Actual fresh FQDN generation not ready; no grant')
            expiry = (datetime.now(timezone.utc) + timedelta(seconds=args.expiry_seconds)).isoformat()
            STAGE = 'fqdn_grant'
            rule = client.call('POST', base + '/policies', {'src_kind': 'cidr', 'src_cidr': '10.233.10.2/32', 'dst_kind': 'fqdn_resource', 'dst_fqdn_resource_id': state['fqdn_resource_id'], 'expires_at': expiry})
            state.update(fqdn_rule_id=rule['id'], fqdn_expires_at=expiry)
            save()
        elif args.phase == 'fqdn-revoke' and state.get('fqdn_rule_id'):
            STAGE = 'fqdn_revoke'
            try:
                client.call('DELETE', base + '/policies/' + state['fqdn_rule_id'])
            except lab.LabError as error:
                if error.status != 404 or error.code != 'rule_not_found':
                    raise
            state['fqdn_rule_id'] = None
            save()
        verify_protected()
        print('Owned LB FQDN API phase completed: ' + args.phase + '; DNS generation and packet enforcement unverified.')
        return
    if args.phase == 'prepare':
        STAGE = 'lb_resource_prepare'
        if state.get('resource_id'):
            raise lab.LabError('LB already prepared; use explicit grant/revoke')
        state['resource_id'] = client.call('POST', base + '/resources', resource_body())['id']
        save()
    else:
        if not state.get('resource_id'):
            raise lab.LabError('Prepare distinct LB resource first')
        STAGE = 'lb_resource_validation'
        resource = saved_resource(client, base + '/resources', state['resource_id'])
        if any(resource.get(k) != v for k, v in resource_body().items()):
            raise lab.LabError('Stored LB resource no longer matches owned /32')
        if args.phase == 'grant':
            if state['rule_id'] or state.get('fqdn_rule_id'):
                raise lab.LabError('Revoke previous LB rule first')
            expiry = (datetime.now(timezone.utc) + timedelta(seconds=args.expiry_seconds)).isoformat()
            STAGE = 'lb_grant'
            rule = client.call('POST', base + '/policies', {'src_kind': 'cidr', 'src_cidr': '10.233.10.2/32', 'dst_kind': 'resource', 'dst_resource_id': state['resource_id'], 'expires_at': expiry})
            state.update(rule_id=rule['id'], expires_at=expiry)
            save()
        elif args.phase == 'revoke':
            STAGE = 'lb_revoke'
            if state['rule_id']:
                try:
                    client.call('DELETE', base + '/policies/' + state['rule_id'])
                except lab.LabError as error:
                    if error.status != 404 or error.code != 'rule_not_found':
                        raise
                state['rule_id'] = None
                save()
        elif args.phase == 'read':
            state['observed_at'] = datetime.now(timezone.utc).isoformat()
            save()
    verify_protected()
    print('Owned LB API phase completed: ' + args.phase + '; packet and persistent-flow enforcement are unverified.')

if __name__ == '__main__':
    try:
        main()
    except (lab.LabError, OSError, KeyError, TypeError, ValueError) as error:
        raise SystemExit(safe_diagnostic(error))
