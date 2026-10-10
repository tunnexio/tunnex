#!/usr/bin/env python3
"""Normal API authority for one owned private LB /32; no packet/readiness claim."""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
import json
from pathlib import Path
import uuid

spec = importlib.util.spec_from_file_location('azure_enrollment', Path(__file__).with_name('enroll-local.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

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

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'grant', 'revoke', 'read'))
    parser.add_argument('--private-root', type=Path, required=True)
    parser.add_argument('--connection-id', required=True)
    parser.add_argument('--expiry-seconds', type=int, default=90)
    args = parser.parse_args()
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
    client = lab.Client(accounts['owner'])
    orgs = client.call('GET', '/api/v1/organizations')
    if not any(o['id'] == setup['org_id'] and o['slug'] == 'azure-s2s-local' for o in orgs):
        raise lab.LabError('Owned Azure organization required')
    base = '/api/v1/organizations/' + setup['org_id']
    connection = client.call('GET', base + '/ipsec/connections/' + args.connection_id)
    if connection['site_id'] != setup['site_id'] or connection['gateway_node_id'] != setup['gateway_id'] or connection['desired_intent'] != 'enabled':
        raise lab.LabError('Enabled owned connection required; restore/readiness is a separate lead gate')
    config = client.call('GET', base + '/ipsec/connections/' + args.connection_id + '/configuration')['configuration']
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
    if args.phase == 'prepare':
        if state.get('resource_id'):
            raise lab.LabError('LB already prepared; use explicit grant/revoke')
        state['resource_id'] = client.call('POST', base + '/resources', resource_body())['id']
        save()
    else:
        if not state.get('resource_id'):
            raise lab.LabError('Prepare distinct LB resource first')
        resource = client.call('GET', base + '/resources/' + state['resource_id'])
        if any(resource.get(k) != v for k, v in resource_body().items()):
            raise lab.LabError('Stored LB resource no longer matches owned /32')
        if args.phase == 'grant':
            if state['rule_id']:
                raise lab.LabError('Revoke previous LB rule first')
            expiry = (datetime.now(timezone.utc) + timedelta(seconds=args.expiry_seconds)).isoformat()
            rule = client.call('POST', base + '/policies', {'src_kind': 'cidr', 'src_cidr': '10.233.10.2/32', 'dst_kind': 'resource', 'dst_resource_id': state['resource_id'], 'expires_at': expiry})
            state.update(rule_id=rule['id'], expires_at=expiry)
            save()
        elif args.phase == 'revoke':
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
    except (lab.LabError, OSError, KeyError, TypeError, ValueError):
        raise SystemExit('Owned LB API input/state/authority check failed; inspect private state without exposing credentials')
