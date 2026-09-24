"""Small helpers for captured, disposable qualification namespaces only."""
import json


def remove_lab_gateway_dns_table(run):
    """Remove Docker's optional DNS NAT table only inside the captured gateway.

    `run` revalidates the captured container and namespace before every command.
    Other table families and names are left for the runtime census to judge.
    """
    result = run('gateway', ['nft', '-j', 'list', 'tables'], capture_output=True)
    document = json.loads(result.stdout)
    tables = document['nftables']
    if not isinstance(tables, list):
        raise ValueError('invalid nft table census')
    matches = [entry for entry in tables if 'table' in entry
               and entry['table'].get('family') == 'ip'
               and entry['table'].get('name') == 'nat']
    if len(matches) > 1:
        raise ValueError('ambiguous nft table census')
    if matches:
        run('gateway', ['nft', 'delete', 'table', 'ip', 'nat'])
