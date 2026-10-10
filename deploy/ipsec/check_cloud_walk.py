"""Shared offline receipt integrity checks; no cloud access or certification."""
import hashlib
import pathlib
import re


def check_walk(document, root, *, profile, environment, checks_required, environment_error):
    """Return static errors only: receipt content and credentials are never echoed."""
    errors = []
    if not isinstance(document, dict):
        return ['invalid receipt']
    if document.get('schema_version') != 1 or document.get('profile') != profile:
        errors.append('unsupported receipt schema/profile')
    if not isinstance(document.get('source_sha'), str) or not re.fullmatch(r'[0-9a-f]{40}', document['source_sha']):
        errors.append('missing source commit')
    if document.get('environment') != environment:
        errors.append(environment_error)
    checks = document.get('checks')
    if not isinstance(checks, dict) or set(checks) != set(checks_required):
        return errors + ['required check set does not match']
    root = root.resolve()
    for name in checks_required:
        entry = checks[name]
        if not isinstance(entry, dict) or entry.get('status') != 'pass':
            errors.append(name + ': pending or failed')
            continue
        artifacts = entry.get('artifacts')
        if not isinstance(artifacts, list) or not artifacts:
            errors.append(name + ': missing evidence')
            continue
        for artifact in artifacts:
            try:
                if not isinstance(artifact, dict):
                    raise ValueError()
                relative = artifact['path']
                digest = artifact['sha256']
                if not isinstance(relative, str) or not relative or pathlib.Path(relative).is_absolute():
                    raise ValueError()
                if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                    raise ValueError()
                path = (root / relative).resolve()
                if not path.is_relative_to(root) or not path.is_file():
                    raise ValueError()
                if path.stat().st_size == 0:
                    raise ValueError()
                with path.open('rb') as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                if actual != digest:
                    raise ValueError()
            except (KeyError, TypeError, ValueError, OSError, RuntimeError):
                errors.append(name + ': invalid or changed evidence')
    return errors

