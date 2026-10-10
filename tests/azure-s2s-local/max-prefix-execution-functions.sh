#!/usr/bin/env bash
# Source-only wrappers. Sourcing this file performs no API/cloud action.
# Root supplies existing absolute paths; helpers retain all identity/CAS gates.

max_prefix_limit() {
  : "${AZURE_SOURCE_ROOT:?reviewed source root required}" "${AZURE_PRIVATE_ROOT:?private root required}" "${AZURE_MAX_STATE:?new limit state required}"
  local phase="${1:?phase required}" output="${2:?new private output required}"
  shift 2
  case "$phase" in prepare|read|restore-read|disable|delete|create|enable) ;; *) return 64;; esac
  python3 "$AZURE_SOURCE_ROOT/tests/azure-s2s-local/qualify-max-prefix-api.py" "$phase" \
    --private-root "$AZURE_PRIVATE_ROOT" --state "$AZURE_MAX_STATE" --purpose limit --output "$output" "$@"
}

max_prefix_baseline() {
  : "${AZURE_SOURCE_ROOT:?reviewed source root required}" "${AZURE_PRIVATE_ROOT:?private root required}" "${AZURE_RESTORED_STATE:?new restoration state required}"
  local phase="${1:?phase required}" output="${2:?new private output required}"
  shift 2
  case "$phase" in prepare|read|restore-read|disable|delete|create|enable) ;; *) return 64;; esac
  python3 "$AZURE_SOURCE_ROOT/tests/azure-s2s-local/qualify-max-prefix-api.py" "$phase" \
    --private-root "$AZURE_PRIVATE_ROOT" --state "$AZURE_RESTORED_STATE" --purpose baseline --output "$output" "$@"
}

max_prefix_dns() {
  : "${AZURE_SOURCE_ROOT:?reviewed source root required}" "${AZURE_PRIVATE_ROOT:?private root required}" "${AZURE_DNS_TRANSITION:?existing prepared DNS state required}"
  local phase="${1:?phase required}"; shift
  # Deliberately excludes prepare: preserve the original eight-policy snapshot.
  case "$phase" in read|revoke|rebind|reconcile|sync-grants) ;; *) return 64;; esac
  python3 "$AZURE_SOURCE_ROOT/tests/azure-s2s-local/rebind-profile-dns.py" "$phase" \
    --private-root "$AZURE_PRIVATE_ROOT" --state-file "$AZURE_DNS_TRANSITION" "$@"
}

max_prefix_cloud() {
  : "${AZURE_SOURCE_ROOT:?reviewed source root required}" "${AZURE_CLOUD_STATE:?new bastion private state required}"
  local phase="${1:?phase required}" receipt="${2:?fresh normal receipt required}"
  shift 2
  case "$phase" in prepare|add|read|reconcile|restore) ;; *) return 64;; esac
  python3 "$AZURE_SOURCE_ROOT/deploy/azure/qualify-owned-max-prefix.py" "$phase" \
    --state "$AZURE_CLOUD_STATE" --normal-receipt "$receipt" "$@"
}
