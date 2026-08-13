#!/usr/bin/env bash
# k3s-demo.sh — bring up the review cluster for the Kubernetes screen, and VERIFY it.
#
# ⛔ WHY THIS EXISTS, AND WHY IT VERIFIES RATHER THAN JUST STARTS.
#
# The S14.8 survival test proved THE SCREEN LOOKS IDENTICAL WHETHER k3s IS UP OR DOWN: with the cluster
# stopped, the control plane still served all three exposed Services, with VIPs and FQDNs, and the fronting
# gateway reported `site_link_down` rather than `k8s_endpoints_unavailable`. Nothing in the product knew.
#
# So a review that does not confirm the cluster is running is a review of a screen that may be lying, and
# under the Human Gate Limit Law that review is INVALID. Hence:
#
#   A BRING-UP THAT STARTS A CONTAINER AND REPORTS SUCCESS IS THE SAME CLASS AS `seed-fixtures` COUNTING ITS
#   OWN INSERTS. IT MUST CHECK THE STATE IT CLAIMS TO HAVE PRODUCED.
#
# Every CIDR below was chosen by MEASUREMENT against the demo org, not from k3s defaults — all three
# documented defaults collide with our fixture ranges (see docs/S14.8-findings.md Part B):
#
#   k3s Service CIDR 10.43.0.0/16  contains routed 10.43.0.0/24
#   k3s pod CIDR     10.42.0.0/16  contains routed 10.42.0.0/24
#   upstream         10.96.0.0/12  contains the device pool 10.99.0.0/24
#
# Usage:  scripts/k3s-demo.sh up | verify | down
set -euo pipefail

PROJECT="${COMPOSE_PROJECT_NAME:-tunnex}"
NET="${PROJECT}_default"
NAME=tunnex-k3s
K3S_IMAGE=rancher/k3s:v1.31.5-k3s1
SERVICE_CIDR=10.96.0.0/16     # clear of the device pool at 10.99
CLUSTER_CIDR=10.97.0.0/16
VIP_RANGE=10.50.0.0/24        # 10/8 slots 10,20,30,31,40,42,43,99 are taken; 50 is clear
DNS_ZONE=k8s.demo.local
CLUSTER_NAME=hq-k3s
API=http://localhost/api/v1
ORG=01900000-0000-7000-8000-000000000001
OWNER=owner@demo.tunnex.local
PASS=tunnex-demo-password
COOKIES="${TMPDIR:-/tmp}/tunnex-k3s-cookies.txt"

# Namespace/name/port triples exposed through the API. Three namespaces so the FQDN pattern
# <service>.<namespace>.svc.<cluster>.<zone> is legible at N>1, which N=1 cannot show.
SERVICES="payments:ledger:8080 analytics:metabase:3000 default:gateway-api:443"

log() { printf '\033[36m>>\033[0m %s\n' "$*"; }

# ⛔ THE KUBECONFIG IS READ OUT OF THE CONTAINER, NOT FROM A FILE ON DISK. A path-based kubeconfig makes
# `verify` depend on WHICH shell created the cluster — the exact dependency this script exists to remove (a
# review a week from now must not need this session's history). The container is the single source of truth.
kube() {
  docker exec "$NAME" kubectl "$@" 2>/dev/null
}
die() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

api() { # api METHOD PATH [JSON]
  local m=$1 p=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -s -b "$COOKIES" -c "$COOKIES" -X "$m" "$API$p" \
      -H 'Content-Type: application/json' -H 'X-Tunnex-CSRF: x' -d "$body"
  else
    curl -s -b "$COOKIES" -c "$COOKIES" -X "$m" "$API$p" -H 'X-Tunnex-CSRF: x'
  fi
}

login() {
  rm -f "$COOKIES"
  curl -s -c "$COOKIES" "$API/meta" -o /dev/null
  local code
  code=$(curl -s -b "$COOKIES" -c "$COOKIES" -o /dev/null -w '%{http_code}' -X POST "$API/auth/login" \
    -H 'Content-Type: application/json' -H 'X-Tunnex-CSRF: x' \
    -d "{\"email\":\"$OWNER\",\"password\":\"$PASS\"}")
  [ "$code" = "200" ] || die "login returned $code — is the stack up? (COMPOSE_PROJECT_NAME=$PROJECT make up-enterprise)"
}

up() {
  docker network inspect "$NET" >/dev/null 2>&1 || die "network $NET not found — start the stack first"
  log "starting k3s ($NAME) on $NET  service-cidr=$SERVICE_CIDR cluster-cidr=$CLUSTER_CIDR"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" --privileged --network "$NET" -p 6443:6443 \
    "$K3S_IMAGE" server \
      --service-cidr "$SERVICE_CIDR" --cluster-cidr "$CLUSTER_CIDR" \
      --disable traefik --disable metrics-server --tls-san 127.0.0.1 >/dev/null
  log "waiting for the node to be Ready"
  local n=0
  until kube get nodes 2>/dev/null | grep -q ' Ready '; do
    n=$((n+1)); [ "$n" -gt 90 ] && die "node never became Ready"; sleep 2
  done

  log "creating workloads in three namespaces"
  for triple in $SERVICES; do
    IFS=: read -r ns name port <<<"$triple"
    kube create namespace "$ns" >/dev/null 2>&1 || true
    kube -n "$ns" create deployment "$name" --image=nginx:alpine >/dev/null 2>&1 || true
    kube -n "$ns" expose deployment "$name" --port="$port" --target-port=80 >/dev/null 2>&1 || true
  done

  login
  log "registering the cluster THROUGH THE API (not the DB)"
  local site cluster cid
  site=$(api GET "/organizations/$ORG/sites" | python3 -c \
    'import sys,json; print(next(s["id"] for s in json.load(sys.stdin) if s["name"]=="hq-lan"))')
  cluster=$(api POST "/organizations/$ORG/k8s/clusters" \
    "{\"site_id\":\"$site\",\"name\":\"$CLUSTER_NAME\",\"vip_range\":\"$VIP_RANGE\",\"service_cidr\":\"$SERVICE_CIDR\",\"dns_zone\":\"$DNS_ZONE\"}")
  cid=$(printf '%s' "$cluster" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("id",""))')
  if [ -z "$cid" ]; then
    # Already registered is not a failure — this script is re-runnable.
    cid=$(api GET "/organizations/$ORG/k8s/clusters" | python3 -c \
      "import sys,json; print(next((c['id'] for c in json.load(sys.stdin) if c['name']=='$CLUSTER_NAME'),''))")
    [ -n "$cid" ] || die "cluster registration failed: $cluster"
    log "cluster already registered ($cid)"
  fi

  log "exposing Services through the API"
  for triple in $SERVICES; do
    IFS=: read -r ns name port <<<"$triple"
    # ⛔ port_high IS SENT EXPLICITLY. The spec says "omit for a single port"; the DB CHECK is both-or-neither,
    # and nothing validates between them, so omitting it returns a 500 (findings A2/A2b, disposition D6).
    # This is a WORKAROUND, not a fix — remove it once D6 lands.
    api POST "/organizations/$ORG/k8s/clusters/$cid/services" \
      "{\"name\":\"$name\",\"namespace\":\"$ns\",\"protocol\":\"tcp\",\"port_low\":$port,\"port_high\":$port}" >/dev/null
  done
  verify
}

verify() {
  log "VERIFYING — a bring-up that only starts things proves nothing"
  docker ps --format '{{.Names}}' | grep -qx "$NAME" || die "$NAME is not running"
  kube get nodes | grep -q ' Ready ' || die "no Ready node"

  local want got
  want=$(printf '%s\n' $SERVICES | tr ' ' '\n' | grep -c . )
  got=$(kube get svc -A --no-headers | grep -cE '(ledger|metabase|gateway-api)' || true)
  [ "$got" -eq "$want" ] || die "expected $want Services in Kubernetes, found $got"

  login
  # ⛔ ARM 4 — THE CP LIST MUST MATCH THE LIVE CLUSTER, NAME BY NAME.
  #
  # "the CP lists some Services" and "the CP lists the Services that exist" are different claims, and only the
  # second is worth a reviewer's trust. This arm catches ABSENCE #2 from the findings — a Service deleted in
  # Kubernetes while still exposed in the control plane — which the D9 rendering rule explicitly does NOT
  # cover. The verifier catching it is the only place that gap is visible today.
  local live cp
  live=$(kube get svc -A --no-headers | awk '{print $2}' | grep -E '^(ledger|metabase|gateway-api)$' | sort | tr '\n' ' ')
  cp=$(api GET "/organizations/$ORG/k8s/services" | python3 -c '
import sys, json
svcs = json.load(sys.stdin)
if not isinstance(svcs, list) or not svcs:
    raise SystemExit(1)
for s in sorted(svcs, key=lambda x: x["fqdn"]):
    print("   %-12s %s" % (s["vip"], s["fqdn"]), file=sys.stderr)
print(" ".join(sorted(s["name"] for s in svcs)) + " ")
' ) || die "the control plane lists NO exposed Services (arm 4: CP is empty)"
  [ "$live" = "$cp" ] || die "arm 4: the CP list and the live cluster DISAGREE
     live cluster : $live
     control plane: $cp
   A Service in one and not the other is finding 'absence #2' — the screen would show it as LIVE."

  printf '\033[32mOK\033[0m the review cluster is up and the control plane agrees with it\n'
  # ⛔ THE ONE THING THIS CANNOT VERIFY, STATED RATHER THAN OMITTED: no gateway in this stack WATCHES the
  # cluster, so `k8s_endpoints_unavailable` never fires here. Any rendering rule keyed on it (D9) is
  # UNVERIFIABLE in this environment — see docs/S14.8-findings.md D9(b).
  printf '\033[33m!!\033[0m k8s_endpoints_unavailable cannot fire in this stack — D9 is unverifiable here\n'
}

down() {
  log "stopping k3s (control-plane rows are left INTACT — that asymmetry is finding D9)"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  printf '\033[32mOK\033[0m stopped. The screen will still list the Services; that is the finding, not a bug in this script.\n'
}

case "${1:-up}" in
  up) up ;;
  verify) verify ;;
  down) down ;;
  *) die "usage: $0 up|verify|down" ;;
esac
