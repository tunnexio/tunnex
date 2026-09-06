#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHART="$ROOT/deploy/helm/tunnex-cp"
VALUES=(--set appBaseURL=https://vpn.example.com --set masterKey.existingSecret=roots
  --set redis.urlSecret=redis --set database.urlSecret=customer-db)
helm lint "$CHART" "${VALUES[@]}"
for mode in legacy tls custom-key no-migration; do
  EXTRA=()
  case "$mode" in
    tls) EXTRA=(--set database.tls.existingSecret=customer-db-tls);;
    custom-key) EXTRA=(--set database.urlSecretKey=connection-uri --set database.tls.existingSecret=customer-db-tls);;
    no-migration) EXTRA=(--set migrations.enabled=false --set database.tls.existingSecret=customer-db-tls);;
  esac
  helm template byodb "$CHART" "${VALUES[@]}" ${EXTRA[@]+"${EXTRA[@]}"} | ruby -ryaml -e '
    mode = ARGV.fetch(0)
    docs = YAML.load_stream(STDIN.read).compact
    workloads = docs.select { |d| ["api", "migrate"].include?(d.dig("metadata", "labels", "app.kubernetes.io/component")) && ["Deployment", "Job"].include?(d["kind"]) }
    abort "missing workloads" unless workloads.size == (mode == "no-migration" ? 1 : 2)
    workloads.each do |w|
      pod = w.fetch("spec").fetch("template").fetch("spec")
      container = pod.fetch("containers").first
      env = container.fetch("env").find { |e| ["DATABASE_URL", "TUNNEX_DATABASE_URL"].include?(e["name"]) }
      expected_key = mode == "custom-key" ? "connection-uri" : "TUNNEX_DATABASE_URL"
      abort "secret drift" unless env.fetch("valueFrom").fetch("secretKeyRef") == {"name" => "customer-db", "key" => expected_key}
      mount = (container["volumeMounts"] || []).find { |v| v["name"] == "database-tls" }
      volume = (pod["volumes"] || []).find { |v| v["name"] == "database-tls" }
      if mode == "legacy"
        abort "legacy mount regression" if mount || volume || pod["securityContext"].key?("fsGroup")
      else
        abort "mount drift" unless mount == {"name" => "database-tls", "mountPath" => "/etc/tunnex/database-tls", "readOnly" => true}
        abort "secret permissions drift" unless volume.fetch("secret") == {"secretName" => "customer-db-tls", "defaultMode" => 288}
        abort "non-root readability drift" unless pod.fetch("securityContext")["fsGroup"] == 10001
      end
    end
  ' "$mode"
done
echo 'BYODB chart contracts passed (legacy, TLS, custom Secret key, migrations disabled)'
