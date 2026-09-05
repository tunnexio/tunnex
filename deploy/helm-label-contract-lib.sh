#!/bin/sh

helm_chart_label_expected() {
  chart_name=$1
  chart_version=$2
  printf '%s-%s' "$chart_name" "$chart_version" \
    | sed 's/+/_/g' \
    | cut -c1-63 \
    | sed 's/-$//'
}

assert_helm_chart_labels() {
  rendered=$1
  expected=$2
  subject=$3
  labels_file="${rendered}.helm-chart-labels"

  sed -n 's/^[[:space:]]*helm.sh\/chart: "\([^"]*\)"$/\1/p' "$rendered" >"$labels_file"
  if [ ! -s "$labels_file" ]; then
    echo "$subject rendered no quoted helm.sh/chart labels" >&2
    return 1
  fi
  if awk 'length($0) > 63 { bad = 1 } END { exit bad ? 0 : 1 }' "$labels_file"; then
    echo "$subject rendered a helm.sh/chart label longer than 63 characters" >&2
    return 1
  fi
  if grep -Ev '^[[:alnum:]]([[:alnum:]_.-]{0,61}[[:alnum:]])?$' "$labels_file" >/dev/null; then
    echo "$subject rendered an invalid Kubernetes helm.sh/chart label" >&2
    return 1
  fi
  if grep -vxF "$expected" "$labels_file" >/dev/null; then
    echo "$subject rendered inconsistent helm.sh/chart labels; expected $expected" >&2
    return 1
  fi
}
