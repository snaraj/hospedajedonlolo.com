#!/usr/bin/env bash
# chart-replica-pin — prove deploymentReady gates the Pods the chart runs.
#
# The platform enters this site's release with deploymentReady false: the
# objects render and bind before any Pod starts, and the reviewed activation
# flips it. If the gate stopped working, a pending release would start Pods
# against a chart selection nobody activated. So each case below renders the
# COMPLETE chart and requires exactly one Deployment whose replica count and
# readiness annotation match the values: false renders zero Pods whatever
# replicaCount says, and true renders exactly replicaCount.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
chart_dir="${repo_root}/chart"
kube_version="v1.36.0"

fail() {
  printf 'chart-replica-pin: FAIL %s\n' "$1" >&2
  exit 1
}

# expect <ready> <replicas> [helm --set ...]
expect() {
  local ready="$1" replicas="$2" rendered deployments counts annotations
  shift 2
  rendered="$(helm template replica-pin "${chart_dir}" --kube-version "${kube_version}" "$@")" ||
    fail "render refused for: $*"
  deployments="$(grep -c '^kind: Deployment$' <<<"${rendered}" || true)"
  [[ "${deployments}" == 1 ]] || fail "expected one Deployment, saw ${deployments} for: $*"
  counts="$(grep -E '^  replicas: ' <<<"${rendered}" | awk '{print $2}' | paste -sd, -)"
  [[ "${counts}" == "${replicas}" ]] || fail "expected replicas ${replicas}, saw '${counts}' for: ${*:-defaults}"
  annotations="$(grep -E '^    platform\.snaraj\.dev/deployment-ready: ' <<<"${rendered}" | awk '{print $2}' | tr -d '"' | paste -sd, -)"
  [[ "${annotations}" == "${ready}" ]] || fail "expected readiness annotation ${ready}, saw '${annotations}' for: ${*:-defaults}"
  printf 'chart-replica-pin: PASS deploymentReady=%s replicas=%s (%s)\n' "${ready}" "${replicas}" "${*:-defaults}"
}

expect false 0
expect false 0 --set replicaCount=1
expect true 2 --set deploymentReady=true
expect true 1 --set deploymentReady=true --set replicaCount=1
