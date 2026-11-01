#!/usr/bin/env bash
# chart-replica-pin — prove deploymentReady gates the Pods the chart runs.
#
# The platform enters this site's release with deploymentReady false: the
# objects render and bind before any Pod starts, and the reviewed activation
# flips it. If the gate stopped working, a pending release would start Pods
# against a chart selection nobody activated.
#
# The answer is read STRUCTURALLY. The complete render is parsed with the
# repository's render parser, exactly one workload must exist and it must be
# a Deployment, and the integer at spec.replicas and the readiness annotation
# are read from that same object. Kubernetes drives desired state from spec
# and ignores status on create, so a rendered status block is refused rather
# than consulted. A text match over "replicas:" lines would accept a status
# block or a quoted key standing in for the real count.
#
# Three layers: the real chart in four value cases; a battery of hostile
# edits to the parsed default render, each of which must be refused; and the
# template-level bypass found in review (spec count unconditional, the
# conditional moved under status, the spec key quoted) rendered from a
# scratch copy of the chart, which must also be refused.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
chart_dir="${repo_root}/chart"
census_module="${script_dir}/chart_render_census.py"
kube_version="v1.36.0"

fail() {
  printf 'chart-replica-pin: FAIL %s\n' "$1" >&2
  exit 1
}

py_core='
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]).parent))
import chart_render_census as census  # noqa: E402

ANNOTATION = "platform.snaraj.dev/deployment-ready"
WORKLOAD_KINDS = {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}


class Refused(Exception):
    pass


def objects_of(text):
    try:
        objects = census.flatten(census.parse_documents(text, "<render>"))
        census.check_installable(objects)
    except census.CensusError as error:
        raise Refused(str(error))
    return objects


def judge(objects, ready, replicas):
    workloads = [o for o in objects if o.get("kind") in WORKLOAD_KINDS]
    if [o.get("kind") for o in workloads] != ["Deployment"]:
        raise Refused("expected exactly one workload, a Deployment; saw %s" % [o.get("kind") for o in workloads])
    deployment = workloads[0]
    if "status" in deployment:
        raise Refused("the rendered Deployment carries status, which Kubernetes ignores on create")
    spec = deployment.get("spec")
    count = spec.get("replicas") if isinstance(spec, dict) else None
    if type(count) is not int or count != replicas:
        raise Refused("spec.replicas is %r, expected %d" % (count, replicas))
    metadata = deployment.get("metadata") if isinstance(deployment.get("metadata"), dict) else {}
    annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
    want = "true" if ready else "false"
    if annotations.get(ANNOTATION) != want:
        raise Refused("readiness annotation is %r, expected %r" % (annotations.get(ANNOTATION), want))


def hostile(objects):
    def edit(change):
        def build():
            mutated = copy.deepcopy(objects)
            change(next(o for o in mutated if o.get("kind") == "Deployment"), mutated)
            return mutated
        return build

    return [
        ("status-carries-the-zero", edit(lambda d, m: (d["spec"].__setitem__("replicas", 2),
                                                       d.__setitem__("status", {"replicas": 0})))),
        ("status-beside-a-correct-spec", edit(lambda d, m: d.__setitem__("status", {"replicas": 0}))),
        ("spec-count-as-string", edit(lambda d, m: d["spec"].__setitem__("replicas", "0"))),
        ("spec-count-missing", edit(lambda d, m: d["spec"].pop("replicas"))),
        ("annotation-claims-ready", edit(lambda d, m: d["metadata"]["annotations"].__setitem__(ANNOTATION, "true"))),
        ("second-deployment", edit(lambda d, m: m.append(copy.deepcopy(d)))),
        ("a-stateful-set-beside-it", edit(lambda d, m: m.append({"apiVersion": "apps/v1", "kind": "StatefulSet",
                                                                 "metadata": {"name": "s"}, "spec": {"replicas": 2}}))),
    ]


mode = sys.argv[2]
text = sys.stdin.read()
try:
    if mode == "assert":
        judge(objects_of(text), sys.argv[3] == "true", int(sys.argv[4]))
    elif mode == "battery":
        objects = objects_of(text)
        judge(objects, False, 0)
        survived = []
        for name, build in hostile(objects):
            try:
                judge(build(), False, 0)
            except Refused:
                continue
            survived.append(name)
        if survived:
            raise Refused("hostile renders ACCEPTED: %s" % ", ".join(survived))
        sys.stdout.write("%d\n" % len(hostile(objects)))
    elif mode == "refuse":
        try:
            judge(objects_of(text), False, 0)
        except Refused as error:
            sys.stdout.write(str(error) + "\n")
            sys.exit(0)
        raise Refused("the review bypass render was ACCEPTED")
    else:
        raise Refused("unknown mode " + mode)
except Refused as error:
    sys.stderr.write(str(error) + "\n")
    sys.exit(1)
'

core() {
  python3 -I -B -c "${py_core}" "${census_module}" "$@"
}

render() {
  local dir="$1"
  shift
  helm template replica-pin "${dir}" --kube-version "${kube_version}" "$@"
}

# expect <ready> <replicas> [helm --set ...]
expect() {
  local ready="$1" replicas="$2"
  shift 2
  render "${chart_dir}" "$@" | core assert "${ready}" "${replicas}" ||
    fail "deploymentReady=${ready} must render spec.replicas ${replicas} (${*:-defaults})"
  printf 'chart-replica-pin: PASS deploymentReady=%s spec.replicas=%s (%s)\n' "${ready}" "${replicas}" "${*:-defaults}"
}

expect false 0
expect false 0 --set replicaCount=1
expect true 2 --set deploymentReady=true
expect true 1 --set deploymentReady=true --set replicaCount=1

refused="$(render "${chart_dir}" | core battery)" || fail "the hostile battery did not hold"
printf 'chart-replica-pin: PASS %s hostile edits of the parsed default render refused\n' "${refused}"

# The review bypass, rendered for real from a scratch copy of the chart.
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
cp -R "${chart_dir}" "${scratch}/chart"
python3 -I -B - "${scratch}/chart/templates/deployment.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
gate = "  replicas: {{ if .Values.deploymentReady }}{{ .Values.replicaCount }}{{ else }}0{{ end }}\n"
if text.count(gate) != 1:
    sys.exit("the replica conditional moved; update this regression with it")
text = text.replace(gate, '  "replicas": {{ .Values.replicaCount }}\n')
text = text.rstrip("\n") + "\nstatus:\n  replicas: {{ if .Values.deploymentReady }}{{ .Values.replicaCount }}{{ else }}0{{ end }}\n"
open(path, "w", encoding="utf-8").write(text)
PY
reason="$(render "${scratch}/chart" | core refuse)" || fail "the review bypass render was accepted"
printf 'chart-replica-pin: PASS the review bypass (quoted spec key, conditional under status) is refused: %s\n' "${reason}"
