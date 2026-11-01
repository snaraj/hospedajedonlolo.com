#!/usr/bin/env bash
# chart-media-pin — prove the media boundary renders as exactly one READ-ONLY
# volume beside the one memory scratch volume, that the process is told the
# same path the volume is mounted at, and that no incomplete or foreign media
# configuration can render at all.
#
# WHY THIS GATE EXISTS. The page's fourteen photographs and its film are too
# large for the image, so they live on an operator-provisioned claim the chart
# mounts and never creates. Media is NOT optional here: the values schema has
# no `enabled` switch, and cmd/server refuses to start without MEDIA_ROOT and
# MEDIA_MAX_CONCURRENT, then hashes every pinned file before it reports ready.
# What a render can still get wrong is everything around that: a writable
# claim, a mount the process is not told about, a second volume nobody
# reviewed, or a scratch volume that quietly grows. Each of those changes what
# a compromised process could write or read, and none of them fails a unit
# test, so this gate pins the rendered shape itself.
#
# Five assertions, all failing closed:
#
#   a. the DEFAULT render — every template, no --show-only — holds exactly one
#      Pod-bearing object, a Deployment with exactly one container and no init
#      or ephemeral container; its pod volumes are EXACTLY the memory `tmp`
#      emptyDir (16Mi) and ONE persistentVolumeClaim of the values' claim,
#      read-only at the volume level; its container mounts are EXACTLY `tmp`
#      at /tmp and that claim at the values' mountPath, read-only at the mount
#      level; MEDIA_ROOT equals that mountPath and MEDIA_MAX_CONCURRENT equals
#      the values' budget, both as plain values, and no other MEDIA_* variable
#      exists; the root filesystem is read-only; and the chart renders no
#      PersistentVolume or PersistentVolumeClaim object of its own;
#   b. every incomplete or foreign media configuration is refused by schema
#      validation, BY NAME — a blank or absent claim, a relative, dot-dot, /tmp
#      or absent mount path, a budget of 0, 257, a string or none, a foreign
#      `enabled` switch, and no media block at all;
#   c. the mount path is ONE fact: overriding it moves the mount and
#      MEDIA_ROOT together, never one of them;
#   d. the claim and the budget are one fact each: overriding them moves the
#      volume and MEDIA_MAX_CONCURRENT with them, so (a) cannot pass for a
#      template that hardcodes the shipped values;
#   e. every hostile render in the battery below is REFUSED by (a)'s own
#      assertion. A gate that cannot fail is not a gate.
#
# HOW IT READS THE RENDER. Not by grep: a value can be rendered under another
# key, and a second volume can arrive without the string a grep looks for.
# The complete render is parsed by scripts/ci/chart_render_census.py's
# document reader — the one the egress and ingress gates use, with its own
# hostile battery — so a Deployment in a new template file, a List wrapper, or
# quoted keys are read the way an API server reads them, and every object is
# required to be installable before anything is asserted about it. The volume
# and mount lists are then compared as WHOLE LISTS, which is what makes a
# second mount, writable or otherwise, impossible to add unseen.
#
# Expectations that are configuration (claim, mount path, budget) come from
# chart/values.yaml; expectations that are DOCTRINE (read-only at both levels,
# the exact tmp volume, exactly one media volume, the exact MEDIA_* inventory)
# are constants here, because a gate that reads its expectation out of the
# thing it checks passes for anything that thing renders.
set -euo pipefail

chart_dir="${CHART_DIR:-chart}"
kube_version="${KUBE_VERSION:-v1.36.0}"
release_name=media-pin
values_file="${chart_dir}/values.yaml"
script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
census_module="${script_dir}/chart_render_census.py"

# Overrides used by (c) and (d); each must differ from the shipped default.
probe_mount_path=/srv/media-pin-probe
probe_claim=media-pin-probe-claim
probe_budget=7

fail() {
  printf 'chart-media-pin: %s\n' "$1" >&2
  exit 1
}

# The structural core. Modes:
#   read-values <values.yaml>                prints claimName, mountPath, budget
#   assert <claim> <mount> <budget>          judges a complete render on stdin
#   battery <claim> <mount> <budget>         every hostile render must be refused
py_core='
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]).parent))
import chart_render_census as census  # noqa: E402

POD_KINDS = {"Pod", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob",
             "ReplicationController"}
STORAGE_KINDS = {"PersistentVolume", "PersistentVolumeClaim"}
TMP_VOLUME = {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}
TMP_MOUNT = {"name": "tmp", "mountPath": "/tmp"}


class Refused(Exception):
    pass


def die(msg):
    sys.stderr.write("chart-media-pin: " + msg + "\n")
    sys.exit(1)


def read_values(path):
    try:
        documents = census.parse_documents(Path(path).read_text(encoding="utf-8"), path)
    except census.CensusError as error:
        die("cannot read %s: %s" % (path, error))
    if len(documents) != 1 or not isinstance(documents[0], dict):
        die("%s is not one mapping" % path)
    media = documents[0].get("media")
    if not isinstance(media, dict):
        die("chart values declare no media mapping")
    claim, mount, budget = media.get("claimName"), media.get("mountPath"), media.get("maxConcurrent")
    if not isinstance(claim, str) or not claim:
        die("chart values declare no usable media.claimName")
    if not isinstance(mount, str) or not mount.startswith("/"):
        die("chart values declare no usable media.mountPath")
    if type(budget) is not int or budget < 1:
        die("chart values declare no usable integer media.maxConcurrent")
    sys.stdout.write("%s\n%s\n%d\n" % (claim, mount, budget))


def same(actual, expected):
    """Equality that refuses the bool/int conflation of Python, where 1 == True;
    an API server decoding readOnly: 1 does not read it as true."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(same(actual[k], expected[k]) for k in expected)
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(same(a, e) for a, e in zip(actual, expected))
    return actual == expected


def objects_of(text):
    try:
        objects = census.flatten(census.parse_documents(text, "<render>"))
        census.check_installable(objects)
    except census.CensusError as error:
        raise Refused(str(error))
    return objects


def judge(objects, claim, mount, budget):
    """Raise Refused unless the parsed render is exactly the media shape."""
    kinds = [o.get("kind") for o in objects]
    stored = sorted(k for k in kinds if k in STORAGE_KINDS)
    if stored:
        raise Refused("the chart renders %s objects; the media claim is operator-provisioned and "
                      "the chart must never create or bind storage of its own" % stored)
    workloads = [o for o in objects if o.get("kind") in POD_KINDS]
    if [o.get("kind") for o in workloads] != ["Deployment"]:
        raise Refused("the complete render carries Pod-bearing objects %s; exactly one Deployment "
                      "is pinned" % [o.get("kind") for o in workloads])
    try:
        pod = workloads[0]["spec"]["template"]["spec"]
    except (KeyError, TypeError):
        raise Refused("the Deployment carries no pod template spec")
    if not isinstance(pod, dict):
        raise Refused("the pod template spec is not a mapping")
    for extra in ("initContainers", "ephemeralContainers"):
        if pod.get(extra):
            raise Refused("the pod carries %s, which this gate does not pin and which could mount "
                          "the media claim writable" % extra)
    containers = pod.get("containers")
    if not isinstance(containers, list) or len(containers) != 1 or not isinstance(containers[0], dict):
        raise Refused("the pod must carry exactly one container mapping")
    container = containers[0]

    expected_volumes = [
        TMP_VOLUME,
        {"name": "media", "persistentVolumeClaim": {"claimName": claim, "readOnly": True}},
    ]
    if not same(pod.get("volumes"), expected_volumes):
        raise Refused("the pod volumes are not exactly the memory tmp volume and one read-only "
                      "media claim.\nexpected:\n%s\nrendered:\n%s"
                      % (json.dumps(expected_volumes, indent=2), json.dumps(pod.get("volumes"), indent=2)))
    expected_mounts = [TMP_MOUNT, {"name": "media", "mountPath": mount, "readOnly": True}]
    if not same(container.get("volumeMounts"), expected_mounts):
        raise Refused("the container mounts are not exactly tmp at /tmp and the media claim "
                      "read-only at the values mount path.\nexpected:\n%s\nrendered:\n%s"
                      % (json.dumps(expected_mounts, indent=2),
                         json.dumps(container.get("volumeMounts"), indent=2)))
    if "volumeDevices" in container:
        raise Refused("the container carries volumeDevices, a second path to the claim")

    env = container.get("env")
    if not isinstance(env, list) or not all(isinstance(e, dict) for e in env):
        raise Refused("the container env is not a list of mappings")
    names = [e.get("name") for e in env]
    if len(names) != len(set(names)):
        raise Refused("the env list repeats a name: %r" % names)
    media_env = [e for e in env if isinstance(e.get("name"), str) and e["name"].startswith("MEDIA")]
    expected_env = [{"name": "MEDIA_ROOT", "value": mount},
                    {"name": "MEDIA_MAX_CONCURRENT", "value": str(budget)}]
    if not same(sorted(media_env, key=lambda e: e["name"]), sorted(expected_env, key=lambda e: e["name"])):
        raise Refused("the MEDIA_* environment is %s; exactly %s is pinned, as plain values"
                      % (json.dumps(media_env), json.dumps(expected_env)))
    if container.get("envFrom"):
        raise Refused("the container carries envFrom, which can set MEDIA_* unseen")
    context = container.get("securityContext")
    if not isinstance(context, dict) or context.get("readOnlyRootFilesystem") is not True:
        raise Refused("the container root filesystem is not read-only")


def cmd_assert(claim, mount, budget):
    try:
        judge(objects_of(sys.stdin.read()), claim, mount, int(budget))
    except Refused as error:
        die(str(error))


def hostile(objects):
    """Every way a render could weaken the media boundary, applied to the real one."""
    def edit(change):
        def apply():
            mutant = copy.deepcopy(objects)
            deployment = next(o for o in mutant if o.get("kind") == "Deployment")
            change(mutant, deployment["spec"]["template"]["spec"])
            return mutant
        return apply

    def container(pod):
        return pod["containers"][0]

    def volume(pod, name):
        return next(v for v in pod["volumes"] if v["name"] == name)

    def mount_of(pod, name):
        return next(m for m in container(pod)["volumeMounts"] if m["name"] == name)

    def env_of(pod, name):
        return next(e for e in container(pod)["env"] if e["name"] == name)

    def drop_env(pod, name):
        container(pod)["env"] = [e for e in container(pod)["env"] if e["name"] != name]

    return [
        ("claim-not-read-only", edit(lambda m, p: volume(p, "media")["persistentVolumeClaim"].pop("readOnly"))),
        ("claim-read-only-false", edit(lambda m, p: volume(p, "media")["persistentVolumeClaim"].update(readOnly=False))),
        ("claim-read-only-string", edit(lambda m, p: volume(p, "media")["persistentVolumeClaim"].update(readOnly="true"))),
        ("claim-renamed", edit(lambda m, p: volume(p, "media")["persistentVolumeClaim"].update(claimName="other"))),
        ("mount-not-read-only", edit(lambda m, p: mount_of(p, "media").pop("readOnly"))),
        ("mount-read-only-false", edit(lambda m, p: mount_of(p, "media").update(readOnly=False))),
        ("mount-read-only-one", edit(lambda m, p: mount_of(p, "media").update(readOnly=1))),
        ("claim-read-only-one", edit(lambda m, p: volume(p, "media")["persistentVolumeClaim"].update(readOnly=1))),
        ("mount-moved", edit(lambda m, p: mount_of(p, "media").update(mountPath="/elsewhere"))),
        ("mount-sub-path", edit(lambda m, p: mount_of(p, "media").update(subPath="immutable"))),
        ("media-mount-dropped", edit(lambda m, p: container(p).update(
            volumeMounts=[x for x in container(p)["volumeMounts"] if x["name"] != "media"]))),
        ("media-volume-dropped", edit(lambda m, p: p.update(
            volumes=[x for x in p["volumes"] if x["name"] != "media"]))),
        ("second-media-volume", edit(lambda m, p: p["volumes"].append(
            {"name": "media-2", "persistentVolumeClaim": {"claimName": "x", "readOnly": True}}))),
        ("host-path-volume", edit(lambda m, p: p["volumes"].append(
            {"name": "host", "hostPath": {"path": "/"}}))),
        ("second-mount-of-the-claim", edit(lambda m, p: container(p)["volumeMounts"].append(
            {"name": "media", "mountPath": "/writable"}))),
        ("tmp-size-raised", edit(lambda m, p: volume(p, "tmp")["emptyDir"].update(sizeLimit="32Mi"))),
        ("tmp-on-disk", edit(lambda m, p: volume(p, "tmp")["emptyDir"].pop("medium"))),
        ("tmp-moved", edit(lambda m, p: mount_of(p, "tmp").update(mountPath="/var/tmp"))),
        ("media-root-differs", edit(lambda m, p: env_of(p, "MEDIA_ROOT").update(value="/elsewhere"))),
        ("media-root-dropped", edit(lambda m, p: drop_env(p, "MEDIA_ROOT"))),
        ("budget-dropped", edit(lambda m, p: drop_env(p, "MEDIA_MAX_CONCURRENT"))),
        ("budget-differs", edit(lambda m, p: env_of(p, "MEDIA_MAX_CONCURRENT").update(value="4096"))),
        ("budget-from-secret", edit(lambda m, p: env_of(p, "MEDIA_MAX_CONCURRENT").update(
            valueFrom={"secretKeyRef": {"name": "s", "key": "k"}}))),
        ("extra-media-variable", edit(lambda m, p: container(p)["env"].append(
            {"name": "MEDIA_ENABLED", "value": "false"}))),
        ("repeated-variable", edit(lambda m, p: container(p)["env"].append(
            {"name": "MEDIA_ROOT", "value": "/elsewhere"}))),
        ("env-from", edit(lambda m, p: container(p).update(envFrom=[{"configMapRef": {"name": "c"}}]))),
        ("writable-root-filesystem", edit(lambda m, p: container(p)["securityContext"].update(
            readOnlyRootFilesystem=False))),
        ("init-container", edit(lambda m, p: p.update(initContainers=[
            {"name": "i", "image": "x", "volumeMounts": [{"name": "media", "mountPath": "/m"}]}]))),
        ("second-container", edit(lambda m, p: p["containers"].append(
            {"name": "sidecar", "image": "x", "volumeMounts": [{"name": "media", "mountPath": "/m"}]}))),
        ("second-deployment", edit(lambda m, p: m.append(copy.deepcopy(
            next(o for o in m if o.get("kind") == "Deployment"))))),
        ("a-stateful-set", edit(lambda m, p: m.append({"apiVersion": "apps/v1", "kind": "StatefulSet",
                                                       "metadata": {"name": "s"}}))),
        ("chart-created-claim", edit(lambda m, p: m.append({
            "apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "c"}}))),
    ]


def cmd_battery(claim, mount, budget):
    objects = objects_of(sys.stdin.read())
    judge(objects, claim, mount, int(budget))
    survived = []
    for name, build in hostile(objects):
        try:
            judge(build(), claim, mount, int(budget))
        except Refused:
            continue
        survived.append(name)
    if survived:
        die("hostile renders ACCEPTED by assertion (a): %s" % ", ".join(survived))
    sys.stdout.write("%d\n" % len(hostile(objects)))


mode = sys.argv[2]
if mode == "read-values":
    read_values(sys.argv[3])
elif mode == "assert":
    cmd_assert(*sys.argv[3:6])
elif mode == "battery":
    try:
        cmd_battery(*sys.argv[3:6])
    except Refused as error:
        die(str(error))
else:
    die("unknown mode " + mode)
'

core() {
  python3 -I -B -c "${py_core}" "${census_module}" "$@"
}

# render prints the COMPLETE chart: every template, never one --show-only
# extract, because a second workload in a new file is exactly what an extract
# cannot see.
render() {
  helm template "${release_name}" "${chart_dir}" --kube-version "${kube_version}" "$@"
}

if ! readvals="$(core read-values "${values_file}")"; then
  fail "could not read the media values from ${values_file}"
fi
{
  IFS= read -r default_claim
  IFS= read -r default_mount_path
  IFS= read -r default_budget
} <<EOF
${readvals}
EOF

[ "${default_mount_path}" != "${probe_mount_path}" ] ||
  fail "the probe mount path must differ from the default, or assertion (c) proves nothing"
[ "${probe_claim}" != "${default_claim}" ] ||
  fail "the probe claim must differ from the default, or assertion (d) proves nothing"
[ "${probe_budget}" != "${default_budget}" ] ||
  fail "the probe budget must differ from the default, or assertion (d) proves nothing"

work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT

# --- (a) the default render is the read-only media boundary -----------------
render >"${work}/default.yaml" || fail "the default chart does not render"
core assert "${default_claim}" "${default_mount_path}" "${default_budget}" <"${work}/default.yaml"
echo "chart-media-pin: (a) the complete render carries one Deployment whose only volumes are the 16Mi memory tmp and the claim ${default_claim}, read-only on the claim AND the mount at ${default_mount_path}, with MEDIA_ROOT equal to it and MEDIA_MAX_CONCURRENT=${default_budget}"

# --- (b) every incomplete or foreign configuration is refused, by name ------
refuse() {
  description="$1"
  expect_name="$2"
  shift 2
  if refusal="$(render "$@" 2>&1)"; then
    fail "${description} rendered instead of failing validation"
  fi
  case "${refusal}" in
    *"${expect_name}"*) ;;
    *) fail "${description} was refused, but not over ${expect_name}: ${refusal}" ;;
  esac
}

refuse "a blank claim name" claimName --set "media.claimName="
refuse "an absent claim name" claimName --set "media.claimName=null"
refuse "a relative mount path" mountPath --set "media.mountPath=data/media"
refuse "a dot-dot mount path" mountPath --set "media.mountPath=/data/../etc"
refuse "the scratch directory as the mount path" mountPath --set "media.mountPath=/tmp"
refuse "an absent mount path" mountPath --set "media.mountPath=null"
refuse "a zero transfer budget" maxConcurrent --set "media.maxConcurrent=0"
refuse "a transfer budget above the server's ceiling" maxConcurrent --set "media.maxConcurrent=257"
refuse "a string transfer budget" maxConcurrent --set-string "media.maxConcurrent=32"
refuse "an absent transfer budget" maxConcurrent --set "media.maxConcurrent=null"
refuse "a foreign enabled switch" enabled --set "media.enabled=false"
refuse "no media block at all" media --set "media=null"
echo "chart-media-pin: (b) a blank or absent claim, a relative, dot-dot, /tmp or absent mount path, a budget of 0, 257, a string or none, a foreign switch, and no media block are each refused by name"

# --- (c) the mount path is ONE fact ------------------------------------------
render --set "media.mountPath=${probe_mount_path}" |
  core assert "${default_claim}" "${probe_mount_path}" "${default_budget}"
echo "chart-media-pin: (c) overriding the mount path moves the mount and MEDIA_ROOT together"

# --- (d) the claim and the budget are one fact each --------------------------
render --set "media.claimName=${probe_claim}" --set "media.maxConcurrent=${probe_budget}" |
  core assert "${probe_claim}" "${default_mount_path}" "${probe_budget}"
echo "chart-media-pin: (d) overriding the claim and the budget moves the volume and MEDIA_MAX_CONCURRENT with them"

# --- (e) the assertion can fail ------------------------------------------------
if ! battery="$(core battery "${default_claim}" "${default_mount_path}" "${default_budget}" <"${work}/default.yaml")"; then
  fail "the hostile battery did not run clean"
fi
echo "chart-media-pin: (e) ${battery} hostile renders all refused by assertion (a)"

echo "chart-media-pin: media renders as exactly one read-only claim the process is told about, beside one 16Mi memory scratch volume, and nothing incomplete or foreign renders"
