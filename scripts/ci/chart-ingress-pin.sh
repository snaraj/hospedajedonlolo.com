#!/usr/bin/env bash
# chart-ingress-pin — prove the rendered ingress NetworkPolicy admits EXACTLY
# ONE peer, named by every fact it takes to name one connector: peer namespace
# + peer app name + peer instance.
#
# Why the instance is load-bearing: the peer namespace is shared. It holds
# several per-site connectors that publish the SAME app.kubernetes.io/name and
# are separated only by app.kubernetes.io/instance. A selector on namespace and
# app name alone admits every one of them — a policy that reads narrow and
# behaves wide. The deployed policy has always carried the instance pin; this
# gate exists so no render can ship a policy weaker than that.
#
# HOW THIS GATE READS THE RENDER — the security-critical part. It does NOT
# count `- from:` lines with grep and inspect the first: that is bypassable. A
# second ingress rule with no `from` — an empty rule (`- {}`), a flow-style
# rule, or a ports-only rule — renders an allow-all while a `from`-line count
# stays at one, and reading only the first rule never sees it. Instead this
# gate extracts the WHOLE rendered `spec.ingress` sub-tree by indentation and
# asserts, structurally:
#   1. the value is a block sequence of EXACTLY ONE rule item, and
#   2. that sub-tree equals, in full, the one rule built from the values —
# so ANY extra rule, extra peer, dropped selector, or altered field, in block
# or flow style, fails the gate. The parser is stdlib Python (this repository is
# stdlib-only): no PyYAML, no yq, so it runs anywhere helm does.
#
# AND WHY THAT WAS NOT ENOUGH ON ITS OWN. Everything above reads
# ONE template through `--show-only`, and finds the spec by a raw line exactly
# equal to `spec:`. YAML allows whitespace before a key colon, allows the key
# to be quoted, resolves escapes inside a double-quoted key, and lets a
# document sit inside a List wrapper — so run ALONE that extraction exits 0 on
# four hostile charts the census refuses: a second policy in the SAME file
# spelled `kind :` / `spec :`, one in a NEW template file, one with quoted or
# escaped keys, and one inside a List. Ingress rules are ADDITIVE, so any of
# them admits a peer this gate still reports as the only one. Nothing shipped
# weaker — the sibling census in chart-egress-pin.sh refuses those renders in
# the same CI job — but this gate should not borrow its blindness coverage from
# a sibling, so assertions (d) and (e) give it census-backed extraction of its
# own: the COMPLETE render, read by scripts/ci/chart_render_census.py through a
# real document reader, with the byte-for-byte canonical text pin kept exactly
# as the assertion over what that reader returns.
#
# Five assertions, all failing closed:
#   a. the DEFAULT render — no flags, shipped values — is exactly one rule
#      pinning namespace + app name + instance, compared in full;
#   b. a blank instance and an absent instance are BOTH refused by schema
#      validation, and refused by name, so nothing can render unpinned;
#   c. a different instance moves the pin: the render is again exactly one
#      rule, now carrying the overridden instance and none of the default,
#      with app name and namespace unchanged — which is why app name alone
#      cannot tell two connectors apart;
#   d. the COMPLETE render — every template, CRDs included, no --show-only —
#      holds exactly one NetworkPolicy, and the ingress sub-tree it carries
#      equals, byte for byte, the canonical text built from chart values;
#   e. every hostile whole-render shape below is REFUSED by (d) ALONE. Each is
#      applied to the real render and fed back through (d)'s own extraction,
#      which must exit non-zero. A gate that cannot fail is not a gate.
#
# Expectations come from chart/values.yaml, the provider binding point, so the
# peer identity is stated in exactly one place and this file names no provider.
set -euo pipefail

chart_dir="${CHART_DIR:-chart}"
kube_version="${KUBE_VERSION:-v1.36.0}"
release_name=ingress-pin
release_namespace=ingress-pin-namespace
values_file="${chart_dir}/values.yaml"
script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
census_module="${script_dir}/chart_render_census.py"

# The hostile whole-render shapes assertion (e) drives, named in the census
# module's own battery. The first four are the exact shapes the raw-line
# extraction exits 0 on, and the rest are the same attack spelled other
# ways a real YAML reader resolves. Named rather than counted, because the
# point is which BLINDNESS is covered, not how many rows run.
hostile_whole_render=(
  shadow-same-file-spaced-keys
  shadow-new-file-spaced-keys
  shadow-double-quoted-keys
  shadow-single-quoted-keys
  shadow-escaped-quoted-kind
  shadow-generic-list-wrapper
  shadow-typed-list-wrapper
  shadow-nested-list-wrapper
  shadow-flow-style-document
  shadow-literal-block-scalar-kind
  shadow-folded-block-scalar-kind
  shadow-uninspectable-list-wrapper
  policy-second-ingress-rule
  policy-drop-peer-instance
)

# Stands in for any other connector sharing the peer namespace. Deliberately
# not the default.
probe_instance=another-connector-instance

fail() {
  printf 'chart-ingress-pin: %s\n' "$1" >&2
  exit 1
}

# The structural core, stdlib Python only. It carries no provider name and no
# single-quote character, so it embeds cleanly here. Modes:
#   read-values <values.yaml>                 prints ns, app, instance, port
#   assert-one-rule <ns> <app> <inst> <port>  reads a render on stdin, asserts
#   expected-ingress <ns> <app> <inst> <port> prints the canonical ingress text
py_core='
import json
import sys

def die(msg):
    sys.stderr.write("chart-ingress-pin: " + msg + "\n")
    sys.exit(1)

def indent_of(s):
    return len(s) - len(s.lstrip(" "))

def block_scalars(lines, header):
    out = {}
    inside = False
    for line in lines:
        if line.rstrip() == header + ":":
            inside = True
            continue
        if inside:
            if line.strip() == "":
                continue
            if indent_of(line) == 0:
                break
            if indent_of(line) == 2 and not line.lstrip().startswith("#"):
                k, sep, v = line.strip().partition(":")
                if not sep:
                    continue
                v = v.split(" #", 1)[0].strip().strip(chr(34) + chr(39))
                out[k.strip()] = v
    return out

def cmd_read_values(path):
    with open(path) as fh:
        lines = fh.read().split("\n")
    ing = block_scalars(lines, "ingress")
    svc = block_scalars(lines, "service")
    for key in ("peerNamespace", "peerAppName", "peerInstance"):
        if not ing.get(key):
            die("chart values declare no ingress." + key)
    if not svc.get("port"):
        die("chart values declare no service.port")
    sys.stdout.write("\n".join([ing["peerNamespace"], ing["peerAppName"],
                                ing["peerInstance"], svc["port"]]) + "\n")

def extract_ingress(text):
    lines = text.split("\n")
    spec_idx = [i for i, l in enumerate(lines) if l.rstrip() == "spec:"]
    if len(spec_idx) != 1:
        die("expected exactly one top-level spec:; found %d" % len(spec_idx))
    i = spec_idx[0] + 1
    ing_i = None
    while i < len(lines):
        l = lines[i]
        if l.strip() == "":
            i += 1
            continue
        if indent_of(l) == 0:
            break
        s = l.strip()
        if indent_of(l) == 2 and s.split(":", 1)[0] == "ingress":
            if s != "ingress:":
                die("spec.ingress rendered inline (%r); expected a block sequence" % s)
            ing_i = i
            break
        i += 1
    if ing_i is None:
        die("no spec.ingress block in the render")
    block = []
    j = ing_i + 1
    while j < len(lines):
        l = lines[j]
        if l.strip() == "":
            block.append(l)
            j += 1
            continue
        if l.rstrip() == "---":
            break
        if indent_of(l) <= 2:
            break
        block.append(l)
        j += 1
    while block and block[-1].strip() == "":
        block.pop()
    if not block:
        die("spec.ingress block is empty")
    return block

def cmd_assert(ns, app, inst, port):
    block = extract_ingress(sys.stdin.read())
    rule_items = [l for l in block if indent_of(l) == 4 and l.lstrip().startswith("-")]
    if len(rule_items) != 1:
        die("spec.ingress is a sequence of %d rules; exactly one is allowed, "
            "so a second rule cannot widen the policy unseen:\n%s"
            % (len(rule_items), "\n".join(block)))
    expected = [
        "    - from:",
        "        - namespaceSelector:",
        "            matchLabels:",
        "              kubernetes.io/metadata.name: " + ns,
        "          podSelector:",
        "            matchLabels:",
        "              app.kubernetes.io/name: " + app,
        "              app.kubernetes.io/instance: " + inst,
        "      ports:",
        "        - port: " + port,
        "          protocol: TCP",
    ]
    if block != expected:
        die("the rendered spec.ingress does not equal the one rule declared "
            "in values.\nexpected:\n%s\n\nrendered:\n%s"
            % ("\n".join(expected), "\n".join(block)))

def cmd_expected_ingress(ns, app, inst, port):
    """The one ingress rule the chart values declare, canonically serialized.

    Built HERE, from values, never read out of the render it will judge: an
    expectation derived from the render would match whatever the render said.
    The serialization is the census module none of this file imports, so both
    sides must independently agree on the same bytes.
    """
    rule = {
        "from": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
            "podSelector": {"matchLabels": {
                "app.kubernetes.io/name": app,
                "app.kubernetes.io/instance": inst,
            }},
        }],
        "ports": [{"port": int(port), "protocol": "TCP"}],
    }
    sys.stdout.write(json.dumps([rule], sort_keys=True, indent=2) + "\n")

mode = sys.argv[1]
if mode == "read-values":
    cmd_read_values(sys.argv[2])
elif mode == "assert-one-rule":
    cmd_assert(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
elif mode == "expected-ingress":
    cmd_expected_ingress(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
else:
    die("unknown mode " + mode)
'

# render prints the NetworkPolicy document alone, at the platform Kubernetes
# target. Extra arguments go straight to helm.
render() {
  helm template "${release_name}" "${chart_dir}" \
    --kube-version "${kube_version}" \
    --namespace "${release_namespace}" \
    --show-only templates/network-policy.yaml "$@"
}

# render_all prints the COMPLETE installable render instead: every template
# file, plus `crds/` — the same set `helm install` would apply. No
# --show-only, because --show-only is exactly the blindfold assertions (d) and
# (e) exist to remove.
render_all() {
  helm template "${release_name}" "${chart_dir}" \
    --kube-version "${kube_version}" \
    --namespace "${release_namespace}" \
    --include-crds
}

# The census-backed extraction: canonical text of the single policy's
# spec.ingress, read from the complete render through a real document reader.
census_ingress() {
  python3 -I -B "${census_module}" ingress-text
}

# The peer identity comes from values (the single binding point), never from
# this script.
if ! readvals="$(python3 -c "${py_core}" read-values "${values_file}")"; then
  fail "could not read the peer identity from ${values_file}"
fi
{
  IFS= read -r peer_namespace
  IFS= read -r peer_app_name
  IFS= read -r peer_instance
  IFS= read -r service_port
} <<EOF
${readvals}
EOF

[ -n "${peer_namespace}" ] || fail "chart values declare no ingress.peerNamespace"
[ -n "${peer_app_name}" ] || fail "chart values declare no ingress.peerAppName"
[ -n "${peer_instance}" ] || fail "chart values declare no ingress.peerInstance"
[ -n "${service_port}" ] || fail "chart values declare no service.port"
[ "${peer_instance}" != "${probe_instance}" ] ||
  fail "the probe instance must differ from the default, or assertion (c) proves nothing"

# (a) The default render is exactly one rule pinning the full peer identity.
render | python3 -c "${py_core}" assert-one-rule \
  "${peer_namespace}" "${peer_app_name}" "${peer_instance}" "${service_port}"
echo "chart-ingress-pin: (a) default render is exactly one rule pinning namespace + app name + instance"

# (b) A blank instance and an absent instance both fail schema validation, by
# name, so an unpinned peer selector is unrepresentable.
for blank_value in '' null; do
  if refusal="$(render --set "ingress.peerInstance=${blank_value}" 2>&1)"; then
    fail "ingress.peerInstance='${blank_value}' rendered instead of failing validation — an unpinned peer selector must be unrepresentable"
  fi
  case "${refusal}" in
    *peerInstance*) ;;
    *) fail "ingress.peerInstance='${blank_value}' was refused, but not over the instance pin: ${refusal}" ;;
  esac
done
echo "chart-ingress-pin: (b) blank and absent instance both refused by schema validation"

# (c) A different instance moves the pin and nothing else: again exactly one
# rule, now the probe instance, the default gone, app name and namespace
# unchanged. Asserting the whole rule equals the expected block with the probe
# instance substituted proves all three at once.
render --set "ingress.peerInstance=${probe_instance}" | python3 -c "${py_core}" assert-one-rule \
  "${peer_namespace}" "${peer_app_name}" "${probe_instance}" "${service_port}"
echo "chart-ingress-pin: (c) the instance discriminates peers sharing one app name"

# (d) The COMPLETE render — not one --show-only extract — holds exactly one
# NetworkPolicy, and its ingress sub-tree equals the canonical text built from
# values. Documents are recognised by their parsed, canonically spelled keys,
# so `kind :`, a quoted `"kind"`, an escaped `"\x6bind"`, a flow-style
# document, and a policy tucked inside a List wrapper are all just
# NetworkPolicies to this extraction.
[ -f "${census_module}" ] || fail "the whole-render census module is missing at ${census_module}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

if ! expected_ingress="$(python3 -c "${py_core}" expected-ingress \
    "${peer_namespace}" "${peer_app_name}" "${peer_instance}" "${service_port}")"; then
  fail "could not build the canonical ingress expectation from ${values_file}"
fi
render_all >"${work}/whole-render.yaml"
if ! rendered_ingress="$(census_ingress <"${work}/whole-render.yaml")"; then
  fail "the complete render carries no single readable NetworkPolicy to pin"
fi
if [ "${rendered_ingress}" != "${expected_ingress}" ]; then
  fail "the complete render does not carry the one ingress rule declared in values.
expected:
${expected_ingress}
rendered:
${rendered_ingress}"
fi
echo "chart-ingress-pin: (d) the complete render carries exactly the one ingress rule values declare"

# (e) Every hostile whole-render shape is refused by (d) alone. Each mutant is
# built from the REAL render, and a mutant that survives is a hole this file
# would otherwise hide behind its sibling gate.
[ "${#hostile_whole_render[@]}" -ge 12 ] ||
  fail "the hostile shape list was shrunk below its floor of 12 — shapes are added, never removed"
hostile_count=0
for mutation in "${hostile_whole_render[@]}"; do
  python3 -I -B "${census_module}" mutate \
    --chart "${chart_dir}" --release "${release_name}" \
    --namespace "${release_namespace}" --name "${mutation}" \
    <"${work}/whole-render.yaml" >"${work}/mutant.yaml"
  if mutant_ingress="$(census_ingress <"${work}/mutant.yaml" 2>/dev/null)" &&
     [ "${mutant_ingress}" = "${expected_ingress}" ]; then
    fail "the hostile whole-render shape '${mutation}' was ACCEPTED by this gate alone — the very blindness assertion (e) exists to rule out"
  fi
  hostile_count=$((hostile_count + 1))
done
echo "chart-ingress-pin: (e) ${hostile_count} hostile whole-render shapes all refused by this gate alone"

echo "chart-ingress-pin: the rendered policy admits exactly one connector"
