#!/usr/bin/env bash
# stage-media.sh <source-dir> <volume-root>
#
# Copy the page's pinned photographs and film from <source-dir> onto a media
# volume laid out the way the server reads it:
#
#     <volume-root>/immutable/<sha256>/<name>
#
# site/media.go is the single source of truth: every row of its `Media` table
# names one file by name, size and SHA-256, and this script stages exactly
# those rows and nothing else. The server hashes every pinned byte at startup
# and refuses to report ready on any mismatch; this script refuses earlier, on
# the operator's machine, so a wrong file never reaches the volume at all.
#
# Each file is a REAL copy, never a link: the server refuses a symlinked or
# hard-linked media file. It is written to a temporary name in its final
# directory, verified, made read-only for everyone (0444, directories 0755, so
# the non-root container user can read a read-only mount), and then renamed
# into place, so a reader never sees a partial file. Re-running is safe: a
# destination already holding the pinned bytes is left as it is, and one
# holding anything else is refused rather than overwritten.
#
# Usage, local preview:
#     scripts/stage-media.sh ~/media-export /tmp/hospedajedonlolo-media
#     MEDIA_ROOT=/tmp/hospedajedonlolo-media MEDIA_MAX_CONCURRENT=8 \
#       go run ./cmd/server
set -euo pipefail

fail() {
  printf 'stage-media: %s\n' "$1" >&2
  exit 1
}

[ "$#" -eq 2 ] || fail "usage: scripts/stage-media.sh <source-dir> <volume-root>"
# A leading "./" keeps a path that starts with "-" from reading as an option
# to the tools below (BSD chmod takes no "--").
case "$1" in -*) source_dir="./$1" ;; *) source_dir="$1" ;; esac
case "$2" in -*) volume_root="./$2" ;; *) volume_root="$2" ;; esac
[ -d "${source_dir}" ] || fail "source directory ${source_dir} does not exist"

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
table="${repo_root}/site/media.go"
[ -f "${table}" ] || fail "cannot find the pinned media table at site/media.go"

if command -v sha256sum >/dev/null 2>&1; then
  digest_of() { sha256sum -- "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  digest_of() { shasum -a 256 -- "$1" | awk '{print $1}'; }
else
  fail "neither sha256sum nor shasum is installed"
fi

size_of() { wc -c <"$1" | tr -d '[:space:]'; }

# GNU stat first (Linux), then BSD stat (macOS).
links_of() { stat -c %h -- "$1" 2>/dev/null || stat -f %l -- "$1"; }

# --- read the pinned table ----------------------------------------------------
# Every line between `var Media = []Object{` and its closing `}` must be one
# row in exactly the shape below; anything else is refused rather than
# skipped, so a table this script cannot read never stages a partial set.
row_shape='^	\{Name: "([a-z0-9][a-z0-9-]*\.(webp|mp4))", SHA256: "([0-9a-f]{64})", Size: ([1-9][0-9]*), ContentType: "(image/webp|video/mp4)"\},$'
names=()
digests=()
sizes=()
inside=0
closed=0
while IFS= read -r line || [ -n "${line}" ]; do
  if [ "${inside}" -eq 0 ]; then
    [ "${line}" = 'var Media = []Object{' ] && inside=1
    continue
  fi
  if [ "${line}" = '}' ]; then
    closed=1
    break
  fi
  [[ "${line}" =~ ${row_shape} ]] ||
    fail "site/media.go carries a row this script cannot read: ${line}"
  names+=("${BASH_REMATCH[1]}")
  digests+=("${BASH_REMATCH[3]}")
  sizes+=("${BASH_REMATCH[4]}")
done <"${table}"
[ "${inside}" -eq 1 ] || fail "site/media.go declares no \`var Media = []Object{\` table"
[ "${closed}" -eq 1 ] || fail "site/media.go never closes its Media table"
[ "${#names[@]}" -gt 0 ] || fail "site/media.go pins no media file"
if [ "$(printf '%s\n' "${names[@]}" | sort | uniq -d)" != "" ]; then
  fail "site/media.go pins one name twice"
fi
if [ "$(printf '%s\n' "${digests[@]}" | sort | uniq -d)" != "" ]; then
  fail "site/media.go pins one digest twice"
fi

# --- verify every source before writing anything ------------------------------
for i in "${!names[@]}"; do
  name="${names[i]}"
  source="${source_dir}/${name}"
  [ ! -L "${source}" ] || fail "${name}: the source is a symbolic link; stage from the real file"
  [ -f "${source}" ] || fail "${name}: missing from ${source_dir}, or not a regular file"
  got_size="$(size_of "${source}")"
  [ "${got_size}" = "${sizes[i]}" ] ||
    fail "${name}: the source is ${got_size} bytes, the table pins ${sizes[i]}"
  got_digest="$(digest_of "${source}")"
  [ "${got_digest}" = "${digests[i]}" ] ||
    fail "${name}: the source digest is ${got_digest}, the table pins ${digests[i]}"
done

# --- stage --------------------------------------------------------------------
make_dir() {
  [ ! -L "$1" ] || fail "$1 is a symbolic link; the volume layout must be real directories"
  mkdir -p -- "$1"
  chmod 0755 "$1"
}

make_dir "${volume_root}"
make_dir "${volume_root}/immutable"
staged=0
present=0
tmp=""
trap 'if [ -n "${tmp}" ]; then rm -f -- "${tmp}"; fi' EXIT
for i in "${!names[@]}"; do
  name="${names[i]}"
  digest="${digests[i]}"
  directory="${volume_root}/immutable/${digest}"
  target="${directory}/${name}"
  make_dir "${directory}"
  if [ -e "${target}" ] || [ -L "${target}" ]; then
    [ ! -L "${target}" ] && [ -f "${target}" ] ||
      fail "${name}: ${target} exists and is not a regular file; refusing to replace it"
    [ "$(digest_of "${target}")" = "${digest}" ] ||
      fail "${name}: ${target} exists with different bytes; refusing to overwrite it"
    [ "$(links_of "${target}")" = 1 ] ||
      fail "${name}: ${target} is hard-linked; the server refuses it, so replace it with a real copy"
    present=$((present + 1))
    printf 'stage-media: present  %s  %s\n' "${digest}" "${name}"
    continue
  fi
  tmp="$(mktemp "${directory}/.${name}.XXXXXX")"
  cp -- "${source_dir}/${name}" "${tmp}"
  chmod 0444 "${tmp}"
  [ "$(digest_of "${tmp}")" = "${digest}" ] ||
    fail "${name}: the copy does not match the pinned digest"
  mv -f -- "${tmp}" "${target}"
  tmp=""
  [ "$(links_of "${target}")" = 1 ] || fail "${name}: the staged copy is hard-linked"
  staged=$((staged + 1))
  printf 'stage-media: staged   %s  %s\n' "${digest}" "${name}"
done

printf 'stage-media: %d pinned files verified at %s/immutable (%d staged, %d already present)\n' \
  "${#names[@]}" "${volume_root}" "${staged}" "${present}"
