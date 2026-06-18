#!/usr/bin/env bash
# Verify the last N minor releases (and their patch releases) for one or more
# Tekton repositories: extract the Rekor UUID from the release page, resolve the
# transparency-log entry, verify the cosign attestation, and confirm every
# attested image+digest is present in that release's release.yaml.
#
# Output: docs/results.json
set -uo pipefail

# Repos to evaluate. Override with REPOS env (space-separated owner/name list).
# Defaults to the core Tekton components.
REPOS="${REPOS:-tektoncd/pipeline tektoncd/results tektoncd/chains tektoncd/operator openshift-pipelines/pipelines-as-code tektoncd/triggers}"
# How many most-recent minor lines to keep per repo (plus all patches on them).
MINORS="${MINORS:-5}"
# Tekton release images are signed by Tekton Chains with this fixed public key.
TEKTON_PUBKEY="${TEKTON_PUBKEY:-https://raw.githubusercontent.com/tektoncd/chains/main/tekton.pub}"
# How many attested images to cosign-verify per release (0 disables). Registry
# round-trips are slow, so we sample rather than verify every subject.
VERIFY_IMAGES="${VERIFY_IMAGES:-3}"
GH_API="https://api.github.com"
AUTH=()
[ -n "${GITHUB_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
OUT="docs/results.json"
mkdir -p docs

# ---- helpers ---------------------------------------------------------------

# json_escape: stdin -> JSON string body (no surrounding quotes)
json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'; }

# semver_minor: vX.Y.Z -> X.Y
semver_minor() { echo "$1" | sed -E 's/^v?([0-9]+)\.([0-9]+)\.[0-9]+.*/\1.\2/'; }

# fetch all releases (paginated) for a repo, emit "tag\tbody_url" lines.
fetch_releases() {
  local repo="$1" page=1
  while :; do
    local resp
    resp=$(curl -fsSL "${AUTH[@]}" \
      "${GH_API}/repos/${repo}/releases?per_page=100&page=${page}") || break
    local count
    count=$(echo "$resp" | jq 'length')
    [ "$count" -eq 0 ] && break
    echo "$resp" | jq -r '.[] | select(.draft==false and .prerelease==false)
      | [.tag_name, (.body // "")] | @base64'
    [ "$count" -lt 100 ] && break
    page=$((page+1))
  done
}

# extract first REKOR_UUID=... token from a release body
extract_uuid() {
  grep -oiE 'REKOR_UUID[=: ]+[a-f0-9]{80,}' <<<"$1" | head -1 \
    | grep -oiE '[a-f0-9]{80,}' | head -1
}

# extract RELEASE_FILE=... url from a release body
extract_release_file() {
  grep -oiE 'RELEASE_FILE[=: ]+[^[:space:]"]+' <<<"$1" | head -1 \
    | sed -E 's/^RELEASE_FILE[=: ]+//I'
}

# ---- per-release verification ---------------------------------------------

verify_release() {
  local repo="$1" tag="$2" body="$3"
  local uuid rfile status="pass" reason="" attested=0 matched=0

  uuid=$(extract_uuid "$body")
  rfile=$(extract_release_file "$body")

  if [ -z "$uuid" ]; then
    emit "$repo" "$tag" "" "$rfile" "no_uuid" "No REKOR_UUID found on release page" 0 0 0 0
    return
  fi

  # 1) Resolve the Rekor entry + pull the attestation.
  local att="$WORK/att.json"
  if ! rekor-cli get --uuid "$uuid" --format json 2>"$WORK/rekor.err" \
        | jq -r '.Attestation' > "$att" 2>/dev/null || [ ! -s "$att" ]; then
    emit "$repo" "$tag" "$uuid" "$rfile" "fail" \
      "Rekor entry did not resolve: $(json_escape <"$WORK/rekor.err")" 0 0 0 0
    return
  fi

  # 2) Confirm the attestation parses and carries subjects.
  if ! jq -e '.subject and (.subject|length>0)' "$att" >/dev/null 2>&1; then
    emit "$repo" "$tag" "$uuid" "$rfile" "fail" \
      "Attestation has no subjects" 0 0 0 0
    return
  fi

  # 3) Strict provenance: verify predicateType is SLSA provenance.
  local ptype
  ptype=$(jq -r '.predicateType // empty' "$att")
  case "$ptype" in
    *slsa.dev/provenance*|*in-toto*) : ;;
    "") reason="missing predicateType; "; status="warn" ;;
    *) reason="unexpected predicateType ${ptype}; "; status="warn" ;;
  esac

  # 4) Cross-check: every attested image:digest must appear in release.yaml.
  if [ -n "$rfile" ] && curl -fsSL "$rfile" -o "$WORK/release.yaml" 2>/dev/null; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      attested=$((attested+1))
      grep -q "${line#*@}" "$WORK/release.yaml" && matched=$((matched+1))
    done < <(jq -r ".subject[] | .name + \":${tag}@sha256:\" + .digest.sha256" "$att")

    if [ "$attested" -ne "$matched" ]; then
      status="fail"
      reason="${reason}only ${matched}/${attested} attested images matched release.yaml; "
    fi
  else
    reason="${reason}release.yaml not fetched, image cross-check skipped; "
    [ "$status" = "pass" ] && status="warn"
  fi

  # 5) Cryptographic signature check with cosign.
  #
  # Tekton release images are signed by Tekton Chains with a FIXED public key
  # (not keyless/Fulcio), and the cosign signature type is "Tekton container
  # signature". So we verify with --key against tekton.pub, NOT with
  # --certificate-identity / --certificate-oidc-issuer.
  #
  # We verify each attested image by digest. VERIFY_IMAGES caps how many per
  # release we check (registry round-trips are slow); 0 disables the step.
  local signed=0 sig_checked=0
  if [ "${VERIFY_IMAGES:-3}" -gt 0 ] && command -v cosign >/dev/null 2>&1; then
    local cap="${VERIFY_IMAGES:-3}" cosign_fail=0
    while IFS= read -r ref; do
      [ -z "$ref" ] && continue
      [ "$sig_checked" -ge "$cap" ] && break
      sig_checked=$((sig_checked+1))
      if cosign verify-attestation \
            --key "$TEKTON_PUBKEY" \
            --type slsaprovenance \
            --insecure-ignore-tlog=false \
            "$ref" >/dev/null 2>"$WORK/cosign.err"; then
        signed=$((signed+1))
      else
        cosign_fail=$((cosign_fail+1))
      fi
    done < <(jq -r '.subject[] | .name + "@sha256:" + .digest.sha256' "$att")

    if [ "$cosign_fail" -gt 0 ]; then
      status="fail"
      reason="${reason}cosign verify-attestation failed for ${cosign_fail}/${sig_checked} image(s): $(json_escape <"$WORK/cosign.err" | head -c 240); "
    fi
  else
    reason="${reason}cosign signature check skipped; "
    [ "$status" = "pass" ] && status="warn"
  fi

  emit "$repo" "$tag" "$uuid" "$rfile" "$status" "$reason" "$attested" "$matched" "$signed" "$sig_checked"
}

emit() {
  python3 - "$@" <<'PY' >> "$WORK/records.jsonl"
import json, sys
repo, tag, uuid, rfile, status, reason, attested, matched, signed, checked = sys.argv[1:11]
print(json.dumps({
  "repo": repo, "tag": tag, "rekor_uuid": uuid, "release_file": rfile,
  "status": status, "reason": reason.strip(", ").strip("; "),
  "images_attested": int(attested), "images_matched": int(matched),
  "images_signed": int(signed), "images_sig_checked": int(checked),
}))
PY
}

# ---- main ------------------------------------------------------------------

: > "$WORK/records.jsonl"
for repo in $REPOS; do
  echo "::group::$repo" >&2
  mapfile -t entries < <(fetch_releases "$repo")
  declare -A seen_minor=()
  ordered_minors=()
  for e in "${entries[@]}"; do
    tag=$(echo "$e" | base64 -d | jq -r '.[0]')
    m=$(semver_minor "$tag")
    if [ -z "${seen_minor[$m]:-}" ]; then
      seen_minor[$m]=1
      ordered_minors+=("$m")
    fi
  done
  keep=("${ordered_minors[@]:0:$MINORS}")
  printf 'keeping minors: %s\n' "${keep[*]}" >&2

  for e in "${entries[@]}"; do
    decoded=$(echo "$e" | base64 -d)
    tag=$(echo "$decoded" | jq -r '.[0]')
    body=$(echo "$decoded" | jq -r '.[1]')
    m=$(semver_minor "$tag")
    for k in "${keep[@]}"; do
      if [ "$k" = "$m" ]; then
        echo "  verifying $tag" >&2
        verify_release "$repo" "$tag" "$body"
        break
      fi
    done
  done
  unset seen_minor
  echo "::endgroup::" >&2
done

# Assemble final JSON.
python3 - "$WORK/records.jsonl" > "$OUT" <<'PY'
import json, sys, datetime, collections
records = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
by_repo = collections.OrderedDict()
for r in records:
    by_repo.setdefault(r["repo"], []).append(r)
summary = collections.Counter(r["status"] for r in records)
print(json.dumps({
  "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
  "summary": dict(summary),
  "total": len(records),
  "repos": by_repo,
}, indent=2))
PY

echo "Wrote $OUT ($(jq '.total' "$OUT") releases)" >&2
# Non-zero exit if any hard failure, so the Action surfaces it.
fails=$(jq '.summary.fail // 0' "$OUT")
[ "$fails" -gt 0 ] && exit 1 || exit 0
