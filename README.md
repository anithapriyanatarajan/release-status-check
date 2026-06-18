# Tekton Attestation Ledger

A GitHub Pages site, fed by a scheduled GitHub Action, that re-verifies the supply-chain
provenance of recent Tekton releases.

For each repo it takes the **last 5 minor lines** plus **every patch release** on those lines,
and for each release it:

1. Parses the `REKOR_UUID` and `RELEASE_FILE` out of the release page body.
2. Resolves the entry in the Rekor transparency log (`rekor-cli get --uuid …`).
3. Pulls the attestation and confirms it parses and carries subjects.
4. Checks the predicate type is SLSA / in-toto provenance.
5. Confirms **every attested image digest** appears in that release's `release.yaml`.
6. Runs **`cosign verify-attestation`** on a sample of the attested images to check the
   cryptographic signature and Rekor inclusion.

### A note on the signing key

Tekton's official release images (`gcr.io/tekton-releases/...`) are **not** keyless / Fulcio
signed. They are signed by Tekton Chains with a fixed public key, so verification uses
`--key` rather than `--certificate-identity` / `--certificate-oidc-issuer`:

```
cosign verify-attestation \
  --key https://raw.githubusercontent.com/tektoncd/chains/main/tekton.pub \
  --type slsaprovenance \
  gcr.io/tekton-releases/...@sha256:<digest>
```

Override `TEKTON_PUBKEY` if a project signs with a different key.

Results are written to `docs/results.json` and rendered by `docs/index.html`.

## Status meanings

| Verdict   | Meaning |
|-----------|---------|
| `verified`| UUID resolved, attestation valid, all attested digests present in release.yaml |
| `check`   | Resolved but something was soft-off (e.g. release.yaml unreachable, unexpected predicate type) |
| `failed`  | Rekor entry didn't resolve, no subjects, or attested digests missing from release.yaml |
| `no uuid` | No `REKOR_UUID` on the release page |

## Setup

1. Create a repo, drop these files in, push to `main`.
2. **Settings → Pages → Source: GitHub Actions.**
3. The workflow runs weekly and on demand (**Actions → Verify Tekton Release Attestations → Run workflow**).

### Optional configuration (repo Variables)

- `REPOS` — space-separated `owner/name` list. Default (core Tekton components):
  `tektoncd/pipeline tektoncd/results tektoncd/chains tektoncd/operator openshift-pipelines/pipelines-as-code tektoncd/triggers`
- `MINORS` — how many minor lines to keep per repo (plus all patches on them). Default `5`.
- `VERIFY_IMAGES` — how many attested images to `cosign verify-attestation` per release.
  Default `3`; set `0` to skip the signature check (Rekor + digest cross-check still run).
- `TEKTON_PUBKEY` — signing key URL. Default the Tekton Chains `tekton.pub`.

## Run locally

```bash
# needs: rekor-cli, cosign, jq, python3, bash
REPOS="tektoncd/pipeline" MINORS=3 bash scripts/verify.sh
python3 -m http.server -d docs   # then open http://localhost:8000
```

The script exits non-zero if any release lands in `failed`, so the Action surfaces real
regressions while still publishing the page.
