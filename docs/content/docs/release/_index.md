---
title: "Release"
linkTitle: "Release"
type: docs
weight: 5
description: >
  Release process, support policy, versioning, CI workflows, and container images.
---

## Support Policy

{{% alert title="Effective from v1.0" color="info" %}}
This support policy applies starting with the first stable release (v1.0.0). All pre-1.0 releases are development milestones without backward-compatibility guarantees.
{{% /alert %}}

BOMHort supports the **current stable release plus the two previous minor versions** (current − 2).

### Support Matrix (example)

| Version | Status | Security Fixes | Bug Fixes | Docs |
|---------|--------|:--------------:|:---------:|:----:|
| v1.3.x (main) | Development | ✅ | ✅ | `latest` |
| **v1.2.x** | **Current Stable** | ✅ | ✅ | `/v1.2/` |
| v1.1.x | Supported | ✅ | Critical only | `/v1.1/` |
| v1.0.x | Supported (last) | ✅ | Critical only | `/v1.0/` |
| v0.x | **End of Life** | ❌ | ❌ | `/v0.x/` (archived) |

When a new minor version is released (e.g., v1.3.0):
- The oldest supported version (v1.0.x) moves to **End of Life**
- Its docs remain accessible but display an "unsupported version" banner
- No further patches are backported

### What "supported" means

- **Security fixes**: CVEs in BOMHort's own code or critical dependency updates are backported
- **Bug fixes (current stable)**: All confirmed bugs are fixed
- **Bug fixes (older supported)**: Only critical/data-loss bugs are backported
- **Features**: Only land in `main` (next release), never backported

---

## Versioning

BOMHort follows [Semantic Versioning](https://semver.org/):

| Component | Format | Example |
|-----------|--------|---------|
| Git tag | `vMAJOR.MINOR.PATCH` | `v1.2.3` |
| Git tag (release candidate) | `vMAJOR.MINOR.PATCH-rc.N` | `v1.3.0-rc.1` |
| Container image tag | `MAJOR.MINOR.PATCH` (no `v`); `latest` for final releases only | `1.2.3`, `1.3.0-rc.1` |
| Helm chart version | Matches Git tag | `1.2.3`, `1.3.0-rc.1` |

The `.` before the RC number is required: SemVer compares `rc.10` after `rc.9`, while `rc10` would sort before `rc9`. The release workflow rejects any other tag shape.

### Version types

- **Major** (v2.0.0) — Breaking changes to API, schema, or configuration
- **Minor** (v1.3.0) — New features, backward-compatible
- **Patch** (v1.2.1) — Bug fixes, security patches, no new features

### Major Version Philosophy

BOMHort plans for **one major version bump every 2–3 years**, driven by accumulated breaking changes — not by calendar. We do not stay on 1.x forever, but we also don't bump majors for marketing reasons.

**Triggers for a major version:**
- ClickHouse schema redesign (ORDER BY changes, table splits/merges)
- API contract breaks (`/api/v2/` introduction)
- Fundamental architecture shifts (e.g., multi-tenant RBAC, new ingestion protocol)
- Helm values restructuring that breaks existing `values.yaml` files

**What a major version provides:**
- Clean slate for accumulated tech debt and design lessons
- Clear migration window for enterprise adopters (migration guide required)
- Marketing momentum for significant capability jumps

**Constraints:**
- The previous major version receives security patches for **12 months** after the new major GA
- A **migration guide** with automated tooling (schema migration scripts, Helm values converter) is mandatory before tagging any major release
- Major versions are announced **at least 3 months** in advance via the roadmap

**Projected timeline:**
- v1.0 — October 2026 (first stable)
- v2.0 — Earliest Q1/Q2 2028 (after 12–18 months of production feedback on 1.x)

---

## How to Release

### Release Branches

Every minor version has a release branch `release/vX.Y`. **All release tags — RCs, the final release and every patch — are cut from it**; the release workflow rejects a tag that is not on its release branch.

- **Branch cut**: the first `make release-rc VERSION=X.Y.0` creates `release/vX.Y` from `main` and tags `-rc.1` on it. From then on `main` is open for the next minor; nothing merged there reaches X.Y by itself.
- **Fixes land on `main` first**, then are backported as a pull request against the release branch: `make cherry-pick PR=<n> BRANCH=X.Y`. Never commit to a release branch directly. PRs are rebase-merged, so the script asks GitHub which commits on `main` belong to the PR and picks all of them; this needs the [GitHub CLI](https://cli.github.com/) (`gh`, or `GH=/path/to/gh`).
- **Only fixes are backported** — bugs, security, CVE-driven dependency bumps, doc corrections. Never features.
- Backport PRs run the full CI (CI, CodeQL and fuzz trigger on `release/**`) and are reviewed and merged like any other PR. `release/**` is branch-protected like `main`.

### Minor / Major Release

Every minor or major release goes through at least one **release candidate**. An RC runs the same pipeline as the final release — same images, signing, provenance and Helm chart — so packaging problems surface on the RC, not on the release.

```bash
# 1. Ensure main is clean and CI passes

# 2. Cut the release branch + first release candidate
make release-rc VERSION=1.3.0 DRY_RUN=1   # preview
make release-rc VERSION=1.3.0             # → release/v1.3 from main, v1.3.0-rc.1 on it

# 3. Install and test the RC (see "Installing a Release Candidate" below).
#    Problems? Fix on main, backport, cut the next RC:
make cherry-pick PR=512 BRANCH=1.3        # → PR against release/v1.3; review + merge it
make release-rc VERSION=1.3.0             # → v1.3.0-rc.2 from release/v1.3

# 4. Cut the final release — ideally from the commit that was tested
make release VERSION=1.3.0 REF=v1.3.0-rc.2

# CI automatically, for RCs and final releases alike:
#    - Builds all 6 images (multi-arch: amd64 + arm64)
#    - Signs images with cosign (keyless)
#    - Attests provenance (SLSA)
#    - Packages and pushes the Helm chart
#    - Creates the GitHub (pre-)release with SBOM + changelog since the last final release
#    Only final releases move the `latest` image tag.
```

The scripts work on the remote's branches only, never on your local checkout. `make release` warns when no RC exists for the version, or when the release branch has moved past the last RC (those commits were never tested as a candidate). `DRY_RUN=1` previews, `YES=1` skips the confirmation, `REMOTE=` / `REF=` override the remote and the commit to tag (it must be on the release branch). Scripts: [`hack/cut-release.sh`](https://github.com/seebom-labs/BOMHort/blob/main/hack/cut-release.sh), [`hack/cherry-pick.sh`](https://github.com/seebom-labs/BOMHort/blob/main/hack/cherry-pick.sh).

### Minor Release Checklist

- [ ] All planned features for this milestone merged to `main`
- [ ] CI passes on `main`
- [ ] `govulncheck ./...` (backend), `npm audit` (ui + docs) clean
- [ ] **`ROADMAP.md` reconciled**: feature PRs do not tick their own entry, so this happens **once, here**. For every issue that landed since the last tag, update all four places it appears — register row, release criteria checklist, milestone map, dependency graph — and move anything that slipped to the next milestone rather than dropping it. (Why not per PR: two PRs editing the same checklist line conflict by construction, and resolving that by picking a side silently un-ticks an already-merged issue.)
- [ ] `docs/ARCHITECTURE_PLAN.md` reflects any new services or schema changes
- [ ] Release branch cut + first RC (`make release-rc VERSION=X.Y.0`)
- [ ] RC installed and tested; fixes backported, further RCs cut as needed
- [ ] Final tag created (`make release VERSION=X.Y.0`) — from the tested RC commit
- [ ] Release notes written (features, breaking changes, upgrade notes)
- [ ] Helm chart version matches Git tag

### Patch Release

Patches are cut from the release branch, after the fixes are backported:

```bash
# 1. Fix the bug on main first (always) — PR, review, merge

# 2. Backport: opens a PR against release/v1.2 from your fork; review + merge it
make cherry-pick PR=<n> BRANCH=1.2

# 3. Tag the patch from release/v1.2
make release VERSION=1.2.4 DRY_RUN=1
make release VERSION=1.2.4

# CI builds and publishes automatically
```

Minors released before release branches existed (≤ 0.7) have no branch yet. Create it from the latest release first: `make release-branch VERSION=0.7` — then backport and release as above.

### Patch Release Checklist

- [ ] Fix merged to `main` first (never patch-only)
- [ ] Backported to `release/vX.Y` via `make cherry-pick` PR, CI green, merged
- [ ] No new features included (patches are bug/security fixes only)
- [ ] Tag follows existing sequence (v1.2.3 → v1.2.4)
- [ ] Release notes mention the fix and affected versions

---

## Documentation for Releases

Docs are versioned at the **minor** level (not per patch):

```
docs.bomhort.dev/           ← latest (main)
docs.bomhort.dev/v1.2/      ← v1.2.0, v1.2.1, v1.2.2, ... share these docs
docs.bomhort.dev/v1.1/      ← v1.1.x docs (frozen at last patch)
docs.bomhort.dev/v1.0/      ← v1.0.x docs (frozen)
```

### When releasing a new minor version:

1. `release/vX.Y` is created at the branch cut (first RC) — the docs freeze point
2. Update `docs/hugo.toml` on the release branch: add versioned `baseURL`
3. Add new version to `params.versions` on both `main` and release branch
4. Mark the oldest supported version's docs with "unsupported" banner

### Doc fixes for patches:

- Fix docs on `main` first
- Backport to the release branch (`make cherry-pick`) if the fix is relevant for that version
- Until versioned docs land (#145), the site deploys from `main` only; pushes to release branches do not publish docs

See [#145](https://github.com/seebom-labs/BOMHort/issues/145) for the full versioned docs implementation plan.

---

## Container Images

All images are published to **GitHub Container Registry (ghcr.io)**.

Images are built for **linux/amd64** and **linux/arm64**.

| Image | Purpose |
|-------|---------|
| `ghcr.io/seebom-labs/bomhort/api-gateway` | REST API server |
| `ghcr.io/seebom-labs/bomhort/parsing-worker` | SBOM processing worker |
| `ghcr.io/seebom-labs/bomhort/ingestion-watcher` | File scanner / queue enqueuer |
| `ghcr.io/seebom-labs/bomhort/cve-refresher` | Daily CVE refresh |
| `ghcr.io/seebom-labs/bomhort/mcp-server` | Read-only MCP server (`mcp.enabled`) |
| `ghcr.io/seebom-labs/bomhort/ui` | Angular frontend (Nginx) |

All images are:
- Signed with [cosign](https://github.com/sigstore/cosign) (keyless via Fulcio)
- Attested with SLSA provenance (`actions/attest-build-provenance`)

### Verifying signatures

Requires **cosign v3 or newer**:

```bash
cosign verify \
  --certificate-identity-regexp="^https://github.com/seebom-labs/BOMHort/\.github/workflows/release\.yml@refs/tags/v1\.2\.3$" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/seebom-labs/bomhort/api-gateway:1.2.3
```

{{% alert title="cosign v2 cannot see these signatures" color="warning" %}}
cosign v2 reports `no signatures found`. The release workflow uses cosign v3,
which stores the signature as an OCI referrer
(`application/vnd.dev.sigstore.bundle.v0.3+json`) instead of the older
`sha256-<digest>.sig` tag that v2 looks for. The signatures are valid — v2 just
looks in the wrong place. Upgrade cosign rather than treating this as a failed
verification.

Note also that the identity regex is **case-sensitive**: the repository is
`seebom-labs/BOMHort`, while the image names are lowercase. A lowercase pattern
fails with `no matching CertificateIdentity found`.
{{% /alert %}}

## Installing from a Release

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 1.2.3 \
  -f values-production.yaml
```

### Installing a Release Candidate

RC charts are SemVer pre-releases: Helm never selects them unless asked for that exact `--version`, so production installs cannot drift onto an RC.

```bash
# Fresh install
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 1.3.0-rc.1 \
  -f values-production.yaml

# Upgrade a test installation to the RC
helm upgrade bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 1.3.0-rc.1 \
  --reuse-values

# Into the local Kind cluster (chart + images from GHCR; run `make kind-up` first)
make kind-deploy-release VERSION=1.3.0-rc.1
```

The chart's `appVersion` is the RC version and `image.tag` defaults to it, so the RC chart deploys the RC images. If your values pin `image.tag`, unset it or set it to the RC.

### Release Candidate from a Branch

To publish an installable build of a branch that is not merged yet: **Actions → Release → Run workflow**, select the branch, enter a pre-release version (e.g. `1.3.0-rc.1`). The run builds, signs and pushes all images and the chart, then creates the tag at the built commit and a GitHub pre-release. Final versions are rejected here — those are only cut by pushing a tag.

## CI Workflows

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| CI | Push/PR to main | Go build + test + vet, Angular build, Helm lint |
| Release | Git tag `v*`, or manual (pre-releases only) | Build + push images, sign, attest, Helm chart, GitHub (pre-)release |
| Fuzz | Weekly + PRs touching `backend/` | SPDX and VEX parser fuzz tests |
| CodeQL | Push/PR | SAST for Go and TypeScript |
| Scorecard | Weekly | OpenSSF Scorecard analysis |

## Building Images Locally

```bash
make images                 # Build all 6 images with tag "dev"
make images TAG=1.3.0-rc.1  # Build with a specific tag
make images-push            # Build and push to GHCR
```
