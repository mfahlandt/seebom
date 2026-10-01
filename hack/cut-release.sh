#!/usr/bin/env bash
# Cut a BOMHort release candidate or final release by tagging the canonical
# repository. The tag push triggers .github/workflows/release.yml, which builds
# and publishes the images, the Helm chart and the GitHub (pre-)release.
#
# Usage:
#   hack/cut-release.sh rc    X.Y.Z   # next release candidate: vX.Y.Z-rc.N
#   hack/cut-release.sh final X.Y.Z   # final release:          vX.Y.Z
#
# Make targets: make release-rc VERSION=X.Y.Z / make release VERSION=X.Y.Z
#
# Environment:
#   REMOTE   git remote of the canonical repo (default: the remote pointing at
#            seebom-labs/*, otherwise origin)
#   REF      commit-ish to tag (default: <REMOTE>/main for X.Y.0,
#            <REMOTE>/release/vX.Y for patch releases)
#   DRY_RUN  1 = print what would happen, create and push nothing
#   YES      1 = do not ask for confirmation
#
# The tag is created on the remote's branch, never on your local checkout, so
# unpushed local commits cannot end up in a release by accident.
set -euo pipefail

die()  { echo "❌ $*" >&2; exit 1; }
info() { echo "▸ $*"; }

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
  exit "${1:-0}"
}

[[ $# -eq 2 ]] || usage 1
KIND="$1"
VERSION="${2#v}"

[[ "$KIND" == "rc" || "$KIND" == "final" ]] || die "first argument must be 'rc' or 'final', got '$KIND'"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
  || die "VERSION must be X.Y.Z (without -rc suffix), got '$VERSION'"
MINOR="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
PATCH="${BASH_REMATCH[3]}"

# ─── Remote ──────────────────────────────────────────────────────────────────
if [[ -z "${REMOTE:-}" ]]; then
  REMOTE=$(git remote -v | awk 'tolower($2) ~ /github\.com[:\/]seebom-labs\// && $3 == "(push)" { print $1; exit }')
  REMOTE="${REMOTE:-origin}"
fi
git remote get-url "$REMOTE" >/dev/null 2>&1 || die "git remote '$REMOTE' does not exist (set REMOTE=...)"
REMOTE_URL=$(git remote get-url --push "$REMOTE")

info "Fetching $REMOTE ..."
git fetch --quiet --tags --force "$REMOTE"

# owner/repo as GitHub Actions sees it. The remote URL may still carry an old
# repository name that GitHub redirects (seebom-labs/seebom → seebom-labs/BOMHort),
# but the GHCR path is derived from the canonical name.
SLUG=$(printf '%s' "$REMOTE_URL" | sed -E 's#^(ssh://)?(git@|https://)github\.com[:/]##; s#\.git$##; s#/$##')
CANONICAL=""
if command -v gh >/dev/null 2>&1; then
  CANONICAL=$(gh api "repos/$SLUG" --jq .full_name 2>/dev/null || true)
fi
if [[ -z "$CANONICAL" ]] && command -v curl >/dev/null 2>&1; then
  CANONICAL=$(curl -fsSL "https://api.github.com/repos/$SLUG" 2>/dev/null \
    | sed -nE 's/^  "full_name": "([^"]+)".*/\1/p' | head -n1 || true)
fi
SLUG="${CANONICAL:-$SLUG}"
GHCR="ghcr.io/$(printf '%s' "$SLUG" | tr '[:upper:]' '[:lower:]')"

# ─── Tag name ────────────────────────────────────────────────────────────────
FINAL_TAG="v$VERSION"
git rev-parse --verify --quiet "refs/tags/$FINAL_TAG" >/dev/null \
  && die "$FINAL_TAG is already released — there is nothing left to cut for $VERSION"

# ─── Ref to tag ──────────────────────────────────────────────────────────────
# Patch releases come from release/vX.Y once that branch exists (see
# docs/RELEASE.md); until then — as for every 0.x patch so far — from main.
if [[ -z "${REF:-}" ]]; then
  REF="$REMOTE/main"
  if [[ "$PATCH" != "0" ]] && git rev-parse --verify --quiet "refs/remotes/$REMOTE/release/v$MINOR" >/dev/null; then
    REF="$REMOTE/release/v$MINOR"
  fi
fi
COMMIT=$(git rev-parse --verify --quiet "$REF^{commit}") \
  || die "cannot resolve '$REF' (set REF=... to override)"

# Highest existing RC number for this version (0 if none).
LAST_RC=$(git tag -l "v$VERSION-rc.*" | sed -nE "s/^v${VERSION//./\\.}-rc\.([0-9]+)$/\1/p" | sort -n | tail -n1)
LAST_RC="${LAST_RC:-0}"

if [[ "$KIND" == "rc" ]]; then
  TAG="v$VERSION-rc.$((LAST_RC + 1))"
else
  TAG="$FINAL_TAG"
fi

# ─── Sanity checks ───────────────────────────────────────────────────────────
WARNINGS=()
if [[ "$KIND" == "final" ]]; then
  if [[ "$LAST_RC" == "0" ]]; then
    WARNINGS+=("no release candidate was cut for $VERSION — consider 'make release-rc VERSION=$VERSION' first")
  else
    RC_COMMIT=$(git rev-parse "v$VERSION-rc.$LAST_RC^{commit}")
    if [[ "$RC_COMMIT" != "$COMMIT" ]]; then
      WARNINGS+=("$REF ($(git rev-parse --short "$COMMIT")) is not the commit of v$VERSION-rc.$LAST_RC ($(git rev-parse --short "$RC_COMMIT")); the final release ships $(git rev-list --count "$RC_COMMIT..$COMMIT") commit(s) nobody tested as an RC")
    fi
  fi
fi

PREVIOUS=$( { git tag -l 'v*' | grep -Ev -- '-' | grep -vxF "$FINAL_TAG" || true; echo "$FINAL_TAG"; } \
  | sort -V | grep -B1 -xF "$FINAL_TAG" | head -n1)
[[ "$PREVIOUS" == "$FINAL_TAG" ]] && PREVIOUS=""

# ─── Summary ─────────────────────────────────────────────────────────────────
echo
echo "  Tag:       $TAG"
echo "  Commit:    $(git log -1 --format='%h %s' "$COMMIT")"
echo "  From:      $REF"
echo "  Remote:    $REMOTE ($SLUG)"
echo "  Publishes: $GHCR/<component>:${TAG#v}, chart oci://$GHCR/charts/bomhort --version ${TAG#v}"
if [[ -n "$PREVIOUS" ]]; then
  echo "  Changes:   $(git rev-list --count "$PREVIOUS..$COMMIT") commit(s) since $PREVIOUS"
fi
for w in ${WARNINGS[@]+"${WARNINGS[@]}"}; do
  echo "  ⚠️  $w"
done
echo

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  info "DRY_RUN=1 — nothing tagged or pushed."
  exit 0
fi

if [[ "${YES:-0}" != "1" ]]; then
  read -r -p "Create and push $TAG to $REMOTE? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || die "aborted"
fi

if [[ "$KIND" == "rc" ]]; then
  MESSAGE="BOMHort $TAG (release candidate for v$VERSION)"
else
  MESSAGE="BOMHort $TAG"
fi
git tag -a "$TAG" -m "$MESSAGE" "$COMMIT"
if ! git push "$REMOTE" "refs/tags/$TAG"; then
  git tag -d "$TAG" >/dev/null
  die "push failed; local tag $TAG removed again"
fi

echo
info "Pushed $TAG. The release workflow is building it now:"
echo "    https://github.com/$SLUG/actions/workflows/release.yml"
echo
info "Once it is green (~15 min), install it with:"
echo "    helm install bomhort oci://$GHCR/charts/bomhort --version ${TAG#v}"
echo "  or into the local Kind cluster (after make kind-up):"
echo "    make kind-deploy-release VERSION=${TAG#v} RELEASE_REPO=${GHCR#ghcr.io/}"




