# Shared helpers for hack/cut-release.sh and hack/cherry-pick.sh. Source, don't run.
# shellcheck shell=bash

die()  { echo "❌ $*" >&2; exit 1; }
info() { echo "▸ $*"; }
warn() { echo "⚠️  $*" >&2; }

# The remote pointing at the canonical repository (seebom-labs/*), else origin.
# Respects $REMOTE if set.
upstream_remote() {
  local remote="${REMOTE:-}"
  if [[ -z "$remote" ]]; then
    remote=$(git remote -v | awk 'tolower($2) ~ /github\.com[:\/]seebom-labs\// && $3 == "(push)" { print $1; exit }')
    remote="${remote:-origin}"
  fi
  git remote get-url "$remote" >/dev/null 2>&1 || die "git remote '$remote' does not exist (set REMOTE=...)"
  printf '%s' "$remote"
}

# owner/repo for a remote, as GitHub Actions sees it. The remote URL may still
# carry an old repository name that GitHub redirects (seebom-labs/seebom →
# seebom-labs/BOMHort), but GHCR paths and web URLs use the canonical name.
# Non-GitHub remotes (e.g. local test repositories) are returned as-is.
repo_slug() {
  local url slug canonical=""
  url=$(git remote get-url --push "$1")
  if [[ ! "$url" =~ github\.com[:/] ]]; then
    printf '%s' "$url"
    return
  fi
  slug=$(printf '%s' "$url" | sed -E 's#^(ssh://)?(git@|https://)github\.com[:/]##; s#\.git$##; s#/$##')
  if command -v curl >/dev/null 2>&1; then
    canonical=$(curl -fsSL --max-time 5 "https://api.github.com/repos/$slug" 2>/dev/null \
      | sed -nE 's/^  "full_name": "([^"]+)".*/\1/p' | head -n1 || true)
  fi
  printf '%s' "${canonical:-$slug}"
}

# Highest final (non-pre-release) tag vX.Y.* for a minor "X.Y", or empty.
latest_patch_tag() {
  git tag -l "v$1.*" | grep -E "^v${1//./\\.}\.[0-9]+$" | sort -V | tail -n1 || true
}

