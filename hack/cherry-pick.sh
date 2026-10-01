#!/usr/bin/env bash
# Backport a change that is merged on main to a release branch, as a pull
# request against release/vX.Y.
#
# Usage:
#   hack/cherry-pick.sh <PR number | commit> <X.Y | release/vX.Y>
#   make cherry-pick PR=431 BRANCH=0.8
#
# Fixes always land on main first. This finds the squash-merged commit of the
# PR on <REMOTE>/main (subject ending in "(#431)"), picks it onto
# release/vX.Y with `git cherry-pick -x` (so the commit names its origin),
# pushes a branch to your fork and prints the link to open the pull request.
# On a conflict it stops on the branch and tells you how to finish.
#
# Environment:
#   REMOTE       git remote of the canonical repo (default: the remote pointing
#                at seebom-labs/*, otherwise origin)
#   PUSH_REMOTE  where the cherry-pick branch is pushed (default: origin)
#   DRY_RUN      1 = show what would be picked, change nothing
set -euo pipefail
# shellcheck source=hack/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
  exit "${1:-0}"
}

[[ $# -eq 2 ]] || usage 1
WHAT="$1"
TARGET="${2#release/}"
TARGET="${TARGET#v}"
[[ "$TARGET" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die "target must be X.Y or release/vX.Y, got '$2'"
BRANCH="release/v$TARGET"

REMOTE=$(upstream_remote)
PUSH_REMOTE="${PUSH_REMOTE:-origin}"
git remote get-url "$PUSH_REMOTE" >/dev/null 2>&1 || die "git remote '$PUSH_REMOTE' does not exist (set PUSH_REMOTE=...)"

info "Fetching $REMOTE ..."
git fetch --quiet --prune "$REMOTE"
git rev-parse --verify --quiet "refs/remotes/$REMOTE/$BRANCH" >/dev/null \
  || die "$BRANCH does not exist on $REMOTE (create it: make release-branch VERSION=$TARGET)"

# ─── Commit to pick ──────────────────────────────────────────────────────────
PR=""
if [[ "$WHAT" =~ ^#?([0-9]+)$ ]]; then
  PR="${BASH_REMATCH[1]}"
  # Squash merges end the subject with "(#<PR>)". Match the subject only — a
  # body mentioning "(#431)" must not count.
  COMMITS=$(git log "$REMOTE/main" --format='%H %s' \
    | awk -v suffix="(#$PR)" 'substr($0, length($0) - length(suffix) + 1) == suffix { print $1 }')
  COUNT=$(printf '%s' "$COMMITS" | grep -c . || true)
  [[ "$COUNT" -ge 1 ]] || die "no commit on $REMOTE/main ends with (#$PR) — is the PR merged?"
  [[ "$COUNT" -eq 1 ]] || die "$COUNT commits on $REMOTE/main end with (#$PR); pass the commit instead"
  COMMIT="$COMMITS"
else
  COMMIT=$(git rev-parse --verify --quiet "$WHAT^{commit}") || die "cannot resolve '$WHAT'"
  if ! git merge-base --is-ancestor "$COMMIT" "$REMOTE/main"; then
    warn "$(git rev-parse --short "$COMMIT") is not on $REMOTE/main. Fixes land on main first, then get backported."
  fi
fi
SHORT=$(git rev-parse --short "$COMMIT")
SUBJECT=$(git log -1 --format=%s "$COMMIT")

if git log "$REMOTE/$BRANCH" --format=%B | grep -qF "cherry picked from commit $COMMIT"; then
  die "$SHORT is already on $BRANCH"
fi
if git merge-base --is-ancestor "$COMMIT" "$REMOTE/$BRANCH"; then
  die "$SHORT is already on $BRANCH (it predates the branch cut)"
fi

[[ "$(git rev-list --parents -n1 "$COMMIT" | wc -w)" -le 2 ]] \
  || die "$SHORT is a merge commit; pick its individual commits instead"

LOCAL_BRANCH="cherry-pick/${PR:-$SHORT}-to-release-v$TARGET"
if git rev-parse --verify --quiet "refs/heads/$LOCAL_BRANCH" >/dev/null; then
  die "local branch $LOCAL_BRANCH already exists (delete it: git branch -D $LOCAL_BRANCH)"
fi

echo
echo "  Pick:      $SHORT $SUBJECT"
echo "  Onto:      $REMOTE/$BRANCH"
echo "  Branch:    $LOCAL_BRANCH → $PUSH_REMOTE"
echo

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  info "DRY_RUN=1 — nothing changed."
  exit 0
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  die "working tree has uncommitted changes; commit or stash them first"
fi

ORIGINAL=$(git symbolic-ref --short -q HEAD || git rev-parse HEAD)
git checkout --quiet --no-track -b "$LOCAL_BRANCH" "$REMOTE/$BRANCH"

if ! git cherry-pick -x "$COMMIT"; then
  echo
  warn "Conflict. You are on $LOCAL_BRANCH. To finish:"
  echo "    1. resolve the conflicts, git add <files>"
  echo "    2. git cherry-pick --continue"
  echo "    3. git push -u $PUSH_REMOTE $LOCAL_BRANCH"
  echo "    4. open a pull request against $BRANCH, and note in it what you resolved"
  echo "  To give up: git cherry-pick --abort && git checkout $ORIGINAL && git branch -D $LOCAL_BRANCH"
  exit 1
fi

git push --quiet -u "$PUSH_REMOTE" "$LOCAL_BRANCH"
git checkout --quiet "$ORIGINAL"

# Link to open the pull request: base = canonical release branch, head = the
# pushed branch (cross-fork syntax owner:repo:branch when pushed to a fork).
UPSTREAM_SLUG=$(repo_slug "$REMOTE")
PUSH_SLUG=$(repo_slug "$PUSH_REMOTE")
if [[ "$UPSTREAM_SLUG" == "$PUSH_SLUG" ]]; then
  HEAD_SPEC="$LOCAL_BRANCH"
else
  HEAD_SPEC="${PUSH_SLUG%%/*}:${PUSH_SLUG#*/}:$LOCAL_BRANCH"
fi

echo
info "Pushed $LOCAL_BRANCH to $PUSH_REMOTE. Open the pull request:"
echo "    https://github.com/$UPSTREAM_SLUG/compare/$BRANCH...$HEAD_SPEC?expand=1"
echo
echo "  Title: [$BRANCH] $SUBJECT"
if [[ -n "$PR" ]]; then
  echo "  Body:  Cherry-pick of #$PR onto $BRANCH."
fi

