#!/usr/bin/env bash
# Demo SBOMs under examples/ are git-ignored on purpose (#394): osv-scanner
# honours .gitignore, and that is the only reliable way to keep deliberately
# vulnerable sample data out of the OpenSSF Scorecard without renaming the
# files away from the .spdx.json / .cdx.json convention. The price is that a
# new demo SBOM silently does not get committed unless someone remembers
# `git add -f`. This script makes that failure loud instead of silent.
#
# Two checks, because the failure shows up in two places:
#
#   1. Locally: a demo SBOM exists on disk but is not tracked. CI cannot see
#      this (it only checks out tracked files), so it is a `make check` /
#      pre-push concern.
#   2. In CI: a README under examples/ names a demo SBOM that is not tracked.
#      Every fixture is documented in its directory's README (that is how the
#      demo is explained), so a README that mentions a file git does not have
#      is the fingerprint of a forgotten `git add -f`. The reverse — a tracked
#      fixture no README mentions — is checked too, so the inventory stays
#      explained.
#
# Only READMEs in directories that actually ship fixtures are consulted;
# examples/kubernetes/README.md uses illustrative names like my-project.spdx.json
# in prose and must not be held to them.
#
# Usage: .github/scripts/check-demo-sboms.sh   (from the repository root)

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail=0
red() { printf '\033[31m%s\033[0m\n' "$*" >&2; }

# ── 1. On disk but not tracked (local only) ──────────────────────────────────
untracked=$(git ls-files --others --ignored --exclude-standard -- examples \
  | grep -E '\.(spdx|cdx)\.json$' || true)
if [[ -n "$untracked" ]]; then
  fail=1
  red "Demo SBOMs present on disk but NOT tracked by git (examples/**/*.spdx.json is git-ignored for scanners, see .gitignore):"
  printf '  %s\n' $untracked >&2
  red "Add them explicitly:  git add -f <file>"
fi

# ── 2. README ↔ tracked inventory ────────────────────────────────────────────
tracked=$(git ls-files -- 'examples/**/*.spdx.json' 'examples/**/*.cdx.json')

# Directories directly under examples/ that ship at least one fixture.
fixture_dirs=$(printf '%s\n' $tracked | awk -F/ '{print $1"/"$2}' | sort -u)

for dir in $fixture_dirs; do
  readme="$dir/README.md"
  [[ -f "$readme" ]] || { fail=1; red "$dir ships demo SBOMs but has no README.md documenting them"; continue; }

  # Basenames the README mentions.
  mentioned=$(grep -oE '[A-Za-z0-9._-]+\.(spdx|cdx)\.json' "$readme" | sort -u || true)
  # Basenames git tracks in that directory.
  have=$(printf '%s\n' $tracked | grep "^$dir/" | xargs -n1 basename | sort -u)

  # README → tracked: the forgotten-add-f case.
  missing=$(comm -23 <(printf '%s\n' $mentioned) <(printf '%s\n' $have) || true)
  if [[ -n "$missing" ]]; then
    fail=1
    red "$readme documents demo SBOMs that are not tracked in git:"
    printf '  %s\n' $missing >&2
    red "If the file exists locally:  git add -f $dir/<path>/<file>   (it is git-ignored on purpose, see .gitignore)"
  fi

  # tracked → README: keep the inventory explained.
  undocumented=$(comm -13 <(printf '%s\n' $mentioned) <(printf '%s\n' $have) || true)
  if [[ -n "$undocumented" ]]; then
    fail=1
    red "Tracked demo SBOMs in $dir that $readme does not mention:"
    printf '  %s\n' $undocumented >&2
  fi
done

if [[ $fail -eq 0 ]]; then
  count=$(printf '%s\n' $tracked | grep -c . || true)
  echo "demo SBOMs: $count tracked, all documented, none forgotten"
fi
exit $fail

