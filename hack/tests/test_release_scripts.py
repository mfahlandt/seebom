"""Tests for hack/cut-release.sh and hack/cherry-pick.sh.

Releases are cut from release branches: the first RC of X.Y.0 cuts
release/vX.Y from main, every later RC, the final and all patches are tagged on
that branch, and fixes reach it only as cherry-picks from main. These tests run
the real scripts against throwaway repositories (a bare "upstream", a bare
"fork" and a working clone), so the rules are checked end to end without
touching GitHub.

Run with python3 -B -m unittest discover -s hack/tests -v.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CUT_RELEASE = ROOT / "hack/cut-release.sh"
CHERRY_PICK = ROOT / "hack/cherry-pick.sh"

# Isolate from the developer's git config (signing, hooks, default branch...).
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_TERMINAL_PROMPT": "0",
}


class ReleaseRepo(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.upstream = tmp / "upstream.git"
        self.fork = tmp / "fork.git"
        self.work = tmp / "work"
        self.env = {**os.environ, **GIT_ENV, "REMOTE": "upstream", "PUSH_REMOTE": "origin", "YES": "1"}
        self.env.pop("DRY_RUN", None)
        self.env.pop("REF", None)
        for bare in (self.upstream, self.fork):
            self.git("init", "--quiet", "--bare", "-b", "main", str(bare), cwd=tmp)
        self.git("init", "--quiet", "-b", "main", str(self.work), cwd=tmp)
        self.git("remote", "add", "upstream", str(self.upstream))
        self.git("remote", "add", "origin", str(self.fork))
        self.counter = 0
        self.commit("initial")
        self.git("push", "--quiet", "upstream", "main")

    def tearDown(self):
        self._tmp.cleanup()

    # ── helpers ──────────────────────────────────────────────────────────────
    def git(self, *args, cwd=None):
        result = subprocess.run(
            ["git", *args], cwd=cwd or self.work, env=self.env,
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()

    def commit(self, subject, path=None, content=None, body=None):
        self.counter += 1
        target = self.work / (path or f"file{self.counter}.txt")
        target.write_text(content if content is not None else f"{subject}\n")
        self.git("add", str(target))
        message = ["-m", subject] + (["-m", body] if body else [])
        self.git("commit", "--quiet", *message)
        return self.git("rev-parse", "HEAD")

    def commit_on(self, branch, subject, **kwargs):
        """Commit on an upstream branch (as a merged PR would) and push it."""
        original = self.git("rev-parse", "--abbrev-ref", "HEAD")
        self.git("fetch", "--quiet", "upstream")
        self.git("checkout", "--quiet", "-B", f"tmp-{branch}", f"upstream/{branch}")
        sha = self.commit(subject, **kwargs)
        self.git("push", "--quiet", "upstream", f"HEAD:refs/heads/{branch}")
        self.git("checkout", "--quiet", original)
        self.git("branch", "--quiet", "-D", f"tmp-{branch}")
        return sha

    def run_script(self, script, *args, **env):
        return subprocess.run(
            ["bash", str(script), *args], cwd=self.work,
            env={**self.env, **env}, capture_output=True, text=True,
        )

    def cut(self, *args, **env):
        return self.run_script(CUT_RELEASE, *args, **env)

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def fails(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stdout + result.stderr)

    def upstream_ref(self, ref):
        result = subprocess.run(
            ["git", "--git-dir", str(self.upstream), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            env=self.env, capture_output=True, text=True,
        )
        return result.stdout.strip() or None


class CutReleaseTest(ReleaseRepo):
    def test_first_rc_cuts_the_release_branch_from_main(self):
        head = self.commit("feat: something")
        self.git("push", "--quiet", "upstream", "main")

        out = self.ok(self.cut("rc", "0.8.0"))

        self.assertEqual(self.upstream_ref("refs/heads/release/v0.8"), head)
        self.assertEqual(self.upstream_ref("refs/tags/v0.8.0-rc.1"), head)
        self.assertIn("release/v0.8 is cut", out)

    def test_later_rcs_follow_the_branch_not_main(self):
        self.ok(self.cut("rc", "0.8.0"))
        self.commit("feat: for 0.9 only")
        self.git("push", "--quiet", "upstream", "main")

        # main moved, the branch did not: nothing new to test.
        self.fails(self.cut("rc", "0.8.0"), "already points at")

        fix = self.commit_on("release/v0.8", "fix: backported")
        self.ok(self.cut("rc", "0.8.0"))
        self.assertEqual(self.upstream_ref("refs/tags/v0.8.0-rc.2"), fix)

    def test_rc_numbers_sort_numerically(self):
        self.ok(self.cut("rc", "0.8.0"))
        for n in (9, 10):
            self.git("tag", f"v0.8.0-rc.{n}", "upstream/release/v0.8")
            self.git("push", "--quiet", "upstream", f"v0.8.0-rc.{n}")
        fix = self.commit_on("release/v0.8", "fix: one more")

        self.ok(self.cut("rc", "0.8.0"))

        self.assertEqual(self.upstream_ref("refs/tags/v0.8.0-rc.11"), fix)

    def test_final_needs_the_release_branch(self):
        self.fails(self.cut("final", "0.8.0"), "make release-rc VERSION=0.8.0")
        self.assertIsNone(self.upstream_ref("refs/tags/v0.8.0"))

    def test_final_warns_about_untested_commits_and_can_release_the_rc(self):
        self.ok(self.cut("rc", "0.8.0"))
        rc1 = self.upstream_ref("refs/tags/v0.8.0-rc.1")
        self.commit_on("release/v0.8", "fix: late")

        preview = self.ok(self.cut("final", "0.8.0", DRY_RUN="1"))
        self.assertIn("nobody tested as an RC", preview)
        self.assertIsNone(self.upstream_ref("refs/tags/v0.8.0"))

        out = self.ok(self.cut("final", "0.8.0", REF="v0.8.0-rc.1"))
        self.assertNotIn("nobody tested", out)
        self.assertEqual(self.upstream_ref("refs/tags/v0.8.0"), rc1)

    def test_ref_must_be_on_the_release_branch(self):
        self.ok(self.cut("rc", "0.8.0"))
        self.commit("feat: main only")
        self.git("push", "--quiet", "upstream", "main")

        self.fails(self.cut("final", "0.8.0", REF="upstream/main"), "is not on release/v0.8")
        self.assertIsNone(self.upstream_ref("refs/tags/v0.8.0"))

    def test_patch_for_a_minor_released_before_branches(self):
        # v0.7.1 was tagged on main, the way every 0.x release used to be.
        self.git("tag", "-a", "v0.7.1", "-m", "v0.7.1")
        self.git("push", "--quiet", "upstream", "v0.7.1")
        v071 = self.git("rev-parse", "v0.7.1^{commit}")
        self.commit("feat: 0.8 work")
        self.git("push", "--quiet", "upstream", "main")

        self.fails(self.cut("final", "0.7.2"), "make release-branch VERSION=0.7")
        self.fails(self.cut("rc", "0.7.2"), "make release-branch VERSION=0.7")

        self.ok(self.cut("branch", "0.7"))
        self.assertEqual(self.upstream_ref("refs/heads/release/v0.7"), v071)

        self.fails(self.cut("final", "0.7.2"), "nothing on release/v0.7 since v0.7.1")

        fix = self.commit_on("release/v0.7", "fix: backported")
        self.ok(self.cut("final", "0.7.2"))
        self.assertEqual(self.upstream_ref("refs/tags/v0.7.2"), fix)

    def test_branch_refuses_to_recreate(self):
        self.ok(self.cut("branch", "0.8"))
        self.fails(self.cut("branch", "0.8"), "already exists")

    def test_already_released_version(self):
        self.ok(self.cut("rc", "0.8.0"))
        self.ok(self.cut("final", "0.8.0"))
        self.fails(self.cut("rc", "0.8.0"), "already released")

    def test_dry_run_creates_nothing(self):
        out = self.ok(self.cut("rc", "0.8.0", DRY_RUN="1"))
        self.assertIn("v0.8.0-rc.1", out)
        self.assertIn("NEW, cut from upstream/main", out)
        self.assertIsNone(self.upstream_ref("refs/heads/release/v0.8"))
        self.assertIsNone(self.upstream_ref("refs/tags/v0.8.0-rc.1"))
        self.assertEqual(self.git("tag", "-l"), "")

    def test_rejects_malformed_versions(self):
        self.fails(self.cut("rc", "0.8.0-rc.1"), "VERSION must be X.Y.Z")
        self.fails(self.cut("final", "0.8"), "VERSION must be X.Y.Z")
        self.fails(self.cut("ship", "0.8.0"), "first argument")


class CherryPickTest(ReleaseRepo):
    def setUp(self):
        super().setUp()
        self.ok(self.cut("branch", "0.8"))
        self.commit("feat: main only", path="feature.txt")
        self.git("push", "--quiet", "upstream", "main")
        # A stand-in for the GitHub CLI: answers `gh pr view` and
        # `gh api repos/.../commits/<sha>/pulls` from files, already in the
        # shape the script's --jq filters produce.
        self.gh_data = Path(self._tmp.name) / "gh"
        self.gh_data.mkdir()
        fake_gh = Path(self._tmp.name) / "fake-gh"
        fake_gh.write_text(FAKE_GH)
        fake_gh.chmod(0o755)
        self.env.update(GH=str(fake_gh), FAKE_GH_DATA=str(self.gh_data))

    def pick(self, *args, **env):
        return self.run_script(CHERRY_PICK, *args, **env)

    def fork_ref(self, ref):
        result = subprocess.run(
            ["git", "--git-dir", str(self.fork), "rev-parse", "--verify", "--quiet", ref],
            env=self.env, capture_output=True, text=True,
        )
        return result.stdout.strip() or None

    def rebase_merge(self, number, *subjects, pr_commits=None, title="fix: rebased", state="MERGED"):
        """Land a PR on main the way a rebase merge does: its commits keep their subjects."""
        shas = [self.commit(subject) for subject in subjects]
        self.git("push", "--quiet", "upstream", "main")
        for sha in shas:
            (self.gh_data / f"commit-{sha}").write_text(f"{number}\n")
        merge = shas[-1] if shas and state == "MERGED" else "-"
        count = pr_commits if pr_commits is not None else len(shas)
        (self.gh_data / f"pr-{number}").write_text(f"{state} {merge} {count} {title}\n")
        return shas

    def picked(self, head, count):
        """Subjects and origins of the last <count> commits on <head>, oldest first."""
        commits = self.git("rev-list", "--reverse", f"-{count}", head).splitlines()
        return [(self.git("log", "-1", "--format=%s", c), self.git("log", "-1", "--format=%B", c)) for c in commits]

    def test_picks_the_squash_merged_pr_onto_the_release_branch(self):
        fix = self.commit("fix(api): handle nil (#42)")
        self.git("push", "--quiet", "upstream", "main")

        out = self.ok(self.pick("42", "0.8"))

        head = self.fork_ref("refs/heads/cherry-pick/42-to-release-v0.8")
        self.assertIsNotNone(head)
        message = self.git("log", "-1", "--format=%B", head)
        self.assertIn(f"cherry picked from commit {fix}", message)
        self.assertEqual(self.git("rev-parse", f"{head}^"), self.git("rev-parse", "upstream/release/v0.8"))
        # Only the fix, not the feature that merged to main before it.
        self.assertNotIn("feature.txt", self.git("ls-tree", "-r", "--name-only", head))
        self.assertEqual(self.git("rev-parse", "--abbrev-ref", "HEAD"), "main")
        self.assertIn("compare/release/v0.8...", out)

    def test_refuses_a_second_backport(self):
        self.commit("fix: once (#43)")
        self.git("push", "--quiet", "upstream", "main")
        self.ok(self.pick("43", "release/v0.8"))
        # The backport PR merges into the release branch.
        self.git("push", "--quiet", "upstream", "cherry-pick/43-to-release-v0.8:refs/heads/release/v0.8")
        self.git("branch", "--quiet", "-D", "cherry-pick/43-to-release-v0.8")

        self.fails(self.pick("43", "0.8"), "already on release/v0.8")

    def test_unmerged_pr(self):
        self.fails(self.pick("999", "0.8"), "is the PR merged")

    def test_matches_the_subject_only(self):
        self.commit("docs: unrelated", body="Follow-up to (#44)")
        self.git("push", "--quiet", "upstream", "main")
        self.fails(self.pick("44", "0.8"), "is the PR merged")

    def test_missing_release_branch(self):
        self.fails(self.pick("1", "0.9"), "release/v0.9 does not exist")

    def test_conflict_stops_on_the_branch(self):
        self.commit_on("release/v0.8", "fix: release-only change", path="shared.txt", content="release\n")
        self.commit("fix: main change (#45)", path="shared.txt", content="main\n")
        self.git("push", "--quiet", "upstream", "main")

        self.fails(self.pick("45", "0.8"), "Conflict")
        self.assertEqual(self.git("rev-parse", "--abbrev-ref", "HEAD"), "cherry-pick/45-to-release-v0.8")
        self.assertIsNone(self.fork_ref("refs/heads/cherry-pick/45-to-release-v0.8"))
        self.git("cherry-pick", "--abort")

    def test_dry_run_changes_nothing(self):
        self.commit("fix: dry (#46)")
        self.git("push", "--quiet", "upstream", "main")
        out = self.ok(self.pick("46", "0.8", DRY_RUN="1"))
        self.assertIn("fix: dry (#46)", out)
        self.assertEqual(self.git("branch", "--list", "cherry-pick/*"), "")

    # ── rebase merges (the default) ─────────────────────────────────────────
    def test_picks_every_commit_of_a_rebase_merged_pr(self):
        first, second = self.rebase_merge(50, "fix(api): handle nil", "test(api): cover nil", title="Handle nil")

        out = self.ok(self.pick("50", "0.8"))

        head = self.fork_ref("refs/heads/cherry-pick/50-to-release-v0.8")
        self.assertIsNotNone(head)
        picked = self.picked(head, 2)
        self.assertEqual([subject for subject, _ in picked], ["fix(api): handle nil", "test(api): cover nil"])
        self.assertIn(f"cherry picked from commit {first}", picked[0][1])
        self.assertIn(f"cherry picked from commit {second}", picked[1][1])
        self.assertEqual(self.git("rev-parse", f"{head}~2"), self.git("rev-parse", "upstream/release/v0.8"))
        self.assertNotIn("feature.txt", self.git("ls-tree", "-r", "--name-only", head))
        self.assertIn("Title: [release/v0.8] Handle nil", out)

    def test_stops_at_commits_of_other_prs(self):
        # #51 had three commits, but one was already on main: only two landed.
        # Walking back by the commit count alone would grab #49's commit.
        self.rebase_merge(49, "fix: someone else's")
        self.rebase_merge(51, "fix: one", "fix: two", pr_commits=3)

        out = self.ok(self.pick("51", "0.8", DRY_RUN="1"))

        self.assertIn("fix: one", out)
        self.assertIn("fix: two", out)
        self.assertNotIn("someone else's", out)

    def test_refuses_a_second_backport_of_a_rebase_merged_pr(self):
        self.rebase_merge(52, "fix: a", "fix: b")
        self.ok(self.pick("52", "0.8"))
        self.git("push", "--quiet", "upstream", "cherry-pick/52-to-release-v0.8:refs/heads/release/v0.8")
        self.git("branch", "--quiet", "-D", "cherry-pick/52-to-release-v0.8")

        self.fails(self.pick("52", "0.8"), "already on release/v0.8")

    def test_open_pr(self):
        self.rebase_merge(53, state="OPEN")
        self.fails(self.pick("53", "0.8"), "is the PR merged")

    def test_needs_the_github_cli_for_rebase_merges(self):
        self.rebase_merge(54, "fix: needs gh")
        self.fails(self.pick("54", "0.8", GH="false"), "needs the GitHub CLI")


# Answers from files in $FAKE_GH_DATA: pr-<n> holds the `gh pr view` line
# ("STATE MERGE_SHA COMMIT_COUNT TITLE"), commit-<sha> the PR numbers.
FAKE_GH = r"""#!/usr/bin/env bash
case "$1" in
  --version) echo "gh version 0.0.0 (fake)" ;;
  pr) cat "$FAKE_GH_DATA/pr-$3" 2>/dev/null || { echo "no pull request $3" >&2; exit 1; } ;;
  api) sha="${2#*/commits/}"; cat "$FAKE_GH_DATA/commit-${sha%/pulls}" 2>/dev/null || true ;;
  *) echo "fake gh: unexpected $*" >&2; exit 1 ;;
esac
"""


if __name__ == "__main__":
    unittest.main()


