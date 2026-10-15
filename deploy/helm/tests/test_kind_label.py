"""kind-label.yml derives the release-notes kind/* label from the pull request title.

Runs the workflow's own `run:` script with a stub `gh`, so the test exercises the exact
shell that runs in CI. Backport titles ("[release/vX.Y] fix: ...", from hack/cherry-pick.sh)
got no label at all before the leading tag was skipped, and their PRs carried needs-kind.

Run with python3 -B -m unittest discover -s deploy/helm/tests -v.
"""

from pathlib import Path
import os
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/kind-label.yml"


def run_script():
    text = WORKFLOW.read_text()
    match = re.search(r"^        run: \|\n((?:          .*\n|\n)+)", text, re.M)
    assert match, "kind-label.yml: run: | block not found"
    return textwrap.dedent(match.group(1))


class KindLabelTest(unittest.TestCase):
    def label_for(self, title, labels=""):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "gh.log"
            stub = Path(tmp) / "gh"
            stub.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\n')
            stub.chmod(0o755)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}", GH_TOKEN="x",
                       REPO="seebom-labs/BOMHort", NUMBER="1", TITLE=title, LABELS=labels)
            subprocess.run(["bash", "-c", run_script()], env=env, check=True,
                           capture_output=True, text=True)
            if not log.exists():
                return None
            return re.search(r"--add-label (\S+)", log.read_text()).group(1)

    def test_conventional_prefixes(self):
        for title, kind in [
            ("feat(api)!: new endpoint", "kind/feature"),
            ("fix: thing", "kind/bug"),
            ("Revert \"feat: x\"", "kind/bug"),
            ("perf(clickhouse): faster", "kind/performance"),
            ("docs: typo", "kind/docs"),
            ("test: more", "kind/test"),
            ("ci(release-notes): sort", "kind/cleanup"),
        ]:
            with self.subTest(title=title):
                self.assertEqual(self.label_for(title), kind)

    def test_backport_titles(self):
        for title, kind in [
            ("[release/v0.8] fix(api): bound archived-packages memory", "kind/bug"),
            ("[release/v0.8] perf(clickhouse): narrow scopes", "kind/performance"),
            ("[release/v0.8][WIP] feat: x", "kind/feature"),
            ("  [release/v0.8]   docs: y", "kind/docs"),
        ]:
            with self.subTest(title=title):
                self.assertEqual(self.label_for(title), kind)

    def test_no_prefix_sets_nothing(self):
        for title in ["Update README", "[release/v0.8] Update README", "[release/v0.8]", "123: x"]:
            with self.subTest(title=title):
                self.assertIsNone(self.label_for(title))

    def test_existing_kind_is_kept(self):
        self.assertIsNone(self.label_for("fix: x", labels="backend kind/feature"))


if __name__ == "__main__":
    unittest.main()
