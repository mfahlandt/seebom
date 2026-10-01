"""Workflow hardening contract (OpenSSF Scorecard: Token-Permissions, Pinned-Dependencies).

Scorecard scores Token-Permissions 0 as soon as one workflow grants contents/actions write at
the top level — that is what prow.yml did, and it took the whole check from 10 to 0. Job-level
grants under a read-only top level are fine. Pinned-Dependencies drops for every `uses:` that
is a tag instead of a commit SHA. These tests keep both from regressing without waiting for the
weekly Scorecard run:

- every workflow declares top-level permissions, and none of them is a write,
- every third-party `uses:` (actions and reusable workflows) is pinned to a full commit SHA,
- the prow jobs still grant what the reusable prow workflow requests (or every run fails).

Run with python3 -B -m unittest discover -s deploy/helm/tests -v.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = sorted((ROOT / ".github/workflows").glob("*.yml"))

# What cncf/prow-github-actions' reusable workflow requests for its single job.
PROW_PERMISSIONS = {"contents", "issues", "pull-requests", "statuses", "actions"}


def top_level_permissions(text):
    """The top-level `permissions:` value: a scalar ("read-all") or a dict of scopes."""
    match = re.search(r"^permissions:[ \t]*(\S*)[ \t]*(?:#.*)?$", text, re.M)
    if match is None:
        return None
    if match.group(1):
        return match.group(1)
    block = re.match(r"((?:[ \t]+.*\n|[ \t]*#.*\n|\n)*)", text[match.end() + 1:]).group(1)
    return dict(re.findall(r"^[ \t]+([a-z-]+):[ \t]*([a-z-]+)", block, re.M))


def job_permissions(text, job):
    match = re.search(rf"^  {re.escape(job)}:\n((?:    .*\n|\n)*)", text, re.M)
    if match is None:
        raise AssertionError(f"job {job} not found")
    block = re.search(r"^    permissions:\n((?:      .*\n)*)", match.group(1), re.M)
    return dict(re.findall(r"^      ([a-z-]+):[ \t]*([a-z-]+)", block.group(1), re.M)) if block else {}


class WorkflowSecurityTest(unittest.TestCase):
    def test_workflows_found(self):
        self.assertIn("prow.yml", [w.name for w in WORKFLOWS])

    def test_top_level_permissions_are_declared_and_read_only(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                permissions = top_level_permissions(workflow.read_text())
                self.assertIsNotNone(permissions, "no top-level permissions: block (Scorecard treats undeclared as write-all)")
                if isinstance(permissions, str):
                    self.assertIn(permissions, ("read-all", "{}"))
                else:
                    writes = sorted(k for k, v in permissions.items() if v == "write")
                    self.assertFalse(writes, f"top-level write permissions {writes}; grant them on the job instead")

    def test_third_party_uses_are_pinned_to_a_commit(self):
        pattern = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.M)
        for workflow in WORKFLOWS:
            for ref in pattern.findall(workflow.read_text()):
                if ref.startswith(("./", "docker://")):
                    continue
                with self.subTest(workflow=workflow.name, uses=ref):
                    self.assertRegex(ref, r"@[0-9a-f]{40}$", "pin to the full commit SHA, keep the tag as a # comment")

    def test_prow_jobs_grant_what_the_reusable_workflow_requests(self):
        text = (ROOT / ".github/workflows/prow.yml").read_text()
        for job in ("prow", "label-sync"):
            with self.subTest(job=job):
                granted = {k for k, v in job_permissions(text, job).items() if v == "write"}
                self.assertEqual(granted, PROW_PERMISSIONS)


if __name__ == "__main__":
    unittest.main()

