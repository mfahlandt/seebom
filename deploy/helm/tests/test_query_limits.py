"""Helm template tests for the API gateway's ClickHouse query limits (#344-I).

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"
LIMIT_VARS = ("CLICKHOUSE_MAX_EXECUTION_TIME", "CLICKHOUSE_MAX_MEMORY_USAGE",
              "CLICKHOUSE_MAX_THREADS")


class QueryLimitsTemplatesTest(unittest.TestCase):
    def helm(self, values):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            return subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )

    def render(self, values=None):
        result = self.helm(values)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {doc.split("# Source: ", 1)[1].split("\n", 1)[0]: doc
                for doc in result.stdout.split("\n---\n") if "# Source: " in doc}

    def gateway(self, docs):
        return docs["bomhort/templates/deployment-api-gateway.yaml"]

    def test_defaults_limit_time_and_memory_but_not_threads(self):
        gw = self.gateway(self.render())
        self.assertIn('- name: CLICKHOUSE_MAX_EXECUTION_TIME\n              value: "30"', gw)
        self.assertIn('- name: CLICKHOUSE_MAX_MEMORY_USAGE\n              value: "536870912"', gw)
        self.assertNotIn("CLICKHOUSE_MAX_THREADS", gw)

    def test_only_the_gateway_is_limited(self):
        docs = self.render({"apiGateway": {"queryLimits": {"maxThreads": 4}}})
        for source, doc in docs.items():
            if source.endswith("deployment-api-gateway.yaml"):
                continue
            for var in LIMIT_VARS:
                self.assertNotIn(var, doc, f"{var} leaked into {source}")

    def test_overrides_and_large_byte_values_render_as_integers(self):
        gw = self.gateway(self.render({"apiGateway": {"queryLimits": {
            "maxExecutionTime": 120, "maxMemoryUsage": 8589934592, "maxThreads": 4}}}))
        self.assertIn('value: "120"', gw)
        self.assertIn('value: "8589934592"', gw)
        self.assertIn('- name: CLICKHOUSE_MAX_THREADS\n              value: "4"', gw)

    def test_zero_or_absent_means_unset(self):
        for values in ({"apiGateway": {"queryLimits": {
                "maxExecutionTime": 0, "maxMemoryUsage": 0, "maxThreads": 0}}},
                       {"apiGateway": {"queryLimits": None}}):
            gw = self.gateway(self.render(values))
            for var in LIMIT_VARS:
                self.assertNotIn(var, gw)

    def test_invalid_values_fail_the_render(self):
        for limits, message in (({"maxMemoryUsage": "512Mi"}, "must be a number"),
                                ({"maxThreads": -1}, "must not be negative")):
            result = self.helm({"apiGateway": {"queryLimits": limits}})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
