"""Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).

The MCP server (#399) is the one component whose misconfiguration is a
security problem rather than an outage: its http transport is a remote
tool-execution endpoint. These tests assert that the chart refuses to render
such a configuration at all, instead of shipping it and hoping the binary's
own check is reached.
"""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"

VALID = {
    "mcp": {
        "enabled": True,
        "httpToken": "s3cret",
        "allowedOrigins": ["https://agent.example"],
    }
}


class MCPServerTest(unittest.TestCase):
    def render(self, values=None, success=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stderr

    def source(self, rendered, template):
        match = re.search(
            rf"# Source: bomhort/templates/{re.escape(template)}\n(.*?)(?=\n---|\Z)",
            rendered, re.DOTALL,
        )
        return match.group(1) if match else None

    def test_disabled_by_default(self):
        rendered = self.render()
        self.assertIsNone(self.source(rendered, "deployment-mcp-server.yaml"))
        self.assertIsNone(self.source(rendered, "service-mcp-server.yaml"))
        self.assertNotIn("mcp-auth", rendered)

    def test_http_without_token_is_refused(self):
        stderr = self.render(
            {"mcp": {"enabled": True, "allowedOrigins": ["https://agent.example"]}},
            success=False,
        )
        self.assertIn("mcp.httpToken", stderr)

    def test_http_without_allowed_origins_is_refused(self):
        stderr = self.render({"mcp": {"enabled": True, "httpToken": "s3cret"}}, success=False)
        self.assertIn("mcp.allowedOrigins", stderr)

    def test_wildcard_origin_is_refused(self):
        stderr = self.render(
            {"mcp": {"enabled": True, "httpToken": "s3cret", "allowedOrigins": ["*"]}},
            success=False,
        )
        self.assertIn("'*'", stderr)

    def test_valid_configuration_renders_deployment_service_and_secret(self):
        rendered = self.render(VALID)
        deployment = self.source(rendered, "deployment-mcp-server.yaml")
        self.assertIsNotNone(deployment, rendered)
        self.assertIn("MCP_ALLOWED_ORIGINS", deployment)
        self.assertIn("https://agent.example", deployment)
        self.assertIn('value: "0.0.0.0:8081"', deployment)
        self.assertIsNotNone(self.source(rendered, "service-mcp-server.yaml"))
        self.assertIn("MCP_HTTP_TOKEN", rendered)

    def test_api_base_url_defaults_to_the_release_gateway(self):
        deployment = self.source(self.render(VALID), "deployment-mcp-server.yaml")
        self.assertIn("http://test-api-gateway.", deployment)

    def test_api_base_url_can_be_overridden(self):
        values = json.loads(json.dumps(VALID))
        values["mcp"]["apiBaseURL"] = "https://bomhort.example.com"
        deployment = self.source(self.render(values), "deployment-mcp-server.yaml")
        self.assertIn("https://bomhort.example.com", deployment)

    # The MCP server is a consumer of the REST API. If it ever grows the
    # release-wide ConfigMap/Secret, it also grows ClickHouse credentials — and
    # the claim that it can only expose what the API exposes stops being true.
    def test_does_not_mount_the_database_credentials(self):
        deployment = self.source(self.render(VALID), "deployment-mcp-server.yaml")
        self.assertNotIn("envFrom", deployment)
        self.assertNotIn("CLICKHOUSE", deployment)
        self.assertNotIn("S3_", deployment)
        self.assertNotIn("GITHUB_TOKEN", deployment)

    def test_inherits_the_gateway_service_token_when_auth_is_on(self):
        values = json.loads(json.dumps(VALID))
        values["apiGateway"] = {"auth": {"enabled": True, "serviceToken": "tok"}}
        deployment = self.source(self.render(values), "deployment-mcp-server.yaml")
        self.assertIn("MCP_SERVICE_TOKEN", deployment)
        self.assertIn("test-api-auth", deployment)

    def test_stdio_transport_exposes_no_port_and_no_service(self):
        values = {"mcp": {"enabled": True, "transport": "stdio"}}
        rendered = self.render(values)
        deployment = self.source(rendered, "deployment-mcp-server.yaml")
        self.assertIsNotNone(deployment, rendered)
        self.assertNotIn("containerPort", deployment)
        self.assertIsNone(self.source(rendered, "service-mcp-server.yaml"))
        self.assertNotIn("mcp-auth", rendered)

    def test_existing_secret_replaces_the_generated_one(self):
        values = {
            "mcp": {
                "enabled": True,
                "allowedOrigins": ["https://agent.example"],
                "existingSecret": {
                    "enabled": True,
                    "secretName": "my-mcp-secret",
                    "httpTokenKey": "token",
                },
            }
        }
        rendered = self.render(values)
        deployment = self.source(rendered, "deployment-mcp-server.yaml")
        self.assertIn("my-mcp-secret", deployment)
        self.assertNotIn("test-mcp-auth", rendered)


if __name__ == "__main__":
    unittest.main()

