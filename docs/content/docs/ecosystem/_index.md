---
title: "Ecosystem"
linkTitle: "Ecosystem"
type: docs
weight: 10
description: >
  The Go client and VEXViper — projects built on BOMHort's REST API, documented from their own repositories.
---

BOMHort's REST API is the only integration surface. These projects use it and
keep their documentation next to their code; the pages in this section are
built from their `main` branch on every docs deploy.

| Project | What it is | Start here |
|---------|------------|------------|
| [bomhort-go](https://github.com/seebom-labs/bomhort-go) | The Go client for the REST API: every endpoint, standard library only, with an in-memory fake gateway for tests. | [Go Client](go-client/) |
| [VEXViper](https://github.com/seebom-labs/VEXViper) | Generates OpenVEX for BOMHort's findings from deterministic evidence plus a heuristic or LLM assessment, and uploads it back. | [VEXViper](vexviper/) |
| [MCP server](/docs/mcp/) | Ships with BOMHort: read-only tools for AI agents. | [MCP Server](/docs/mcp/) |

## How-to guides

- [Use the Go client](go-client/overview/#quick-start)
- [Upload VEX with the Go client](go-client/how-to-upload-vex/)
- [Test your code against a fake BOMHort](go-client/testing/#the-fake-gateway-bomhorttest)
- [Migrate from VEXViper's internal client to bomhort-go](go-client/how-to-migrate-from-vexviper/)
- [Run VEXViper as a CronJob against your instance](vexviper/how-to-cronjob/)
- [Review VEX drafts in pull requests before they reach BOMHort](vexviper/how-to-gitops/)
- [Set up an LLM provider for VEXViper](vexviper/how-to-llm/)
- [Connect an AI agent to BOMHort](/docs/mcp/#connecting-an-agent)
