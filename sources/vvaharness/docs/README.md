<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Documentation

Start with the two main guides:

| Guide | |
|---|---|
| [User Guide](USER_GUIDE.md) | All commands, flags, backends, stages, and outputs |
| [Setup Guide](SETUP_GUIDE.md) | Install, credentials, `.env`, config profiles |

Reference docs:

| Doc | |
|---|---|
| [Configuration](configuration.md) | `config.yaml` reference |
| [Models](models.md) | Model roles & backend swap |
| [Outputs](outputs.md) | Markdown + SARIF report anatomy |
| [`repos.csv` format](repos-csv.md) | Batch input spec |
| [Architecture](architecture.md) | Module map & data flow |
| [DeepAgents route](deepagents.md) | The `via: deepagents` route — provider, tool, TLS, and limit guidance |
| [Operational Security](security.md) | Isolation, redaction, data egress |
| [Skills](SKILLS.md) | Security-analysis lenses built into the pipeline |
| [Exploit verification](exploit-verification.md) | **Beta (API only), off by default (localhost only).** Confirming findings live against a running target (step 6) — and the `ev-replay` command |
| [Remediation](remediation.md) | The `remediate` command (step 10) — fix generation |
| [Validation](validation.md) | The `validate` / `s11` command (step 11) — agentic fix grading |
| [Reporting issues](contributor-issue-guide.md) | How to file bug, documentation, and setup reports via GitHub issue forms |

Features & combinations:

| File | |
|---|---|
| [Features & Capabilities](features.md) | What the tool does and every backend/stage combination: pipeline stages, backends, recipe profiles, credentials per combination, commands and flags, specialist lenses, the taint engine, and limitations. |
| [Errors and Exit Codes](errors.md) | Public error codes, process exit codes, recovery actions, and artifact locations. |
