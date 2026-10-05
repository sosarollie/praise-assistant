# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Packaged AI-agent operating instructions.

`vvaharness setup --install-agents` writes these into the files each agent
reads, so an agent driving the tool RUNS it rather than editing it. AGENTS.md
and .github/copilot-instructions.md are always written; CLAUDE.md and the
Claude skill only when a `claude` CLI is on PATH, and GEMINI.md only when
`gemini` is. Existing files are never overwritten. Kept in the package (not
just the repo AGENTS.md) so pip-installed users have it too."""
from __future__ import annotations

# Canonical operating manual (cross-tool: AGENTS.md, Cursor, Codex, …).
# Leads with the Apache header so generated files carry it like the rest of the tree.
AGENT_DOC = """\
<!--
Copyright 2026 Visa, Inc.
Licensed under the Apache License, Version 2.0; see http://www.apache.org/licenses/LICENSE-2.0
-->
# Operating vvaharness (for AI coding agents)

`vvaharness` is a **released** CLI security-scanning product. **Operate it,
do not develop or repair it.**

## The three rules
1. **Never edit the `vvaharness` package source** to make a scan run. If it
   won't run, that's an environment problem (below) or a bug to report.
2. **Never hand-write config files.** Use a shipped profile via `--config`.
3. **On any failure, run `vvaharness doctor` (or `setup`), fix the environment
   it points to, and re-run.** Report bugs; don't patch around them.

## Run it
```
pipx install .                     # from the vvaharness folder; or: pip install .
vvaharness setup                   # checks Python, agents, keys, gateway, config
vvaharness scan --repo <path> --application-id <id> --stop-after s9
vvaharness scan --repo <path> --stop-after ev   # Beta — API only: EV preflight only
vvaharness ev-replay --repo <path>              # Beta — API only: re-run verified exploits
```
- The shipped default routes DeepAgents/Anthropic throughout: S0's LLM seed
  annotation (`callgraph_detection: llm` — S0 spends tokens), S1-S9, and both
  S10 and S11, so one Anthropic credential covers a run. Zero tools on the
  single-prompt roles; S1's explorer and the static S6 verifier keep a
  read-only tool loop. The exception is exploit verification
  (**Beta — API only**), which ships all four exploit-verification roles
  `via: deepagents` in `default.yaml`, `full.yaml` and `taint.yaml`, and
  `via: sdk` in `sdk.yaml`. No shipped profile routes an EV role `via: cli`.
  One Anthropic credential covers an EV-armed `default` or `taint` run;
  `full.yaml` additionally needs `OPENAI_API_KEY`, for its `judge` alone. A
  complete run needs credentials for each enabled backend. `setup` reports
  missing pieces.
- **Exploit verification (EV) is Beta — API only.** It sends real HTTP attack
  traffic at a running localhost target and is off unless `EV_API_COLLECTION`
  names a Postman/OpenAPI/Swagger collection. Do not arm it unless the user
  explicitly asks; it can only verify findings that map to an HTTP endpoint.
  `--stop-after ev` parses the collection and probes the target's
  reachability, then stops **before S0** — no call graph and no model spend.
  `vvaharness ev-replay --repo <path>` re-checks exploit-verified findings
  against a redeployed target.
- The packaged default sets `step_remediate.enabled: false` and
  `step_validate.enabled: false`, so a plain scan using it skips S10/S11.
  Other profiles or a local overlay can enable them (`sdk`/`full` still do).
  `--remediate` enables S10 only and can edit target source. In-scan S11 requires
  `step_validate.enabled: true`; there is no scan `--validate` flag.
  Standalone `remediate` and `validate` remain available when these flags are
  false. Keep `--stop-after s9` to explicitly skip both stages with any profile,
  even with `--remediate`.
- `sdk.yaml` spells every role `via: sdk`; its detection and S10 paths use
  `ANTHROPIC_SDK_API_KEY`, while S11 pins external `claude` and uses ambient
  Claude login / `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN`. The SDK-named key alone does not authenticate S11. A
  standard Anthropic credential can cover all stages through the sole-SDK
  detection fallback.
- For an enterprise gateway, use the endpoint/trust variables for the selected
  backend (`ANTHROPIC_SDK_BASE_URL` for direct SDK detection;
  `ANTHROPIC_BASE_URL` for Claude/DeepAgents paths). Run `setup` for exact
  environment guidance.

## On failure
Read the one-line `✗ scan failed: …`, run `vvaharness doctor`, fix what it
flags (usually a credential or `ANTHROPIC_BASE_URL`), re-run. Full trace:
`VVAHARNESS_DEBUG=1`. Findings are triage candidates, not confirmed vulns.
"""

# Claude Code skill: same content, with the required frontmatter so Claude Code
# auto-discovers it from ~/.claude/skills/vvaharness/SKILL.md.
CLAUDE_SKILL = (
    "---\n"
    "name: vvaharness\n"
    "description: Operate the vvaharness SAST CLI (install, setup, doctor, "
    "scan). Use when asked to scan a repo for vulnerabilities with vvaharness. "
    "Operate the tool; never edit its source or hand-write its config. "
    "Exploit verification is Beta and API-only; do not arm it unless asked.\n"
    "---\n\n"
) + AGENT_DOC


def gemini_doc() -> str:
    return AGENT_DOC.replace("(for AI coding agents)", "(for the Gemini CLI)")
