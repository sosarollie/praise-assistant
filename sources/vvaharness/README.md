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

# Visa Vulnerability Agentic Harness — Agentic Vulnerability Discovery, Remediation, and Validation

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Python](https://img.shields.io/badge/python-%E2%89%A5%203.11-blue.svg)
![Version](https://img.shields.io/badge/version-1.4.0-informational.svg)
![Output](https://img.shields.io/badge/output-Markdown%20%2B%20SARIF%202.1.0-green.svg)

VVAH is Visa's open-source harness for autonomous vulnerability discovery,
remediation, and validation using large language models, built on learnings from
[Project Glasswing](https://www.anthropic.com/glasswing) (Anthropic's
initiative for AI-assisted vulnerability research).

VVAH supports a four-phase pipeline: an S0 static seed followed by detection
and reporting (S1–S9), with optional remediation and validation (S10–S11).
The shipped `default.yaml` and `full.yaml` profiles derive that seed from the
model; `taint.yaml` uses rules mode, which needs operator-supplied source/sink
YAML. The four phases:

- **Phase 1 — Discovery & Modeling (S1–S3)**: map the attack surface and build a
  threat-aware plan.
- **Phase 2 — Deep Dive & Verification (S4–S6)**: run multi-lens analysis and
  adversarial verification to assess likely exploitability.
- **Phase 3 — Synthesis & Reporting (S7–S9)**: deduplicate, chain, and emit
  structured findings (Markdown + SARIF).
- **Phase 4 — Remediation & Validation (S10–S11, optional)**: propose candidate
  fixes and adversarially validate them before adoption. Disabled in the shipped
  default profile, which stops after Phase 3 (S9). See
  [Run your first scan](#run-your-first-scan) for how to enable these stages.

Three design choices drive finding quality: threat modeling before analysis
focuses the attack surface; multi-agent deterministic voting reduces false
positives; and structured triage artifacts compress the lifecycle from
AI-discovered weakness to actionable finding. The bottleneck in AI-assisted
vulnerability management is triage speed, not discovery. VVAH is designed
around that constraint. The primary effectiveness metric is **Mean Time to
Adapt (MTTA)**: elapsed time from AI-discovered exploitability to a validated
fix in production.

**Multi-model by design.** Every model-driven role — S0 through S11 — can be
pointed at its own model and provider:

- **Anthropic Claude** — native route
- **OpenAI-compatible** — OpenAI models and any OpenAI-compatible gateway
- **Open-weight** — served over Chat Completions-compatible endpoints

No single provider is a hard dependency. Detection and remediation/validation
draw on the same set; see [docs/models.md](docs/models.md) for the per-role
matrix.

For setup, see [`docs/SETUP_GUIDE.md`](docs/SETUP_GUIDE.md). GitHub Issues are
open for bug, documentation, setup, and feature-request reports — see
[Reporting issues](#reporting-issues). This repository is not currently
accepting external code contributions; see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

> **Authorized use only.** Run scans only against code you own or have explicit
> permission to test. Findings and fixes are LLM-generated triage candidates
> that require human review — see [Limitations](#limitations-read-before-you-trust-output).
>
> **Data egress warning.** Any role routed to `via: cli`, `via: sdk`,
> `via: openai`, or `via: deepagents` sends prompt data to that model provider
> endpoint (Anthropic/OpenAI or your configured gateway). Use only approved
> endpoints and scan targets you are authorized to process.

**Docs:** [docs/](docs/README.md) — full documentation index ·
[SETUP_GUIDE.md](docs/SETUP_GUIDE.md) — install & configuration ·
[USER_GUIDE.md](docs/USER_GUIDE.md) — commands & options ·
[models.md](docs/models.md) — model/backend selection ·
[remediation.md](docs/remediation.md) · [validation.md](docs/validation.md) ·
[Project Glasswing white paper](https://corporate.visa.com/content/dam/VCOM/corporate/visa-perspectives/security-and-trust/documents/project-glasswing.pdf) — technical background.

---

## What's new in 1.4

- **Exploit verification (S6)** — VVAH can now prove a finding is exploitable by
  attacking it with real HTTP traffic, so a confirmed finding arrives with
  evidence attached instead of waiting on a human to reproduce it. That is a
  direct move on MTTA: confirming exploitability is usually the slowest manual
  step between an AI-discovered weakness and a validated fix. Additive and
  positive-only — it never drops a finding, and the static verifier keeps the
  verdict. Beta, API-only, localhost-only, and off unless
  `EV_API_COLLECTION` is set — see
  [Exploit verification](#exploit-verification-s6--beta-api-only) below for
  the full safety constraints.
- **`vvaharness ev-replay`** — regression-test your fix with the exploit that
  found the bug. After you patch and redeploy, replay re-runs the confirmed
  attack against the target and tells you whether it still lands — a regression
  test derived from the attack itself, not from a guess about it. We are not
  aware of another open-source harness that closes that loop.
- **`--stop-after ev`** — validate a collection and target with no model spend
- **Exploit-verification credentials** — EV's own auth credentials are read only
  from `EV_AUTH_*` environment variables, never from a profile or a CLI flag, and
  a collection may name the auth *scheme* but never a value. Other secrets can
  still reach the target on the wire: a token saved inside the collection's own
  requests, the client-key passphrase `EV_TARGET_CLIENT_KEY_PASSPHRASE`, and any
  hardcoded credential the attacker agent finds in the repo and replays.

---

## Features

- **From detection to a graded fix** — the S0–S11 pipeline combines threat-
  modeled discovery, deep-dive analysis, adversarial verification, reporting,
  remediation, and fix validation.
- **Threat-aware analysis** — threat modeling and multi-lens research focus review
  on the attack surface that matters.
- **Reachable-code analysis** — AST/call-graph seeding focuses model review on
  relevant code paths rather than the whole repo.
- **Real data-flow evidence** — interprocedural taint analysis complements
  model-based review across supported application languages.
- **Coverage backstop** — unrecognised files can be added to catch-all review
  chunks instead of being silently excluded. The backstop is best-effort, not a
  guarantee; see [docs/security.md](docs/security.md) for coverage guidance.
- **Proof, not just suspicion** *(Beta — API only)* — optional exploit
  verification attacks a candidate finding over live HTTP and reports back
  whether it is really exploitable, and `ev-replay` re-runs that same exploit
  after you ship the fix. Off unless you arm it; see
  [Exploit verification](#exploit-verification-s6--beta-api-only).
- **Actionable output** — produce Markdown and SARIF 2.1.0 reports with CVSS,
  CWE, and per-run diagnostics.
- **Your models and gateway** — use Anthropic or OpenAI-compatible models through
  `cli`, `sdk`, `openai`, or `deepagents` routes, configured per role.
- **Portfolio-scale operations** — scan CSV-defined repositories with resumable
  state and monitor long-running work through stderr output or the optional
  `--s6-progress-file` artifact.

See [docs/features.md](docs/features.md) for the full capability reference,
including backend and stage details, specialist lenses, taint analysis, and
limitations.

---

## Quick start

### Prerequisites

- Python 3.11 or newer.
- Permission to scan the target repository.
- One Anthropic credential for the packaged default profile:
  `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or `ANTHROPIC_SDK_API_KEY`.
  Claude Code CLI auth (run `claude`, then `/login`; or `claude setup-token`)
  is optional and needed only for a role you configure with `via: cli`; no
  shipped profile does.

Credential and profile details are in [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)
and [docs/models.md](docs/models.md).

### Install and configure

```bash
git clone https://github.com/visa/visa-vulnerability-agentic-harness VisaVulnerabilityAgenticHarness
cd VisaVulnerabilityAgenticHarness
```

**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

**Windows PowerShell**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
```

```bash
cp .env.example .env
$EDITOR .env                       # set an Anthropic credential
claude                              # optional: only for via: cli roles — /login in the REPL (or: claude setup-token)
```

`pipx install .` is an alternative. For platform-specific setup, TLS/proxy notes, editable installs, and profile selection, use [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md).

### Check the installation

```bash
vvaharness --version
vvaharness setup                    # readiness check; no model spend
vvaharness doctor                   # live backend check; spends model tokens
```

For the full configuration reference, see [docs/configuration.md](docs/configuration.md) and [docs/models.md](docs/models.md).

### Run your first scan

**Step 1** — Detection only, no code edits. Always start here:

```bash
vvaharness scan --repo /path/to/your/repo --stop-after s9
```

**Step 2** — Review the Markdown report and SARIF output in
`/path/to/your/repo/security-scan/`.

**Step 3 (optional)** — When ready, explicitly enable remediation in a scan.
This can edit source files:

```bash
vvaharness scan --repo /path/to/your/repo --remediate
```

The packaged default sets `step_remediate.enabled: false` and
`step_validate.enabled: false`. `--remediate` enables S10 only, not S11; run
standalone `validate` afterward to grade the fixes. In-scan S11 requires
`step_validate.enabled: true` in the effective config (no scan `--validate`
flag). Other configs or a local overlay can change these defaults; keep
`--stop-after s9` to explicitly skip S10/S11 with any profile.

Alternatively, after a detection-only run, remediate and validate independently:

```bash
vvaharness remediate --repo /path/to/your/repo --mode report-only  # propose only
vvaharness remediate --repo /path/to/your/repo                     # applies fixes
vvaharness validate --repo /path/to/your/repo                      # validate fixes
```

For command flags and troubleshooting, see [USER_GUIDE.md](docs/USER_GUIDE.md).

### Use with an AI agent (Claude / Copilot / Gemini)

```bash
vvaharness setup --install-agents
```

This writes `AGENTS.md` (cross-tool) and `.github/copilot-instructions.md`
(Copilot) unconditionally; when the `claude` CLI is detected it also writes
`CLAUDE.md` + a Claude skill in `~/.claude/skills/` (Claude Code), and when the
`gemini` CLI is detected it writes `GEMINI.md` (Gemini CLI). Existing files are
left untouched. See [docs/SKILLS.md](docs/SKILLS.md) for the analysis capabilities.


---

## Pipeline

VVAH implements an S0 static seed plus an eleven-stage workflow. The common
operator path is detection through S9. The shipped default profile disables
S10 remediation and S11 validation; `sdk` and `full` still enable both, while
`taint` also leaves them off. These stages remain available by explicit opt-in
or standalone commands.

| Stage group | Stages | Purpose |
|---|---|---|
| Static seed (optional) | S0 | Source/sink callgraph seed for taint-first scanning |
| Discovery & Modeling | S1–S3 | Attack surface mapping, threat modeling, hunting plan |
| Deep Dive & Verification | S4–S6 | Multi-lens research, policy gates, adversarial verification |
| Synthesis, Chaining & Reporting | S7–S9 | Deduplication, chain construction, SARIF emission |
| Remediation & Validation | S10–S11 | Candidate fixes and adversarial fix validation |

For stage-by-stage internals, see [docs/architecture.md](docs/architecture.md).
For every command and flag, see [docs/USER_GUIDE.md](docs/USER_GUIDE.md).

---

## Skills

The pipeline combines stage prompts, language-specific lenses, specialist
security lenses, remediation playbooks, and validation personas. See
[docs/SKILLS.md](docs/SKILLS.md) for the full capability inventory, and
[docs/features.md](docs/features.md) for how those capabilities are selected by
configuration.

---

## Exploit verification (S6) — Beta (API only)

**What you get.** Exploit verification proves a finding is really exploitable by
attacking it with live HTTP traffic, so the finding reaches you with evidence
attached rather than waiting in a queue for someone to reproduce it by hand.
That is aimed squarely at **MTTA**, VVAH's primary metric: for findings that map
to an endpoint, it removes the slowest manual step between an AI-discovered
weakness and a validated fix. It is **positive-only** and **additive** — a
confirmation is a fact you can act on, a non-confirmation means *not proven*
(never *safe*), and nothing is ever dropped because EV could not reach it.

**And `ev-replay` closes the loop.** Once you have patched and redeployed,
`vvaharness ev-replay` re-runs the exploit that found the bug against the same
target — a regression test derived from the attack itself, not from a guess about
it. We are not aware of another open-source harness that does this.

**Now the constraints.** EV is an optional S6 add-on, in Beta. **"API only"**
means it needs a Postman/OpenAPI/Swagger collection and can verify only findings
that map to an HTTP endpoint; off-wire classes stay SAST-only. It is off by
default — it arms when `EV_API_COLLECTION` is set (including a stale value left
in `.env`), with no CLI flag. It is **not a sandbox**: it sends real HTTP
requests (`POST` always, and `PUT`/`PATCH` on every shipped profile) to a live
target, and a reachability pass calls **every distinct path in your collection**
with its example body — downgrading any method the run has not opted into to
`OPTIONS`, so a `DELETE` route is never actually exercised there — before any
finding is selected, so arming it is live traffic even when nothing maps to an
endpoint. Its destination is pinned in code to a localhost/loopback host —
enforced in code rather than left to convention — which establishes where EV
sends, not what is listening there, so pointing it only at a disposable local
instance you are authorized to attack is the operator's job. See
[docs/exploit-verification.md](docs/exploit-verification.md) for supported collections, safety
rules, and setup, and the [Limitations](#limitations-read-before-you-trust-output) note below.

---

## Output

Per target, under `<target>/security-scan/`:

- `findings.json` — typed `FinalReport` JSON
- `<module>_<ts>_report.md` — findings + dropped-findings appendix
- `<module>_<ts>_report.sarif` — SARIF 2.1.0
- `<module>_<ts>_errors.jsonl` — non-fatal errors, written only when one is logged

With S10 enabled by config or `--remediate`, a successful remediation session
can also write `<target>/security-remediation/<NN_slug>/finding_case.json` and
**edit source files in the target repo** (fix mode — see
[Run your first scan](#run-your-first-scan)). The packaged default skips S10/S11;
`--stop-after s9` explicitly skips them with any profile.
A timestamped `run_manifest_*.json` is written to the working directory.

Pipeline checkpoints and resume state are kept **outside** the scanned repo, in
a SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db` (default
`~/.vvaharness/state/`); prune old runs with `vvaharness gc`.

For report, SARIF, `findings.json`, remediation, validation, and manifest
schemas, see [docs/outputs.md](docs/outputs.md).

---

## Limitations (read before you trust output)

- **LLM-generated, non-deterministic.** Findings and fixes are triage candidates,
  not confirmed vulnerabilities or production-ready patches. Human review is
  required, and runs may differ.
- **No compilation or execution.** VVAH reads the target and does not build,
  run, or test it; findings are never confirmed by execution. No shipped profile
  grants the agent `Bash`. Exploit verification is the one component that
  generates traffic, and only against a target you are already running.
- **No published accuracy numbers yet.** Precision and recall have not been
  published.
- **Coverage is bounded, not complete.** Stage caps, failed or timed-out chunks,
  unsupported languages, and non-path-sensitive taint analysis can leave code
  unreviewed. See [docs/security.md](docs/security.md) for coverage guidance.
- **Enabled remediation modifies the target.** The `default` and `taint`
  profiles disable S10/S11; `full` and `sdk` still enable them. `--remediate`
  enables S10 only. Use `--stop-after s9` to explicitly skip both stages with
  any profile.
- **Review remediation fixes before you rely on them.** VVAH does not build or
  test patched code; review and test generated fixes before merging.
- **Elevated privilege.** Run VVAH only against authorized, trusted repositories;
  prompt data may expose sensitive files or credentials to configured providers.
- **Exploit verification (S6) is Beta, API only, and localhost-only.** It exists to remove the
  slowest manual step in triage — proving a finding is really exploitable — and
  the price of that evidence is live attack traffic, so it is a trade to make
  deliberately rather than by accident. When armed it sends real
  HTTP requests — `POST` always, plus state-changing methods on every shipped
  profile — to a running target; its destination is pinned in code to a localhost
  address, which fixes where it sends but not what is listening there, so
  confirming the target is yours to do. "API only" means it works from a
  Postman/OpenAPI/Swagger collection you supply and skips any finding with no
  endpoint in that collection. It is positive-only — a non-confirmation is *not
  proven*, not *safe* — and some classes need manual review. See
  [`docs/security.md` → Execution boundary](docs/security.md#execution-boundary)
  and [`docs/exploit-verification.md` → What needs manual validation](docs/exploit-verification.md#what-needs-manual-validation-and-what-you-get).
- **Token-hungry.** There is no global spend cap. Run `vvaharness estimate` first
  and scope large scans; see [docs/configuration.md](docs/configuration.md).

See [docs/features.md](docs/features.md) and [docs/security.md](docs/security.md)
for the complete limitations and safety model.

---
## Learn more

- [Visa Perspectives announcement](https://corporate.visa.com/en/sites/visa-perspectives/newsroom/visa-vulnerability-agentic-harness-expanded.html)
  — the public VVAH announcement.
- [Project Glasswing white paper](https://corporate.visa.com/content/dam/VCOM/corporate/visa-perspectives/security-and-trust/documents/project-glasswing.pdf)
  — technical background on the approach behind VVAH.

---

## Security

Report vulnerabilities responsibly through the private channels in
[SECURITY.md](SECURITY.md). The public issue tracker is open for bug,
documentation, setup, and feature-request reports — never for security vulnerabilities.

---

## Reporting issues

Bugs, documentation, setup, and feature requests go
through the issue forms in `.github/ISSUE_TEMPLATE/` (blank issues are
disabled). See reporter guidance in
[`docs/contributor-issue-guide.md`](docs/contributor-issue-guide.md). Report
security vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).

---

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Copyright 2026 Visa, Inc.

Third-party dependencies are installed from PyPI at install time (not bundled
in this repository); their licenses are inventoried in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

See [CHANGELOG.md](CHANGELOG.md) for release history.
