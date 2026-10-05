# PraiseAssistant

Evidence-driven orchestration for authorized bug bounty, penetration testing, and source review. PraiseAssistant combines an executable control CLI with an OMP multi-agent crew: explicit work stages, scoped requests, durable case state, shared communication, independent judgment, and reviewed workflow memory.

It does not grant authorization, guarantee vulnerability discovery, train model weights, or replace an operating-system sandbox. Findings are not confirmed merely because a scanner or another agent calls them verified.

## Architecture

```text
Authorization + scoped engagement
              |
       Plan and discovery
              |
   Evidence normalization + gate
              |
       Controlled proof
              |
 Independent artifact-based judgment
              |
            Report

Closed case -> lesson proposal -> paired evaluation
            -> independent approval -> retrieval or rollback

A supplied patch takes a separate validation path.
```

- **One control plane.** PraiseAssistant owns stage transitions, evidence integrity, request policy, and confirmation readiness.
- **One role catalog.** `praiseassistant/roles.json` defines stage assignments and configured model selectors. Installation generates the OMP catalog and overrides from it.
- **Explicit scheduling.** Task metadata selects the stage. Words such as “proof,” “duplicate,” or “independent review” inside a task cannot silently select another lane.
- **Proof before reporting, not before discovery.** A credible source candidate can reach the gate without runtime reproduction. Confirmation requires two distinct clean-state reproductions and a different-family judgment.
- **Local helpers are optional.** Their outputs enter the same evidence contract; they are neither shipped dependencies nor final authorities.

## Agentic role distribution

The lead is the top-level session. Workers have bounded contracts and do not inherit permission to expand scope.

| Stage / role | Responsibility | Configured primary selector |
|---|---|---|
| Lead | Scope, scheduling, coverage, synthesis, report | `openai-codex/gpt-daybreak-blue-latest:high` |
| `plan` / `pentest-planner` | Ranked hypotheses and falsification tests | `openai-codex/gpt-daybreak-blue-latest:high` |
| `recon` / `pentest-scout` | Scoped surface mapping and candidates | `opencode-go/deepseek-v4.1-flash:high` |
| `discover` / `pentest-finder` | Source paths and violated trust/ownership invariants | `opencode-go/deepseek-v4.1-flash:high` |
| `gate` / `pentest-verifier` | Evidence and reachability sanity gate; no final verdict | `opencode-go/mimo-v2.6-flash:high` |
| `proof` / `pentest-exploiter` | Minimal controlled reproduction of gated cases | `opencode-go/deepseek-v4-pro:high` |
| `verdict` / `pentest-skeptic` | Re-derive impact, check duplicates, judge artifacts | `opencode-go/glm-5.3-flash:high` |
| `patch` / `pentest-tester` | Validate an existing fix and alternate paths | `opencode-go/glm-5.3-flash:high` |
| `pentest-finder-deep` | Explicitly escalated unresolved source analysis | `opencode-go/deepseek-v4-pro:max` |
| `pentest-exploiter-deep` | Explicitly escalated complex proof | `opencode-go/deepseek-v4-pro:max` |
| `pentest-skeptic-deep` | Explicitly escalated disputed judgment | `openai-codex/gpt-daybreak-blue-latest:max` |
| `security-reviewer` | Bounded defensive source review, not final confirmation | `openai-codex/gpt-daybreak-blue-latest:high` |

Routine judgment and patch lanes have Mimo/GPT-6.1-Sol alternates; escalated judgment has a GPT-6.1-Sol alternate. Selection excludes actual recorded producer families rather than assuming the spawning lead produced the finding, and fails closed when no listed selector is outside those families. DeepSeek Flash/Pro share a family, as do GPT-family selectors. A configured selector is not proof of the model that served a request: each worker records its observed identity.

Model availability and account entitlement are external prerequisites. There is no silent substitution or claim that these assignments have superior measured recall. Generic coding tasks outside an initialized engagement keep the normal OMP workflow.

## Evidence and case states

Each engagement holds its own scope, structured database, human-readable chat, and evidence:

```text
<engagement>/
  scope.json
  state.sqlite3
  agentschat.md
  evidence/
```

Operational files belong outside this repository and are ignored by version control.

The normal path is **candidate -> gated -> reproduced -> confirmed**. Held, rejected, and duplicate cases retain their history. A gate accepts concrete evidence plus a source/sink path or a named violated boundary invariant; it does not demand a finished exploit first.

Final confirmation checks distinct clean-state IDs, reproduction artifacts, current evidence hashes, and a known checker family different from the recorded producers. Missing or changed evidence blocks confirmation. The database is authoritative; prose in chat cannot advance a case by itself. Model identifiers and clean-state descriptions are operational attestations, not cryptographic proof of identity or environment reset.

Patch validation uses four evidence-backed gates: `root_cause`, `instance_coverage`, `no_new_vulnerabilities`, and `security_best_practices`. All must pass for a fixed result. An unevaluated or failed security gate cannot be hidden by a high weighted score.

## Multi-agent communication

`agentschat.md` is the human-readable projection of serialized structured messages. Every message carries the engagement identity, an ordered sequence number, UTC time, role, observed model identity, an evidence reference when relevant, and an **ask** or **close**.

Use the `praiseassistant_chat` tool in an OMP engagement. CLI operators can use:

```sh
praiseassistant --engagement "$ENGAGEMENT" chat \
  --role pentest-finder --model "$OBSERVED_MODEL" \
  --summary 'Candidate has an evidence-backed cross-tenant boundary path.' \
  --ask 'Gate the candidate before assigning proof work.' \
  --evidence source-trace.json
```

Evidence references are relative to that engagement's `evidence/` directory. Keep raw output and real user data out of chat. Workers receive scoped case state, recent communication, and approved lessons as **data**, not authority to override safety rules.

To schedule a worker through OMP's task tool, begin its task with a single metadata line:

```text
PraiseAssistant-Task: {"stage":"discover","engagement_dir":"/absolute/engagement/path","escalated":false}
Trace the authorized source path and record the evidence-backed candidate.
```

Proof, judgment, and patch tasks also carry `candidate_id`. Escalation requires an explicit unresolved reason. The integration validates scheduling through the CLI before choosing the worker and model.

## Self-learning methods

Learning is reviewed workflow memory, not unsupervised self-modification:

1. **Observe:** propose a bounded technical lesson from a closed, evidence-backed case.
2. **Evaluate:** compare matched baseline/learned cases, including positive and negative controls. Require improvement without newly introduced misses or false positives.
3. **Promote:** a different-family reviewer explicitly approves a passing evaluation with current artifacts.
4. **Retrieve:** active lessons become bounded context for future work; the control policy remains authoritative.
5. **Rollback:** deactivate an unhelpful lesson without deleting its history.

The `learn` CLI and `praiseassistant_learning` tool implement this lifecycle. Paired results are recorded evaluation evidence; the program does not certify an arbitrary evaluator's claims. Helper output, source comments, chat, and lessons never automatically edit scopes, credentials, role definitions, safety instructions, or model weights.

## Installation

### Prerequisites

- Python **3.11 or newer** on Linux.
- Git and access to this repository.
- OMP; the integration is exercised against **18.6.1**. Authenticate your own providers separately.
- Available model selectors matching your catalog, or an explicitly updated catalog.

PraiseAssistant's runtime uses only the Python standard library. Packaging uses setuptools. No target data or provider credentials are distributed.

Install OMP using its [official installation guide](https://github.com/can1357/oh-my-pi#install), for example:

```sh
bun install -g @oh-my-pi/pi-coding-agent
```

### Install the program and crew

```sh
git clone https://github.com/sosarollie/praise-LLM-Assistant.git PraiseAssistant
cd PraiseAssistant
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .

python scripts/install.py --dry-run
python scripts/install.py
export PATH="$HOME/.local/bin:$PATH"
praiseassistant --help
```

The installer deploys owned roles, extension, workflow skills, security rules, and catalog under `~/.omp/agent/`, plus a CLI launcher under `~/.local/bin/`. It preserves unrelated settings and refuses differing owned files unless `--overwrite` is explicit:

```sh
python scripts/install.py --overwrite
```

Replacement preserves per-file backups and prints their location. Use another home directory for an isolated installation:

```sh
python scripts/install.py --home /absolute/test-home
```

Restore an installation using its printed backup path:

```sh
python scripts/install.py --restore-backup "$BACKUP"
```

For an isolated installation, also pass the same `--home /absolute/test-home` when restoring its backup. Rollback refuses destinations changed after installation rather than erasing new user work. Restart OMP or use `/reload`; running workers retain their existing extension/model state. The CLI launcher depends on the installed Python environment, so keep that environment available.

### Start an authorized engagement

Set these values only after the program authorizes the asset and test type:

```sh
export ENGAGEMENT="$HOME/pentest-workspace/authorized-program"
praiseassistant init --directory "$ENGAGEMENT" \
  --program 'Authorized program' \
  --basis 'Written scope and permitted test types' \
  --asset 'https://authorized.example/api/' \
  --mode blackbox --max-requests 50 --interval 1

omp --cwd "$ENGAGEMENT" \
  --model openai-codex/gpt-daybreak-blue-latest:high
```

The example hostname is reserved documentation data, not a target to probe. Modes are `blackbox`, `source`, `audit`, `patch`, and `development`. Local source scopes use explicit absolute directories. Only `GET` is allowed by default, with a **zero-request budget** until the operator explicitly sets one. Other methods need an explicit scoped allowance.

The scoped OMP integration exposes state, chat, transitions, learning, and controlled request tools. In `blackbox`, `source`, `audit`, and `patch` modes it blocks shell/eval/browser/direct remote reads and unknown execution bridges. `development` deliberately retains normal execution tools for trusted local implementation work; it is not a restricted target-testing mode. Controlled requests enforce exact origin/path boundaries, allowed methods, shared budgets/throttling, verified TLS, bounded response capture, and no automatic redirects/environment proxies.

Pass owned, explicitly provided credentials by **file reference**, not as model-visible values or command-line JSON: the request tool accepts `headers_file`, and the CLI accepts `--headers-file`. Keep that JSON file in a private, mode-`0600` location within the engagement's allowed local roots, for example `<engagement>/secrets/provided-account.json`. Do not use discovered credentials.

Captured request/response artifacts mask recognized secrets and supplied credential values on a best-effort basis. This is **not data-loss prevention**: inspect evidence before sharing it, minimize capture, and keep raw sensitive data private.

The extension is **not an OS sandbox**: a trusted operator can disable it, and untrusted applications need separate host/container network and filesystem restrictions. Capability restrictions do not prove a payload is non-destructive; the operator still owns authorization and minimal-impact testing.

## Development and verification

```sh
python -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/router.test.mjs
```

Tests cover consumer-visible boundaries: evidence integrity and transitions, scope/HTTP limits, routing and bypass guards, chat concurrency, learning approval/regression handling, and installation preservation/rollback. Live provider tests require your own authentication and are separate from deterministic regression tests.

## Repository layout

```text
praiseassistant/             CLI, state/control, learning, authoritative role catalog
home/.omp/agent/agents/      Bounded role contracts
home/.omp/agent/extensions/  OMP scheduling and capability integration
home/.omp/agent/skills/      Public workflow, communication, learning, patch guides
home/.omp/agent/RULES.md     Stack safety and evidence policy
scripts/install.py          Conflict-aware installation and rollback
tests/                      Deterministic behavioral regressions
```

Local dependencies, private evaluations, legacy archives, credentials, operational databases, chat, and engagement evidence are intentionally excluded. The repository contains the stack implementation and reproducible installation instructions, not a workstation image.

## Reporting discipline

Only independently confirmed cases are submission-ready. Include exact preconditions, clean reproduction steps, minimal redacted evidence, demonstrated impact, program-appropriate severity, and the relevant remediation invariant. Static-only conclusions must state their limitations. Keep duplicate causes together, respect every hop's scope, and never inflate severity to compensate for incomplete proof.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
