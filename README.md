# Praise LLM Assistant

Personal backup of Praise's **OMP-based bug bounty and authorized pentesting workflow**. Intended destination: the private repository [sosarollie/praise-LLM-Assistant](https://github.com/sosarollie/praise-LLM-Assistant).

This is the existing working configuration, not a new autonomous pentest product. It preserves the assistant, role prompts, model router, skills, local analysis tools, and public prior-art corpus. It does not authorize testing any target.

## Included and excluded

| Included | What is preserved |
|---|---|
| OMP 18.6.1 | Exact Linux x86_64 executable and both installed native modules |
| uv 0.12.0 | Exact `uv` and `uvx` executables |
| Assistant configuration | `config.yml`, `RULES.md`, `crew-router.js`, and ten local pentest role prompts |
| Skills | Six OMP security skills, 22 shared engineering skills, one workspace operator skill, and their supporting assets |
| Engagement workspace setup | Root `AGENTS.md` and `.agents` configuration/skill; no target directories |
| Frame 0.0.1 | Complete local source snapshot at `f477e2836667dbd5f13d94ad66ee5d9d54b74b23`, including tests, benchmarks, license, and scanner extra |
| Visa vulnerability agentic harness 1.4.0 | Complete local source snapshot at `287e735b182b11ecdf8de7422b4e70d6ad8bc03a`, including rules, validation assets, tests, documentation, license, and notice |
| HackerOne prior art | Installed public report CSV, top-report lists, and our local `h1_query.py` wrapper |
| Dependency state | Exact versions of the three installed Frame dependencies and 78 installed Visa harness dependencies; installation receipts and Python version |

**Explicitly excluded:** Agentic Bug Hunter and CyberStrike. CyberStrike remains a separate local solution. No replacement for Agentic Bug Hunter is implemented here.

Also excluded: provider/GitHub credentials, OAuth tokens, authentication databases, private keys, shell history, OMP sessions and caches, target logs, PoCs tied to engagements, captured traffic, evidence, and findings. The publicly disclosed HackerOne corpus is not private engagement evidence.

The operator skill is preserved as historical local documentation. It mentions optional platforms, including the excluded products and paths that are not installed on this machine. Those references are not bundled implementations or install instructions executed by this project's importer. ARES, CyberStrikeAI, and Cairn are not included.

## Repository layout

```text
home/                         Credential-free mirror of selected /home/kali files
  .omp/agent/                 OMP configuration, rules, roles, router, security skills
  .agents/                    Shared engineering skills and their provenance lock
  pentest-workspace/          Workspace instructions and operator skill
sources/
  frame/                      Preserved Frame source and upstream assets
  vvaharness/                 Preserved Visa harness source and upstream assets
requirements/
  frame.txt                   Installed dependency pins, excluding the root package
  vvaharness.txt              Installed dependency pins, excluding the root package
provenance/                   Original uv receipts and Python environment metadata
runtime/linux-x64/            Compressed exact-runtime archive split into 48 MiB parts
snapshot.json                 SHA-256 hashes, file modes, restore destinations, versions
scripts/restore.py            Verify and restore the snapshot
```

The runtime is split because the original executables/native modules exceed GitHub's per-file limits. These are real binary contents, not Git LFS pointers. Keep all six parts together. The compressed runtime occupies approximately 271 MiB; restore also needs temporary space for decompression and Python dependencies.

## How the crew works

```text
Scoped engagement -> planning + recon/source discovery
                  -> cheap candidate gate
                  -> minimal proof (or gated chain escalation)
                  -> different-family skeptical verdict
                  -> report

Patch supplied -> adversarial patch validation -> acceptance decision
```

Candidates are not confirmed findings. A dropped candidate does not enter the proof lane. Deep source analysis and complex proof work receive a specific unresolved gap, not an unrestricted repeat of the original sweep.

`home/.omp/agent/extensions/crew-router.js` selects a crew role from the task description and pins its model before spawning. This pinning **takes precedence over** `task.agentModelOverrides` in `config.yml`. The snapshot preserves both mappings. Restart OMP or use `/reload` after changing the router; already-running children retain their current models.

### Pentesting roles

Models in this table use the `opencode-go/` provider unless explicitly qualified otherwise. Reasoning levels are part of the selectors, not claims about the models actually serving future requests.

| Role | Responsibility | Primary configured model |
|---|---|---|
| `pentest-scout` | Broad scoped reconnaissance and candidate generation; never a verdict | `space-bunny-free:high` |
| `pentest-planner` | Ranked hypotheses, coverage, and engagement plans | `deepseek-v4.1-flash:high` |
| `pentest-finder` | Primary source discovery and input-to-sink traces | `deepseek-v4.1-flash:high` |
| `pentest-finder-deep` | Bounded unresolved cross-file analysis after the ordinary pass | `deepseek-v4-pro:max` |
| `pentest-verifier` | Mechanical pass/drop gate before costly proof work | `mimo-v2.6-flash:high` |
| `pentest-exploiter` | Minimal working proof for a gated, reachable candidate | `deepseek-v4-pro:high` |
| `pentest-exploiter-deep` | Gated multi-step proofs and attack chains | `deepseek-v4-pro:max` |
| `pentest-skeptic` | Routine evidence-backed finding verdict | `glm-5.3-flash:high` |
| `pentest-skeptic-deep` | Disputed severity, chain adjudication, or final second opinion | `glm-5.2:max` |
| `pentest-tester` | Independent production exploitability and patch validation | `glm-5.3-flash:high` |

Supporting mappings: generic `scout` uses `muse-spark-1.3-contributor:low`; `sonic` uses `space-bunny-free:low`; generic `task` is pinned to `space-bunny-free:high`. The bundled `security-reviewer` uses `openai-codex/gpt-daybreak-blue-latest:high` for bounded defensive source review; analysis is not a final independent verdict.

The ordinary skeptic and tester can select Mimo Flash or Grok 4.7 instead of GLM Flash when needed for parent-family separation. The deep skeptic can select Grok 4.7 instead of GLM 5.2. The router blocks an independent checker if no different-family selector is available. The checker must also compare its **observed** model against the actual finding producer recorded in the engagement log. DeepSeek Flash and Pro are one family; escalation from Flash to Pro is not independent validation.

### General model configuration versus the pentest lead

The saved general OMP roles are:

- `default`: `openai-codex/gpt-6.1-sol:max`
- `smol`: `opencode-go/longcat-2.5-preview-free:high`
- `plan`: `opencode-go/deepseek-v4.1-flash:high`
- `slow`: `opencode-go/deepseek-v4-pro:max`

These are preserved exactly; the backup does not silently change defaults. No explicit Sol selector is assigned to a pentest crew role. For the documented pentesting lead workflow, launch Daybreak Blue explicitly as shown below. Model availability, account entitlement, and upstream aliases can change independently of this snapshot.

`providers.maxInFlightRequests.openai-codex: 3` is a shared provider request cap, not a three-agent limit and not extra subscription capacity. The rules require bounded batches, `omp usage --redact` before/after a batch, and an operating target of at least 20% remaining in active quota windows. None of this permits more target traffic or broader scope.

## Skills

Skills are on-demand instructions and supporting assets. Loading one does not mean a scanner runs automatically, an account is authenticated, or a finding is proven.

### Security workflow skills

Location: `home/.omp/agent/skills/`.

| Skill | Purpose |
|---|---|
| `bounty-report` | Authorization/scope gate, non-destructive testing, evidence, severity, and report workflow |
| `agents-chat` | Append-only per-engagement coordination and evidence-index protocol |
| `frame-scan` | Use Frame's symbolic reasoning, local SAST, taint/entailment checks, and bounded proof paths |
| `vvaharness-scan` | Operate Visa's staged repository analysis, remediation, and validation pipeline |
| `hackerone-prior-art` | Query disclosed reports for duplicate/prior-art and payout calibration; estimates are not guarantees |
| `vva-validation-scoring` | Four-gate adversarial patch validation and scoring |

The query wrapper and corpus are included, not merely linked. Frame/Visa rules, prompts, package data, and remediation policies are preserved with their source snapshots.

### Engineering and communication skills

Location: `home/.agents/skills/`.

| Skill | Purpose |
|---|---|
| `caveman` | Terse, fact-focused responses |
| `caveman-commit` | Intent-focused Conventional Commits messages |
| `caveman-compress` | Compress memory and instruction files |
| `caveman-discover` | Identify LLM workflows and spending categories |
| `caveman-evidence-review` | Inspect cost, traces, latency, routing, and errors |
| `caveman-explore` | Read-only code localization |
| `caveman-help` | Explain Caveman modes and commands |
| `caveman-learn` | Identify and reduce token-cost sinks |
| `caveman-manage` | Controlled experiment approval, promotion, and rollback |
| `caveman-optimize` | Evaluate approved optimizations against baselines |
| `caveman-review` | Concise diff/PR review |
| `caveman-setup` | Configure spend observability |
| `caveman-stats` | Inspect current-session usage and cache behavior |
| `cavecrew` | Delegation guidance for code location, implementation, and review |
| `find-skills` | Find and install relevant skills |
| `investigate-first` | Diagnose from evidence before editing |
| `lean-build` | Keep new behavior narrow and complete |
| `migration` | Reversible configuration/data/API transitions |
| `safe-refactor` | Preserve behavior during restructuring |
| `surgical-patch` | Targeted fixes with regression proof |
| `verify-and-stop` | Focused acceptance checks without scope growth |
| `simplified-technical-english` | Controlled, plain technical documentation |

The workspace's `offsec-assistant` skill is an operator/environment reference originally written for Gemini. It is preserved under `home/pentest-workspace/.agents/skills/`, including its historical tool references. Current standing authorization and safety rules take precedence over permissive assumptions or legacy examples in that file.

## Import / restore

### Prerequisites

- Linux x86_64 with glibc, as on the original Kali installation. The included runtime is not a macOS/Windows/ARM build.
- Git and Python **3.11 or newer** to run the importer.
- Several GiB of free space for the repository, runtime staging, and dependencies.
- GitHub access to this private repository. `gh` is convenient but not part of the assistant runtime backup.
- Internet access for pinned Python dependencies and, if missing, CPython 3.13.12. The importer restores the bundled OMP/uv binaries without downloading current replacements.

### 1. Clone and verify

```bash
gh auth login --hostname github.com --git-protocol https --web
gh repo view sosarollie/praise-LLM-Assistant --json visibility,viewerPermission
# Require visibility PRIVATE before uploading future backups.
gh repo clone sosarollie/praise-LLM-Assistant
cd praise-LLM-Assistant
python3 scripts/restore.py --verify-only
```

Alternatively, clone with Git using your own configured HTTPS credential helper or SSH authentication. Do not put a token in a clone URL.

Verification checks SHA-256 for every captured file, all archive parts, and each unpacked runtime member. It detects corruption; it is not a digital signature or a substitute for trusting the repository owner.

### 2. Restore the assistant and tools

For the original account/home layout:

```bash
python3 scripts/restore.py --home /home/kali
export PATH="$HOME/.local/bin:$PATH"
omp --version
frame --help
vvaharness --help
```

This restores the saved files/modes and exact binaries. It installs Frame with its `[scan]` extra and Visa's harness from the **included local sources**, using the captured dependency versions and CPython 3.13.12. Sources are placed under `~/.local/share/praise-LLM-Assistant/sources/`; uv creates isolated tool environments and launchers under `~/.local/share/uv/tools/` and `~/.local/bin/`.

For another Linux account, use:

```bash
python3 scripts/restore.py --home "$HOME"
```

The original snapshots in the repository remain byte-identical. During restoration to a different home, occurrences of `/home/kali` in assistant configuration/instructions are relocated to the requested home. Tool source files are not rewritten. For byte-identical deployed assistant files, use the original `/home/kali` layout.

A clean home is the closest reproduction. The importer does not delete unrelated files or prune extra existing agents/skills. Differing existing files cause a preflight refusal before snapshot files are replaced. To explicitly replace them:

```bash
python3 scripts/restore.py --home "$HOME" --overwrite
```

Changed existing files are saved first under `~/.local/state/praise-LLM-Assistant/restore-backups/<UTC timestamp>/` with their original relative paths. Restore an individual saved file to its corresponding home path to undo that replacement. New files and uv tool installs are not automatically rolled back. `--overwrite` also authorizes uv to replace an existing installation of the two tools. Existing provider credentials are neither imported nor overwritten.

Offline/configuration-only restoration:

```bash
python3 scripts/restore.py --home "$HOME" --skip-tools
```

This is intentionally not a complete Python-tool installation. Rerun without `--skip-tools` when package access is available. Installation errors are reported rather than treated as a successful import.

### 3. Authenticate separately

```bash
omp login openai-codex
omp login opencode-go
omp usage --redact
```

Use your own Codex/OpenCode Go account entitlements. Provider credentials and OAuth state were intentionally not committed. An old chat/session cannot be resumed from this repository.

Frame/Visa's external LLM-assisted modes have their own backend configuration requirements; see the preserved `frame-scan` and `vvaharness-scan` skills and upstream tool documentation. OMP login is not an automatic credential bridge to those tools. Keep any API keys in your local environment/credential store, never this repository.

### 4. Launch a real engagement

```bash
# Only after identifying a real program, its scope, and authorized accounts:
mkdir -p "$HOME/pentest-workspace/REAL-ENGAGEMENT/evidence"
omp --cwd "$HOME/pentest-workspace/REAL-ENGAGEMENT" \
  --model openai-codex/gpt-daybreak-blue-latest --thinking high
```

Replace `REAL-ENGAGEMENT` with the actual program/scope boundary; do not initialize placeholder or global logs. Read the workspace instructions and `agents-chat` skill, then record the program, assets, and in-scope basis before active testing. Each child receives the absolute engagement directory, log path, evidence path, and authorized scope. Use observed model identifiers in the log; never assume a requested selector proves the producer's identity.

No denial-of-service, persistence, bulk data access, credential reuse, or out-of-scope probing. Minimal proofs must reproduce twice from a clean state before reporting. The README's setup commands do not change these boundaries.

### 5. Check the imported surface

```bash
omp --version
python3 "$HOME/.omp/agent/skills/hackerone-prior-art/h1_query.py" stats --type IDOR
frame --help
vvaharness --help
```

These are local checks, not target scans. Confirm OMP reports version 18.6.1, the public corpus loads, and both tool CLIs start. The ten custom role prompt files are restored under `~/.omp/agent/agents/`; OMP discovers them when starting the task subsystem. A real provider-backed engagement still requires fresh authentication and scope; no live pentest is part of the backup verification.

### Verification performed for this snapshot

- Complete import into a clean, isolated home; Frame and Visa's harness both installed and their actual CLI entrypoints ran.
- All three Frame and 78 Visa harness dependency versions matched the original environments.
- Frame's documented separation-logic example returned `VALID`; the local corpus loaded 10,212 disclosed reports.
- Hash verification covered 1,648 captured files, six archive parts, and five exact runtime files. Actual local OMP credential values were absent from the captured files and runtime bytes.
- Existing-file conflicts refused restoration before copying any runtime files; explicit overwrite preserved the prior file and relocated paths; a repeated import changed zero files.
- The restored router's proof lane and different-family checker selection were exercised locally. No provider-backed model turn or live target test was performed.
- Gitleaks 8.30.1 raised 29 matches in synthetic test fixtures. All 14 implicated files were SHA-256-identical to their exact public upstream commits; the fixtures were retained unchanged, not hidden with scanner exceptions.

A credential-free OMP installation correctly refuses model-backed startup until login or API-key configuration is supplied. The importer does not fake or restore authentication.


## Fidelity limits

This is an application/workflow snapshot, **not a disk image**. Assistant bytes, source snapshots, runtime bytes, modes, versions, and dependency pins are preserved. It does not reproduce the OS/kernel, every system pentest binary, shell customization, browser profile, provider accounts, model availability, local engagement records, or existing sessions. Python dependencies are version-pinned rather than vendored as an offline wheelhouse. The importer relocates source installation paths and regenerates uv environments/entrypoints instead of copying virtualenvs tied to the old machine.

## Upstream attribution and licenses

- [OMP / oh-my-pi](https://github.com/can1357/oh-my-pi): assistant runtime; [official site](https://omp.sh/).
- [uv](https://github.com/astral-sh/uv): Python tool installer/runtime executables.
- [Frame](https://github.com/lambdasec/frame): Apache-2.0; preserved `sources/frame/LICENSE`.
- [Visa vulnerability agentic harness](https://github.com/visa/visa-vulnerability-agentic-harness): Apache-2.0; preserved `LICENSE`, `NOTICE`, and third-party notices in its source directory.
- [InsiderPhD/hackerone-reports](https://github.com/InsiderPhD/hackerone-reports): publicly disclosed report metadata snapshot; individual reports retain their authorship and platform terms.
- [Caveman](https://github.com/JuliusBrussee/caveman) and the sources recorded in `home/.agents/.skill-lock.json`: installed engineering skills.

Third-party source/license notices are retained; this personal backup does not relicense them. Keep the repository private and do not enable Pages or public artifact publication.
