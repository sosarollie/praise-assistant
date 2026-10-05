---
name: vvaharness-scan
description: Run Visa's Vulnerability Agentic Harness (vvaharness) — a multi-stage LLM pipeline for autonomous vulnerability discovery, remediation, and fix validation with threat modeling, adversarial verification, dedup, and SARIF output. Use for deep source-code audits of a whole repo, triage of large codebases, or validating applied security patches.
---

# VVAH: Visa Vulnerability Agentic Harness

`vvaharness` (visa/visa-vulnerability-agentic-harness, v1.4.0) is installed as an
isolated `uv tool`; the CLI is `vvaharness` on `PATH`. It is an **agentic SAST
pipeline**, not a pattern matcher: a static seed, then LLM stages, then
deterministic dedup, then structured reporting.

Use it for whole-repo audits where Frame's symbolic tier is too narrow (authz,
business logic, design-level flaws), and for validating patches.

## Pipeline stages

| Stage | Name | What it does |
|---|---|---|
| S0 | static seed | Derives an initial model of the code (profiles `default`/`full` derive it from the LLM; `taint` uses operator-supplied source/sink YAML) |
| S1 | preprocess / recon | File inventory, call graph (LLM seed + regex supplement), entry points and sinks |
| S2 | threat modeling | STRIDE threats, assets, trust boundaries, baseline checklists |
| S3 | decompose | Taint chunks + catch-all sweep, specialist scoping |
| S4 | deep dive | Per-chunk vulnerability discovery + research lens (11 specialist + 42 language lenses) |
| S5 | pre-filter | Deterministic confidence/evidence gates |
| S6 | adversarial verify | Second-opinion reviewer; the false-positive suppressor |
| S7 | dedup | Semantic + deterministic dedup |
| S8 | exploit chain | Multi-hop chains, severity ranking |
| S9 | report | Markdown + SARIF 2.1.0 |
| S10 | remediate | Candidate fixes (opt-in; **edits source**) |
| S11 | validate | Adversarial validation panel on applied fixes (opt-in) |

`--stop-after {clone,ev,s0..s11}` truncates the run; `--remediate` enables S10
for that run; the packaged default stops at S9.

## Preflight

```bash
vvaharness doctor            # credentials + live backend connectivity (read-only)
vvaharness setup             # guided readiness; --write-env persists a .env
vvaharness estimate --repo /path/to/target   # rough scope/cost, spends nothing
```

`doctor` reports per-role blockers. Shipped profiles route detection through
`via: deepagents` on Anthropic models, so a full run needs
`ANTHROPIC_API_KEY` / `ANTHROPIC_SDK_API_KEY` / `ANTHROPIC_AUTH_TOKEN`;
`OPENAI_API_KEY` is required for roles switched to `provider: openai` (the
`full.yaml` exploit-verification judge ships that way). Exploit verification is
Beta, API-only, localhost-only, and off unless `EV_API_COLLECTION` is set.

## Standard workflow

1. **Cost-preview before spending.**
   ```bash
   vvaharness estimate --repo ./target
   ```

2. **Discovery run to S9.**
   ```bash
   vvaharness scan --repo ./target --application-id <asset-id> --stop-after s9
   ```
   `--repo-name` tags report filenames and SARIF `run.properties`.
   Batch mode: `--repo-file repos.txt` (one `app_id,repo_name,path` per line) or
   a CSV with `AppID,RepoName[,Path]`; `--group-by-app` runs one scan per
   application across its repos; `--workspace` sets the clone dir.

3. **Resume instead of restarting** after an interruption: `--resume`.

4. **Narrow the file set** rather than re-running blind: `--step1-config` overlay
   YAML (`exclude_dirs`/`exclude_exts`/`globs`, `max_file_kb`, `config_dedup`)
   APPENDs to `config.yaml`. `--auto-step1` lets the model derive that overlay;
   `--no-auto-step1` hard-disables it.

5. **Remediation is opt-in and writes to the repo** (`<repo>/security-remediation/`):
   ```bash
   vvaharness remediate --repo ./target --mode report-only   # proposes only, no edits
   vvaharness remediate --repo ./target --top 5 -i           # interactive picker, applies fixes
   vvaharness scan --repo ./target --remediate --top 5      # enables S10 inside the scan
   ```
   `--resume` skips findings already remediated; `-v` prints prompt + raw response.

6. **Validate applied fixes** with the S11 panel: `vvaharness validate --help`,
   alias `vvaharness s11`. Needs in-scan `step_validate.enabled: true`.

7. **Re-check a redeployed target** for exploit-verified findings:
   `vvaharness ev-replay` with `EV_TARGET_URL` + `EV_*` env from a run that had
   `EV_API_COLLECTION`.

## Configuration

`./config.yaml` if present, else the packaged default profile. Copy a shipped
profile as a starting point:

```bash
VVAH_PY="$(dirname "$(readlink -f "$(command -v vvaharness)")")/python"
VVAH_SITE="$("$VVAH_PY" -c 'import vvaharness, os; print(os.path.dirname(vvaharness.__file__))')"
cp "$VVAH_SITE/config/profiles/sdk.yaml" ./config.yaml
```

`config.local.yaml` is an optional overlay. Per-role model/provider routing is
the point of the design — see `docs/models.md` upstream.

## Output

Markdown + SARIF 2.1.0 under the run's state/checkpoint directory, with
`run.properties.applicationId` set from `--application-id`.

## Pitfalls

- Every model-driven role bills real tokens. `estimate` first, `--stop-after` when
  iterating, never `--remediate` on a target you cannot change.
- S10/S11 are disabled in the shipped default profile; a scan that "didn't
  remediate" is behaving as configured, not broken.
- Findings are LLM-generated triage candidates. S6 exists precisely because raw
  LLM findings are noisy — do not skip verification when writing anything up.
- Only scan code you own or are authorized to test; prompt data leaves to the
  configured provider endpoint.
- `vvaharness gc` prunes old checkpoint runs; use `--dry-run` first.
