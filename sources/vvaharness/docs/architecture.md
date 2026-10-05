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

# Architecture

Module map and data flow for the `vvaharness` package.

## Module layout

```
vvaharness/
  cli.py              — console entry point: setup / init / doctor / estimate /
                        gc / scan / remediate / validate / ev-replay;
                        loads .env, checks the Python floor, resolves --config
  orchestrator/       — pipeline driver package:
                        entry.py (argparse + main), scan.py (single-repo driver),
                        batch.py (clone + group-by-app), preflight.py (backend
                        configure/probe), checkpoints.py, store.py (SQLite
                        state store), cleanup.py, cmdb.py,
                        enrich_findings.py, config_paths.py,
                        findings_json.py (findings.json emitter), and the
                        case-ID subsystem (artifacts.py, case_ids.py,
                        case_rollup.py, sarif_ids.py)
  agentdoc.py         — AGENTS.md / CLAUDE.md / .github/copilot-instructions.md /
                        GEMINI.md / Claude skill text for `setup --install-agents`
  manifest.py         — run-level run_manifest_*.json (version, per-role model
                        entries — id/via/provider/resolved_route —
                        config/overlay hashes, target git SHA, arguments,
                        outcome, timing, per-stage tokens/cost)
  models/             — pydantic data contracts (ContextPackage, Finding, FinalReport, …)
  config/             — config loader (${ENV} expansion, local override, step1 overlays)
    profiles/         — bundled profiles: default.yaml (all roles via:deepagents/anthropic —
                        detection on claude-opus-4-7, preprocess on claude-sonnet-4-6,
                        remediate on claude-opus-4-8, validate on claude-opus-5
                        with claude-opus-4-8 personas),
                        sdk.yaml (all roles spelled via:sdk, s4 voting off), full.yaml (multi-backend example template — ships all roles via:deepagents, on Anthropic except its exploit-verification judge on provider:openai, the cross-vendor example; s4 voting on), taint.yaml (taint-first)
  pipeline/stages/    — the scan analysis stages:
                        s0_seed (static callgraph seed), s1_preprocess, s1_autoexclude, s2_threatmodel, s3_decompose,
                        s4_deepdive, s5_prefilter, s6_verify, s7_dedup, s8_chain,
                        s11_validate (thin wrapper hooking the validation/ package
                        into the pipeline)
    callgraph_engine/ — tree-sitter static seed engine (parser plugins for
                        Python/Java/C#/JavaScript/TypeScript/Go; typed taint
                        facts for Python/Java/C#/JavaScript/TypeScript, Go
                        reachability plus field/container facts only):
                        _scan.py    — per-file scanner; emits FileIndex containing
                                      call edges, taint facts, a reserved CFG field,
                                      reflection facts, and framework markers
                        _graph.py   — interprocedural call graph construction,
                                      reachability, and structured taint propagation
                        _annotator.py — spec derivation from observed call patterns
                        _rules.py   — rulepack loader (source/sink/sanitizer specs)
  pipeline/callgraph_consumer.py — shared read-only graph helpers used by S3 and
                        S5–S8; S2 and S4 consume ContextPackage AST views/spans
                        directly. The helpers index graph and seed facts per
                        ContextPackage
  remediation_agent/  — Step 10 (the `remediate` command / --remediate): proposes
                        and applies a minimal fix per verified finding and writes
                        per-finding DTOs under <repo>/security-remediation/
  validation/         — Step 11 (the `validate` command): DTO discovery (no
                        model spend) feeds the s11 agentic panel — two
                        always-on personas (security-architect and
                        penetration-tester), plus a cross-repo-analyzer the
                        orchestrator is instructed to spawn only when the fix
                        spans 2+ repos — scoring each DTO against weighted
                        fix-quality gates. Agents are read-only; host code
                        persists temporary artifacts and the DTO result
  exploit_verification/ — Step 6 exploit verification (EV, Beta; API-only, and
                        idle unless EV_API_COLLECTION names a collection). An
                        additive live-verify pass wired in through thin hooks
                        like S10/S11: gate.py (offline collection preflight),
                        probe.py (online reachability probe that runs before S0 — ahead of auto-exclude and any model spend), and
                        verify/router.py at the S6 call site, which routes
                        live-verifiable findings to the EV agent and the rest to
                        s6_verify. settings.py/options.py (the
                        step6_exploit_verification: block + EV_* env), auth,
                        safety.py (loopback-only target guard and the disclosure
                        redactor, both in code with no override),
                        collection/ (Postman / OpenAPI-Swagger parsers),
                        classify/ (finding → verify-category), mapping/
                        (finding → endpoint), payloads/ (per-subtype templates +
                        builder), executor/ (safety-gated HTTP send and the
                        http_request tool, plus oob.py, concurrency.py,
                        ratelimit.py), verify/ (agent, oracle, judge),
                        replay/ (the `ev-replay` command: re-send confirmed
                        exchanges at a redeployed target)
  (operator input)    — ./inputs/validator_hints.yaml (per-CWE bypass cheatsheets
                        injected into the validation session launch prompt)
  backends/           — model transports, one directory per family:
    llm/               — the detection dispatcher and its transports: modules
                        exposing prompt()/agentic() that return str
                        registry.py   — dispatcher; routes on `via:`, resolving the
                                        chosen backend's module on selection so
                                        picking one never imports another's SDK;
                                        `deepagents` is deliberately absent from
                                        its backend table (a stray registry call
                                        with a deepagents model fails loudly)
                        deepagents.py — the `via: deepagents` dispatch seam
                                        (dispatch_prompt/dispatch_agentic): each
                                        resolves `via` once, then either runs the
                                        DeepAgents harness (below) or delegates
                                        to registry.prompt/agentic unchanged
                        cli.py        — `claude` CLI subprocess (`via: cli`)
                        sdk.py        — Anthropic Python SDK (`via: sdk`)
                        openai.py     — OpenAI-compatible API (`via: openai`)
                        agent_sdk.py  — Claude Agent SDK backend for the mutating
                                        remediation `fix` role (delegated to from
                                        sdk.py under `via: sdk`); native
                                        Read/Glob/Grep/Edit/Write inside a
                                        deny-by-default (no-Bash) permission sandbox
                        tools.py      — sandboxed Read/Glob/Grep tool-loop for sdk/openai
                        tls.py        — string→bool coercion for `verify_ssl`
                        cache.py      — prompt-cache marker/route helpers
                        models.py     — the family's contract and shared tunables
    harness/           — the agentic S10/S11 family: a Harness ABC with async
                        typed-message streams. Claude Agent SDK for `via: cli`/
                        `via: sdk`, DeepAgents/LangGraph for `via: deepagents`,
                        with mode-specific filesystem permissions. Detection
                        roles spelled `via: deepagents` run on this same
                        harness, reached through llm/deepagents.py (never the
                        llm registry): a one-shot parser graph for
                        prompt()-shaped roles — the model is offered zero
                        tools — and the read-only streaming graph for the
                        agentic ones
  report/             — enrich.py (CVSS env scoring, CMDB, Markdown→SARIF),
                        cvss.py, cwe.py, redact.py (secret/PII redaction at write
                        time), rows.py (per-FindingCase render helpers)
  rules/              — S4 CWE knowledge base: bundles `generic.kb.yaml` (the
                        knowledge-base overlay S4 merges), families.py,
                        build_kb.py, generic_pack.py. Distinct from S0 source/sink
                        specs — the "no pack is bundled" note under Stages applies
                        only to those S0 specs, not to this KB
  injectors/          — cve_feed.py, design_controls.py (optional context loaders)
  util/               — environment (setup/doctor checks), tokens, metrics, errlog,
                        prompts, json_extract, status (progress spinner),
                        pricing (price-table loader), stage_telemetry,
                        response_quality, counters, logs, scan_progress, warn_once
  lang/               — language hints (hints.py: EXT_TO_LANG, LANG_HINTS,
                        SPECIALIST_HINTS) plus ts_graph.py (TypeScript/JavaScript
                        call-graph helper)
  api.py              — programmatic entry point (in-process scan API)

inputs/               — context inputs: *.example.* samples plus operator-editable
                       validator_hints.yaml / remediation_policy.yaml / remediation_playbook.yaml
scripts/              — developer helper scripts (not part of the installed package)
```

## Stages (data flow)

```
        repo  +  optional inputs (known_cves, design_controls, cmdb)
                              │
   s0 seed        ── Rules mode requires operator-supplied generated source/sink
                     YAML; no pack or heuristic baseline is bundled. Without
                     usable specs it returns an empty seed and later stages
                     continue. With external or LLM-derived specs, the AST
                     engine builds a callgraph and source→sink seed:
                     Python/Java/C#/JavaScript/TypeScript can emit typed taint
                     evidence (only Python/Java/C# also model response sinks);
                     Go emits call-graph reachability plus field/container
                     facts, with no interprocedural propagation facts;
                     unsupported languages emit no S0 seed.
                     • CFG boundary — the data model reserves CFG and
                       condition-gated transfer structures, but the current
                       scanner does not populate a branch CFG or perform
                       branch-/path-sensitive analysis
                     • Reflection detection — ReflectionFact records getMethod /
                       forName / invoke (Java), getattr / __import__ (Python),
                       GetMethod / Delegate.CreateDelegate (C#); ReflectionTaintEdge
                       propagates taint through dynamically resolved targets
                     • Framework lifecycle sources — FrameworkMarkerFact captures
                       @RequestParam / @PathVariable (Spring), request.GET/POST
                       (Django), [FromQuery] / [FromRoute] (ASP.NET); RouteTaintFact
                       models URL path-parameter bindings; ResponseDataflowFact
                       tracks flows to response sinks (JsonResponse, HttpResponse,
                       Ok, render); FrameworkTaintEdge propagates taint from
                       framework-managed entry points
                     • Transfer kinds: source / assign / arg_to_param /
                       return_to_local / local_to_sink / return_to_sink /
                       field_write / field_read / container_put / container_get /
                       sanitize / reflect / framework
                     • FileIndex fields: imports, functions, source_hits, sink_hits,
                       call_edges, observed_calls, assigns, returns, call_args,
                       field_writes, field_reads, container_writes, reserved cfgs,
                       reflection_facts, framework_markers, route_facts,
                       response_dataflow, bridge_signals
   s1 preprocess  ── repo survey, call graph ─────────► ContextPackage
   s2 threatmodel ── assets, trust boundaries, threats ─► ThreatModel
   s3 decompose   ── risk/taint/catch-all/specialist/threat-fallback chunks ► TaskManifest
   s4 deepdive    ── per-chunk findings (×N + vote) ───► Finding[]
   s5 prefilter   ── deterministic confidence/evidence gates; optional S5-b
                     semantic pre-dedup (reuses the `dedup` model) before S6
   s6 verify      ── adversarial TRUE/FALSE_POSITIVE + CVSS per finding
                     • when exploit verification is armed (EV_API_COLLECTION
                       set and the collection probed before S0), S6 routes
                       live-verifiable findings through
                       exploit_verification/verify/router.py first and the rest
                       to the static verifier — additive and positive-only
   s7 dedup       ── deterministic + semantic dedup ───► canonical Finding[]
   s8 chain       ── exploit-chain analysis + re-rank ─► FinalReport
   s9 SARIF       ── parse the Markdown report ────────► *_report.sarif
                              │
            <target>/security-scan/<module>_<ts>_report.{md,sarif}
              + <target>/security-scan/findings.json (the typed FinalReport)
              + <module>_<ts>_errors.jsonl only when an error was logged
                              │
   ingest upload  ── optional outbound network push, AFTER S9 ─► remote ingest hub
                     Gated on `output.ingest_url` **and** `output.ingest_token`
                     (env `VVAHARNESS_INGEST_URL` / `VVAHARNESS_INGEST_TOKEN`);
                     with either unset the upload is skipped. When configured,
                     `scan.py:_upload_to_ingest` POSTs the S9 Markdown report
                     and SARIF to the endpoint with the bearer token,
                     TLS-verified per `output.ingest_verify` — which `default.yaml`
                     ships as `false` while the other three profiles ship `true`,
                     so on the default profile the token travels to an unverified
                     endpoint unless you set it. A successful
                     upload is checkpointed so `--resume` does not re-send it.
                     Beyond the configured model endpoints, this is the only path
                     that sends scan output off the machine. It is not the only
                     outbound network activity: batch mode clones each repo from
                     `batch.git_base_url` using a token-bearing URL, and exploit
                     verification sends live requests to a loopback target.
                     See [security.md](security.md).
```

The standalone `vvaharness validate` command runs separately, over the
remediation DTOs the `remediate` command leaves under
`<repo>/security-remediation/<NN_slug>/finding_case.json`:

```
   remediation DTOs (validatable status, finding + evidence/diff.patch)
                              │
   discover       ── locate DTOs awaiting validation (no model spend)
  s11 panel      ── configured Harness backend — two always-on personas
              (security-architect + penetration-tester; + cross-repo-analyzer
               only when the fix spans 2+ repos) →
                     weighted gate scores → verdict
                              │
      host fills each DTO's `validation` block; state derives to validated |
      failed | open; temporary validation_report.json and
       synthesized_gates.json are consumed before the workspace is removed
```

Scan state is checkpointed in the SQLite DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`) — never
inside the scanned repo. S0–S6 have individual scan checkpoints. S7 retains
its S5/S6 outputs in the existing bundled checkpoint for compatibility, while
the additional S5 and S6 rows let an interrupted run continue at S6 or S7.
S8 and S9 are stored separately. Remediation and validation also store
per-finding resume records. `vvaharness scan --resume` reuses the available
completed work, and `vvaharness gc` prunes old runs. The whole scan is
summarised in cwd `run_manifest_*.json`.

## LLM transport layer

Optional S0 annotation, auto-step1, S1–S8 model calls, and non-DeepAgents S10
remediation calls go through
`backends/llm/registry.py`, which reads the per-role `{id, via, …}` node and dispatches
to one of three registered transports; a fourth `via` bypasses the registry
through the dispatch seam in `backends/llm/deepagents.py`:

| `via:` | Module | Transport |
|---|---|---|
| `sdk` | `backends/llm/sdk.py` | Anthropic Python SDK |
| `openai` | `backends/llm/openai.py` | OpenAI-compatible Chat Completions |
| `cli` | `backends/llm/cli.py` | `claude` CLI subprocess |
| `deepagents` | `backends/llm/deepagents.py` | DeepAgents harness — a one-shot parser graph for `prompt()`-shaped roles (the model is offered no tools) and the read-only streaming graph for `agentic()` ones. Not registered in the registry: stages call `dispatch_prompt`/`dispatch_agentic`, which resolve `via` once and delegate every other value to `registry.prompt`/`registry.agentic` unchanged; a direct registry call with a DeepAgents model is rejected |

The `deepagents` row is valid on the roles in `DEEPAGENTS_ROLES` in the
registry: `remediate`, `validate`,
`preprocess`, `autoexclude`, `threatmodel`, `decompose`, `deepdive`,
`verify`, `dedup`, `chain`, `graph_annotate`,
`exploit_verification.classify`, `exploit_verification.mapper`,
`exploit_verification.judge`, and `exploit_verification.attacker`. The gate
rejects any role not on this list at preflight (see
[models.md](models.md) for the role/backend matrix).

`sdk` and `openai` run their agentic Read/Glob/Grep tool-loop through
`backends/llm/tools.py` (sandboxed to the target repo, no Bash); `cli` uses the
CLI's native tools (Bash-capable, though no shipped profile grants it). In S10
fix mode, `via: sdk` delegates Edit/Write work to `backends/llm/agent_sdk.py`.

The agentic S10/S11 Harness is a separate route, reached through
`backends/harness/registry.get_harness` — never through the llm dispatcher
above. A detection role spelled `via: deepagents` reaches the same harness,
but through the `backends/llm/deepagents.py` dispatch seam rather than a
stage's own `get_harness` branch; only the `remediate`/`validate` roles run
the S10/S11 agent graph:

| Stages | Selector | Implementation |
|---|---|---|
| S10/S11 | `via: deepagents` on `models.remediate` / `models.validate` | DeepAgents/LangGraph agent graph; repo-confined writes for S10 fix mode and read-only agents for S11 |
| S11 | `via: cli` or `via: sdk` | Both select the Claude Agent SDK Harness; validation remains read-only |
| S11 | legacy `via: openai` | Normalized to DeepAgents with `provider: openai` before launch |

**How the detection one-shot path stays tool-less.** A detection `prompt()`
call compiles a one-shot parser graph
(`backends/harness/deepagents/options/oneshot.py`) whose security properties
are enforced by complementary layers, each at its own seam:

- **Advertisement** — the `ToolPolicy` is folded into a single `ExcludeTools`
  middleware entry at the `wrap_model_call` seam: with the empty policy the
  detection dispatcher passes, every native filesystem tool is withheld from
  the model's request — and so is `task`, the sub-agent dispatch tool. On its
  own this fails open: the LangGraph tool node keeps every registered tool
  object (deepagents 0.7.13 has no per-call way to remove a
  middleware-injected tool), so a forged or hallucinated tool_call would
  still reach the executor.
- **Execution (fail closed)** — `PermitTools`
  (`backends/harness/deepagents/permit_tools.py`) acts at the
  `wrap_tool_call` seam and refuses any tool_call whose name is outside the
  session's permitted set, answering with a synthetic error `ToolMessage`
  instead of executing. The one-shot detection parser permits **zero** tools
  (`task` included); the agentic detection path permits exactly the granted
  read natives, so advertisement equals permission there.
- **Write/delete ops** — `READ_ONLY_PERMISSIONS` deny rules refuse
  `write_file`/`edit_file`/`delete` graph-wide, sub-agents included.
- **Command execution** — the session backend is a plain `FilesystemBackend`,
  not a sandbox, so `execute` has nothing to dispatch to.
- **Sub-agent reads** — the one-shot path supplies its own redaction-wrapped,
  read-only `general-purpose` sub-agent spec, displacing the ungated,
  unredacted builtin deepagents would otherwise auto-add; a dispatched
  sub-agent's reads are masked too.

The upshot: excluded tool objects remain inside the compiled graph, so the
guarantee is "unreachable" (un-advertised *and* refused at the executor), not
"absent". Agentic detection roles run the streaming
graph read-only, with the read-redaction middleware on. See
[deepagents.md](deepagents.md) for the full account. On every shape,
deepagents attaches a block-marker prompt-caching middleware
(`BlockMarkerPromptCaching(enabled=cache_markers)`), so the system prompt and
tool definitions are cached across repeated same-stage calls (writes bill at
1.25×, reads at 0.1×) — unless the `sdk:` block's `cache_markers` kill switch
is set to `off`, which disables the markers on this route.

See [models.md](models.md) for the complete role/backend matrix.

## Cross-cutting concerns

- **Config** (`config/`): `${ENV:-default}` expansion, optional
  `config.local.yaml` deep-merge, and per-scan `step1` overlays. Two load-time
  policy gates: an environment variable whose name matches a secret pattern
  may be interpolated only into credential keys — anywhere else the load fails
  with `ConfigPolicyError`, even when the variable is unset; and, on POSIX
  hosts, `config.local.yaml` must be owned by the invoking user (or root) and
  not group/world-writable, otherwise loading fails with a fix-it message
  (`chmod go-w`, or set `VVAHARNESS_NO_LOCAL_CONFIG` to skip the overlay).
- **Redaction** (`report/redact.py`): card/PII/credential material is masked at
  the Markdown and SARIF write boundary so it does not land in those final
  artifacts. Card numbers are Luhn+IIN gated and SSNs area/group/serial gated
  for precision; values
  following a strong credential keyword (`password`, `api_key`, `access_key`,
  `client_secret`, `auth_token`) are always masked, while a short lowercase word
  after a prose-ambiguous keyword (`secret`, `token`, `credential`) is left as ordinary text.
- **Token & cost accounting** (`util/tokens.py`, `util/metrics.py`): phase
  buckets record usage by phase; they do not enforce spend caps. Budget caps
  are route-specific parameters enforced only by compatible CLI/Claude Agent
  SDK paths and ignored by raw SDK, OpenAI, and DeepAgents paths. The report's embedded `ScanMetrics` and
  terminal `Tokens:` summary are built immediately before S8 and re-snapshotted
  once S8 returns, so they include S8 but omit S9–S11 activity;
  `run_manifest_*.json` carries per-stage token/cost entries
  (`stages.<id>`) and run `totals` including cache read/write tokens. On
  DeepAgents routes, langchain-anthropic reports TTL'd cache writes under
  `ephemeral_5m/1h_input_tokens` and zeroes the generic `cache_creation`;
  those keys are now folded into cache-write accounting, so S10/S11
  cache-write spend — previously reported as 0 and under-priced at 1.0× —
  is counted and priced at its 1.25× rate.
- **Error log** (`util/errlog.py`): non-fatal errors are appended to the
  per-scan `*_errors.jsonl`.
