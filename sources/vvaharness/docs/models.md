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

# Models — role selection and data schemas

This file covers two different things that both go by "models", and it is worth
knowing which one you are looking for:

| Part | Subject |
|---|---|
| [Model selection & backends](#model-selection--backends) | **LLM models.** Which model id and `via:` backend each pipeline role uses, and how to swap one. |
| [Pydantic data models](#pydantic-data-models-vvaharnessmodels) | **Python classes.** The `vvaharness/models/` schemas that carry taint evidence, control flow, and framework facts between stages. |

---

## Model selection & backends

Each model role in `config.yaml` chooses its own `{id, via, provider}` subject
to the role matrix below (`provider` applies to `via: deepagents` only).
S0/S9 also contain deterministic work with no model role; S5 is deterministic
apart from an optional pre-verify semantic dedup (S5-b) that reuses the
`dedup` role's model (`models.dedup`), armed by `default.yaml`.
Detection roles use `cli`, `sdk`, `openai`, or `deepagents`: every shipped
role is in the registry's `DEEPAGENTS_ROLES` gate, including
`deepdive` (S4, single-shot on that route) and `verify` (S6, read-only
agentic) — so setup/doctor accepts `via: deepagents` on all of them. The gate
itself remains for roles added in the future: `via: deepagents` on a role not
in `DEEPAGENTS_ROLES` is rejected by setup/doctor and at preflight, before a
scan starts.
Remediation fix mode is supported by `cli`, `sdk`,
and `deepagents` (legacy direct `openai` is report-only). Validation supports
`cli`, `sdk`, or `deepagents`; legacy `via: openai` validation is normalized to
DeepAgents with the OpenAI provider.

### Default role → backend mapping

The shipped **default profile** (`vvaharness/config/profiles/default.yaml`) runs
S0 locally and routes every model role — the S1–S9 detection roles on
`claude-opus-4-7` (S1 `preprocess` on `claude-sonnet-4-6`), plus S10
remediation and S11 validation — through DeepAgents
with Anthropic. One credential therefore covers the whole run: any of
`ANTHROPIC_SDK_API_KEY` (highest precedence),
`ANTHROPIC_API_KEY`, or `ANTHROPIC_AUTH_TOKEN`. The `sdk:` block's gateway and
mTLS settings reach the detection roles regardless of which of the three
supplies the key.
It does **not** require the `claude` CLI for detection; no shipped profile
routes an S1–S9 detection role `via: cli` unless you edit a profile copy to do
so. All four exploit-verification roles ship `via: deepagents` in `default.yaml`,
`full.yaml` and `taint.yaml`, and `via: sdk` in `sdk.yaml`. No shipped profile
routes an EV role `via: cli`. One Anthropic credential covers an EV-armed
`default` or `taint` run; `full.yaml` additionally needs `OPENAI_API_KEY`, for
its `judge` alone.

| Step | Role | Default (`default.yaml`) | Switchable to |
|---|---|---|---|
| s0 rules seed | — | local AST engine | — |
| s0 LLM annotation | `graph_annotate` (legacy fallback chain — see the note under this table) | `deepagents` (Anthropic) — `default.yaml` and `full.yaml` set `callgraph_detection: llm`, so this role **does** run (`taint.yaml` uses `rules` and leaves it idle) | cli ⇄ sdk ⇄ openai ⇄ deepagents (single-shot) |
| auto-step1 | `autoexclude` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents (single-shot) |
| s1 preprocess | `preprocess` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents (agentic; Bash on `cli` only) |
| s2 threatmodel | `threatmodel` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents (single-shot; agentic when `step2.agentic: true`) |
| s3 decompose | `decompose` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents (single-shot) |
| s4 deepdive | `deepdive` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents (single-shot) |
| s5 prefilter | — (S5-b pre-verify dedup reuses `dedup`) | local; optional S5-b semantic dedup on `models.dedup` | — |
| s6 verify | `verify` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents (agentic; Bash on `cli` only) |
| s6 exploit verification (opt-in) | `exploit_verification.classify` / `.mapper` / `.judge` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents |
| s6 exploit verification (opt-in) | `exploit_verification.attacker` | `deepagents` (Anthropic) | sdk ⇄ openai ⇄ deepagents — the role supplies its own `http_request` tool, which `via: cli` cannot carry |
| s7 dedup | `dedup` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents (single-shot) |
| s8 chain | `chain` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ openai ⇄ deepagents (single-shot) |
| s9 SARIF | — | local | — |
| s10 remediate (`remediate` cmd) | `remediate` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ deepagents (agent graph; `openai` is report-only) |
| s11 DTO discovery (`validate` cmd) | — | local | — |
| s11 agentic validation | `validate` (+ per-persona overrides) | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ deepagents (agent graph; `openai` → `deepagents`) |

> **s0 LLM annotation fallback chain.** The step resolves its role in order
> `graph_annotate` → `preprocess` → `callgraph_creation` → `deepdive`, taking the
> first one the profile configures. Only roles carried in the DeepAgents gate may be
> routed `via: deepagents`; the legacy `callgraph_creation` entry is not in the gate,
> so preflight refuses it there.

> **The exploit-verification roles are nested under `models.exploit_verification`**
> (`classify`, `mapper`, `judge`, `attacker`) and belong to the S6 exploit-verification
> pass, which is **Beta**, API-only, localhost-only, and inert unless `EV_API_COLLECTION`
> is set — so their credentials are needed only on a run that arms it. Shipped routing
> differs per profile: `default.yaml`, `full.yaml` and `taint.yaml` run all four roles
> `via: deepagents`, and `sdk.yaml` runs all four `via: sdk`. Three of those are
> single-vendor (Anthropic); `full.yaml` is the cross-vendor example, keeping `attacker`,
> `classify` and `mapper` on Anthropic while its `judge` resolves through the DeepAgents
> runtime with `provider: openai`, so arming EV there also needs an OpenAI credential.
> `attacker` is optional — omit it to run the pass without the adaptive loop. See
> [exploit-verification.md](exploit-verification.md).

> **`deepagents` is one harness, two graph shapes.** Every `via: deepagents`
> role runs on the DeepAgents/LangGraph harness. The single-shot detection
> roles above compile a one-shot parser graph on which the model is offered
> **zero tools — no filesystem tools, no shell, and no sub-agent dispatch**
> (the `task` tool is withheld from every model request). The agentic
> detection roles — `preprocess`, `verify`, and `threatmodel` with
> `step2.agentic: true` — run the streaming graph with read-only
> Read/Glob/Grep, results redacted. On `remediate` / `validate` it is the
> **agent graph**, unchanged. No detection-quality difference is claimed
> between the routes — pick one for its transport and tooling properties
> (tool exposure, TLS/mTLS reach, caching), not for expected recall.

> **Two post-scan commands.** `remediate` is S10: the Remediation Agent (LLM
> role `models.remediate`) proposes fixes and writes DTOs. `validate` is S11:
> it first discovers validatable DTOs deterministically (no model), then runs
> the agentic panel. The commands are separate; S10 writes the DTOs and S11
> grades them.

#### s11 validation personas

The `validate` command (s11) runs an adversarial panel with **two always-on personas**
(`security-architect` and `penetration-tester`) plus a `cross-repo-analyzer` that the
orchestrator is instructed to spawn only when the fix spans two or more repositories;
when it does run it returns `skip` for gates outside its multi-repo perspective. Each
persona inherits the orchestrator model when its key is unset; all four shipped
profiles instead pin each one explicitly. Each is
independently overridable via an optional per-persona key **nested under `models.validate`**
in `config.yaml`:

```yaml
models:
  validate:
    orchestrator:        {id: claude-opus-5, via: deepagents, provider: anthropic}
    security_architect:  {id: claude-sonnet-4-6}
    penetration_tester:  {id: claude-sonnet-4-6}
    cross_repo_analyzer: {id: claude-sonnet-4-6}
```

`models.validate.orchestrator` accepts `{id, via, provider}` and resolves to
`via: cli`, `via: sdk`, or `via: deepagents`; a legacy `via: openai` value is routed to
`via: deepagents` with the OpenAI provider, which is equivalent to writing
`{via: deepagents, provider: openai}`. An unset persona key inherits the
orchestrator's model (`models.validate.orchestrator`).

> **One vendor per validation panel.** The per-persona keys honour **`id` only** — a
> `via:` or `provider:` written on a persona is ignored. The whole panel runs on the
> backend and provider resolved from `models.validate.orchestrator`.
>
> So personas may differ in *model id within one vendor* (orchestrator `gpt-5.5`,
> personas `gpt-5.5-mini`), but a mixed-vendor panel is **refused at startup with exit
> code 2**, before any workspace is staged or token spent:
>
> ```yaml
> # REFUSED — gpt-5.5 cannot run on the Anthropic endpoint the panel uses
> validate:
>   orchestrator:       {id: claude-opus-4-8, via: deepagents, provider: anthropic}
>   security_architect: {id: gpt-5.5}
> ```
>
> ```
> validate: models.validate.security_architect is 'gpt-5.5', which routes to an
> OpenAI-compatible endpoint, but the panel runs on Anthropic (from
> models.validate.orchestrator). …
> ```
>
> Keep the orchestrator and every persona on the same vendor: all `claude-*` with
> `provider: anthropic` (the shipped `default.yaml`), or all `gpt-*` with
> `provider: openai`.

Other profiles ship under `vvaharness/config/profiles/`:

- **`sdk.yaml`** — every configured role is spelled `via: sdk`. Detection uses
  `ANTHROPIC_SDK_API_KEY`. In this profile specifically, S10 requests
  Edit/Write, so the read-only Anthropic SDK loop delegates that remediation
  call to the Claude Agent SDK and translates the SDK-named key. This is not
  the shipped default S10 route; `default.yaml` uses DeepAgents. S11's Agent
  SDK Harness pins external `claude` and uses
  ambient Claude login/OAuth or standard `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN`. A standard Anthropic credential alone can cover all
  stages through the sole-SDK detection fallback; the SDK-named key alone covers
  S1–S10 but does not authenticate S11. No route
  grants Bash. Its
  deepdive at `temperature: 0.4` on `claude-sonnet-4-6` is capable of s4
  majority voting, but this profile ships `runs: 1` / `vote_threshold: 1`, so
  voting is off — raise `step4.runs` / `vote_threshold` to turn it on
  (`full.yaml` ships `runs: 3` / `vote_threshold: 2`). `default.yaml` likewise
  ships `runs: 1`, a single pass. Raising it works there too, even though its
  `claude-opus-4-7` deepdive **rejects an explicit `temperature`**: such models
  sample at the provider's own non-zero default, so repeated runs still diverge
  and voting still filters. A temperature-capable model lets you tune how much
  diversity you get; it is not a precondition for voting.
- **`full.yaml`** — the **multi-backend template** you copy to `./config.yaml`
  and edit, and the only shipped profile with s4 voting on (`runs: 3` /
  `vote_threshold: 2`). As shipped every role is `via: deepagents`, on
  Anthropic apart from the exploit-verification `judge` (`provider: openai`),
  so one Anthropic credential runs it as-is — the judge's `OPENAI_API_KEY` is
  needed only on an EV-armed run; commented `cli` / `sdk` / `openai`
  alternatives sit beside the roles that accept them, and uncommenting one adds
  that backend's credential requirement (Claude CLI auth, or `OPENAI_API_KEY`).
- **`taint.yaml`** — S0-enabled, taint-first detection. All of S1–S9 runs
  `via: deepagents` (Anthropic), so one Anthropic credential covers it and no
  `claude` binary is required. It sets `callgraph_detection: rules`, which needs
  operator-supplied source/sink YAML — with none supplied, S0 returns an empty
  seed and later stages continue. S10/S11 are disabled in this profile.
- **DeepAgents routing** — reached per model via `via: deepagents` + a
  `provider` key on the role (no separate profile), on detection and post-scan
  roles alike. On `remediate` / `validate` it selects the shared
  DeepAgents/LangGraph agent graph (`default.yaml` routes both there, on
  Anthropic); a detection role reaches the same harness through the stage's
  dispatch seam (`backends/llm/deepagents.py`) — a one-shot parser graph that
  offers the model no tools on the single-shot roles, a read-only streaming
  graph on the agentic ones. Exactly two providers are supported (the
  deepagents `Provider` enum has no other members):
  - `provider: anthropic` — uses the Anthropic Messages API (`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, optional `ANTHROPIC_BASE_URL`); for Claude models. Behind a private-CA gateway this branch needs `sdk.ca_cert` or ambient `SSL_CERT_FILE`/`SSL_CERT_DIR` — it deliberately ignores ambient `NODE_EXTRA_CA_CERTS`/`REQUESTS_CA_BUNDLE` (a CA path *replaces* system trust here, so honouring a corporate-proxy CA ambiently would break public `api.anthropic.com`); without an honoured name you get `CERTIFICATE_VERIFY_FAILED`.
  - `provider: openai` — uses the OpenAI-compatible API (`OPENAI_API_KEY` + optional `OPENAI_BASE_URL`): the Responses API by default with `store: false`, with a one-shot learned fallback to Chat Completions and a per-model `use_responses_api:` override (see [deepagents.md](deepagents.md)); works with OpenAI models and OpenAI-compatible endpoints (vLLM, Together AI, Ollama, …). Set `OPENAI_BASE_URL` to point at your endpoint — see [Running any role on a third-party model](#running-any-role-on-a-third-party-model) for recipes and the Azure caveat.
  When `provider` is omitted, the backend infers from the model name (an id containing `claude` → Anthropic, anything else → OpenAI-compatible).

  **`provider:` looks like a free choice and is not.** It selects the API
  *surface* (Anthropic Messages vs OpenAI-compatible), and gateways enforce the pairing:
  an Anthropic model requires `provider: anthropic` and an OpenAI-compatible
  model requires `provider: openai`. Measured against a live gateway:
  `claude-opus-4-8` with `provider: openai` returns
  `400 model claude-opus-4-8 is not an OpenAI API compatible model`, and
  `gpt-5.5` with `provider: anthropic` returns
  `400 Model 'gpt-5.5' is not supported on the /v1/messages endpoint`. This is
  a gateway/provider constraint, not a harness limitation — cross-wiring the
  two never works.

### Backends

| `via:` | Transport | Tools | Honours |
|---|---|---|---|
| `cli` | Detection/S10: `claude` subprocess; S11: Claude Agent SDK Harness | Detection/S10 can expose native Read Glob Grep **Bash**; S11 is read-only | `max_budget_usd`, `effort`, and `max_turns` are each forwarded only when the installed CLI advertises the corresponding flag |
| `sdk` | Detection: Anthropic Python SDK; S10 only delegates to Claude Agent SDK when mutating tools are requested; S11: Claude Agent SDK Harness | Detection Read Glob Grep; delegated S10 repo-confined Edit/Write; S11 read-only | `temperature`, `thinking_budget`, `betas`, `max_turns` where supported |
| `openai` | OpenAI Chat Completions (any compatible endpoint) | Read Glob Grep (sandboxed `backends/llm/tools.py`) | `temperature`, `max_turns` |
| `deepagents` | DeepAgents / LangGraph harness on every role: the S10/S11 agent graph; a one-shot parser graph on the single-shot detection roles; a read-only streaming graph on the agentic detection roles | S10/S11: Read Glob Grep, repo-confined Edit/Write in remediation fix mode, no shell. Detection one-shot: **no tools offered at all** — no filesystem tools, no shell, no sub-agent dispatch. Detection agentic: read-only Read Glob Grep, reads redacted | S10/S11: `max_turns`, structured output. Detection: `max_turns` on agentic roles (mapped to the recursion limit); `temperature`, `thinking_budget`, `betas`, `timeout`, `max_budget_usd` are accepted-and-ignored |

Detection `via: sdk` / `via: openai` auto-drop and retry params the model rejects
(e.g. `temperature` on models that don't support it). `via: cli` is the only
backend with **Bash** — re-add `- Bash` to `step1.allowed_tools` if you switch
`preprocess` to `cli`. The `openai` client is bundled, so `via: openai` works
out of the box — it only needs `OPENAI_API_KEY`.

`via: cli` reads the optional `cli:` config block (`verify_ssl`, `ca_cert`, `effort`, `no_proxy`) and
propagates TLS/proxy settings into the `claude` subprocess environment: `ca_cert`
→ `NODE_EXTRA_CA_CERTS`, `verify_ssl: false` → `NODE_TLS_REJECT_UNAUTHORIZED=0`,
and `no_proxy` → `NO_PROXY`/`no_proxy`. Auth and endpoint stay delegated to the
CLI's native precedence. All of these are optional — when their env vars are
unset they inject nothing. Prefer absolute certificate paths — a relative
value in a transport block resolves against the selected config's directory
(network/UNC paths are refused). mTLS client certs are
available to the direct Anthropic SDK detection transport
(`ANTHROPIC_SDK_CLIENT_CERT`) and to `via: deepagents` — on detection roles
via `client_cert` in the transport block matching the resolved vendor (`sdk:`
for Anthropic, `openai:` for OpenAI-compatible), and on every deepagents role
via `VVAHARNESS_TLS_CLIENT_CERT` in the environment (+ optional
`VVAHARNESS_TLS_CLIENT_KEY` for a split key). The
Claude Agent SDK paths (S10/S11 on `via: sdk` / `via: cli`) do not consume
those settings, `via: cli` cannot use mTLS (Node exposes no env path), and
neither can `via: openai`.

A bare-string model id (e.g. `deepdive: some-model-id`) defaults to `via: cli`
for backward compatibility.

### Model Performance & Sizing

Performance varies significantly with model size and precision. The harness asks the
model to reason about multi-file codebases, reconstruct taint paths, classify CWEs,
generate adversarial security questions, and synthesise a structured verdict — all
in a single long-running agentic session. Smaller or heavily quantised models
measurably underperform on these tasks, typically losing track of dependency chains
mid-session or failing to produce schema-valid structured output.

#### Recommended specification

| Dimension | Minimum | Notes |
|---|---|---|
| **Architecture** | Reasoning model | Models with explicit chain-of-thought or extended-thinking modes consistently outperform pure completion models of equal parameter count on code-analysis tasks. |
| **Parameters** | ≥ 70 B | The minimum scale where models reliably handle multi-file taint paths, CWE classification, and complex remediation reasoning. Models below this threshold tend to lose track of long dependency chains mid-session. |
| **Precision** | INT16 / FP16 / BF16 | Models quantised below INT16 — INT8, INT4, GPTQ 4-bit — show meaningful degradation in structured-output fidelity and code-level reasoning at this task complexity. FP32 is fine but rarely available at 70 B+ scale. |
| **Context window** | ≥ 32 k tokens | A typical deep-dive session over a large service can accumulate 20–30 k tokens of tool results. Models with shorter windows will truncate mid-session or refuse tool results, silently reducing coverage. |

#### Example models

The following are examples of models that meet the recommended specification.
Any model satisfying the criteria above is expected to work.

| Model family | Examples | Notes |
|---|---|---|
| **Claude (Anthropic)** | Claude Opus 5, Claude Opus 4, Claude Sonnet 4.x | Opus for remediation and validation — the shipped default pins `claude-opus-5` as its S11 validation orchestrator; it also runs Opus on most scan roles (Sonnet on `preprocess`) — swap scan roles to Sonnet to cut cost. |
| **GPT-5 series (OpenAI)** | gpt-5, gpt-5.6-terra | Strong structured-output reliability across all roles. |
| **Kimi** | Kimi K2.7-code | Code-focused reasoning; reachable on detection and remediation/validation roles via an OpenAI-compatible endpoint. |
| **GLM (Zhipu AI)** | GLM-5.2 | OpenAI-compatible endpoint. |
| **DeepSeek** | DeepSeek-V4, DeepSeek-R1 | Strong code reasoning; R1 variant preferred for validation roles. |

#### Role tiers

| Role | Recommended tier | Why |
|---|---|---|
| S1–S9 scan (`preprocess` → `chain`) | Mid-tier reasoning | High-volume; many calls per repo. Throughput and cost matter here. |
| S10 remediate | High-tier reasoning | Proposes code changes; needs deep reasoning about fix correctness. |
| S11 validate orchestrator | High-tier reasoning | Synthesises adversarial persona findings into a structured verdict. |
| S11 validate personas | Mid-to-high reasoning | Independent security review; each persona reads the full diff. |

The shipped `default.yaml` runs Opus on every scan role except `preprocess`;
the table above is cost guidance for operators configuring custom deployments.

### Swapping a role

```yaml
models:
  autoexclude: {id: <model-id>, via: sdk}
  preprocess:  {id: <model-id>, via: cli}   # ← flip to get Bash in s1
  decompose:   {id: <model-id>, via: openai}
```

No code change — `backends/llm/registry.py` `resolve()` reads `{id, via, temperature,
thinking_budget, betas}` and routes detection calls to
`backends/llm/{cli,sdk,openai}.py`. A role spelled `via: deepagents` never
goes through the registry (`deepagents` is deliberately absent from its
backend table, so a stray registry call fails loudly): each stage's
`dispatch_prompt` / `dispatch_agentic` call in `backends/llm/deepagents.py`
branches on the resolved `via` and sends it to the DeepAgents harness,
forwarding the role's `provider`; S10/S11 DeepAgents routes use the shared
Harness backend. See `docs/deepagents.md` for the route's provider, tool, TLS,
and limit guidance.

### Running any role on a third-party model

Every role that accepts `via: deepagents` can run on an OpenAI-compatible
endpoint by spelling the role `{id, via: deepagents, provider: openai}` and
pointing `OPENAI_BASE_URL` / `OPENAI_API_KEY` at the endpoint. Be clear about
what this adds: S2/S3 could already reach both vendors — the role matrix
above lists the legacy `via: openai` backend beside their Anthropic
routes, and `full.yaml` as shipped runs them on Anthropic via DeepAgents
with commented alternatives beside them — so this is a config spelling
plus mTLS, not new model
reach. The deepagents `Provider` enum has exactly two members,
Anthropic and OpenAI-compatible.

**Recipe — GLM 5.2, Kimi K2.7-code, a Gemini OpenAI-compatible surface, or
any other OpenAI-compatible vendor (e.g. Qwen).** The shape is the same for
all of them; only the endpoint and model id differ (see the verification note
at the end of this section for which ids have actually been exercised):

```yaml
models:
  threatmodel: {id: glm-5.2, via: deepagents, provider: openai}
  decompose:   {id: glm-5.2, via: deepagents, provider: openai}
```

```bash
# .env — never put the key in the YAML
OPENAI_API_KEY=<vendor API key>
OPENAI_BASE_URL=<the vendor's OpenAI-compatible Chat Completions base URL>
```

> **Gemini caveat — do not route Gemini's *agentic* roles `via: deepagents`.**
> Gemini 3.x (and any model that requires the client to echo opaque per-turn
> state, such as Gemini's `thought_signature`) fails deterministically on the
> second tool call of a multi-turn `via: deepagents` session: the route's
> langchain-openai message conversion strips that state on tool-call replay,
> and the endpoint answers HTTP 400. Single-shot deepagents roles
> (`threatmodel`, `decompose`, `deepdive`, `dedup`, `chain`, `autoexclude`,
> `graph_annotate`) are unaffected — they never replay a tool call — but the
> agentic roles (`preprocess`, `verify`, agentic S2) are not viable there. For
> Gemini detection use the direct `via: openai` backend, which replays tool
> calls verbatim and works with the same endpoint and credentials. This is a
> transport constraint, not a quality statement about either route.

**One endpoint per vendor per run.** `OPENAI_BASE_URL` is a single global
value and role specs carry no `base_url`, so a run supports one Anthropic
endpoint plus one OpenAI-compatible endpoint. Two different OpenAI-compatible
vendors in the same run need an aggregating proxy that fronts both.

**Azure caveat.** The v1 surface
(`https://<resource>.openai.azure.com/openai/v1/`) works with the deployment
name as the model id. Classic per-deployment endpoints need `AzureChatOpenAI`,
which this route does not construct — front them with the v1 surface or a
compatible gateway.

**Vendor `tool_choice` limits are harmless here.** Kimi K2.5+ and
Qwen/DashScope document only `tool_choice: auto|none`. The one-shot detection
path offers the model no tools and requests no structured output, so the
limit never bites on the single-shot roles.

**Two gateway traps, measured live.** Newer OpenAI reasoning models
(`gpt-5.5`) reject the classic `max_tokens` parameter outright
(`400 Unsupported parameter: 'max_tokens' is not supported with this model.
Use 'max_completion_tokens' instead`). Neither shipped route is affected —
the deepagents route works because langchain translates its bound
`max_tokens` to `max_completion_tokens`, and the direct `via: openai` backend
auto-detects and retries with the parameter the model wants — but a raw
hand-rolled API call against the same gateway will hit it. And Gemini
reasoning models return an opaque gateway
`500 "'NoneType' object has no attribute 'get'"` when the requested
`max_tokens` is below the model's internal reasoning budget (reproduced at
`max_tokens: 16`; fine at 4096) — a tiny smoke-test token cap can therefore
masquerade as a gateway outage.

**mTLS.** A gateway requiring a client certificate works on this route: set
`client_cert` in the transport block matching the resolved vendor (`sdk:` for
Anthropic, `openai:` for OpenAI-compatible), or export
`VVAHARNESS_TLS_CLIENT_CERT` (a combined-PEM path; add
`VVAHARNESS_TLS_CLIENT_KEY` when the private key is a separate file). CA
trust keeps using `SSL_CERT_FILE`. The block's `verify_ssl: false` disables
verification with a loud man-in-the-middle warning — a private-CA bundle is
the right fix, not disabled verification (and a configured `ca_cert` wins
over `verify_ssl: false` on every route). Two things to know when it doesn't
connect: profile TLS material (`ca_cert` / `client_cert` / `verify_ssl` in
the `sdk:`/`openai:` blocks) reaches the S0–S9 deepagents roles and the
direct `via: sdk`/`openai` transports, but **not** `via: deepagents` S10/S11,
whose invoker passes credentials only — those two stages read
`SSL_CERT_FILE` / `VVAHARNESS_TLS_CLIENT_CERT` from the process environment
instead. And mTLS **fails open**: a client chain that cannot be loaded (a
classic mistake is pointing `client_cert` at a CA bundle) warns
`client_cert '<path>' could not be loaded (…) — mTLS is NOT active` and
continues with server-authenticated TLS only, so check stderr for that
warning before blaming the gateway.

**No pricing table is bundled.** Every stage's `cost_usd` is `null` unless a
pricing table is supplied — either the `pricing.file` config key or the
`VVAHARNESS_PRICING_FILE` environment variable, which overrides it — points at
an operator-supplied pricing table, and a
single unpriced model also nulls the run's `totals.cost_usd` — a blank cost
field on a third-party model is expected, not a bug.

**Caching: block markers plus the user-turn breakpoint.** The harness swaps
deepagents' auto-attached prompt-caching middleware for its own subclass,
which places three block-level markers — system prompt, tool definitions and
the conversation tail — so agentic sessions cache the growing conversation,
not just the static prefix; and the S4-style user-turn shared-prefix
breakpoint works here too — a `cache_prefix` becomes a `cache_control`-marked
leading block on Anthropic-routed requests (folded into the turn on
OpenAI-compatible ones, where the gateway's implicit cache applies). **The
kill switch for this route is the `sdk:` transport block's `cache_markers`
key**: it gates all four markers. The documented top-level `cache_markers`
scalar still governs the `sdk`/`openai` routes (`via: cli` places no markers at
all, so it has nothing to gate there), so a strict
gateway needs both keys set to `off`.
`doctor --cache-probe` covers deepagents roles with a dedicated arm (two
calls per model through the real dispatch seam).

**Minimal `.env` by goal:**

| Goal | Required `.env` |
|---|---|
| All-Anthropic, detection + S10/S11 | `ANTHROPIC_API_KEY` — one line |
| Detection on a third-party model (GLM / Kimi / Qwen / Gemini) | `OPENAI_API_KEY`, `OPENAI_BASE_URL` |
| Mixed: Anthropic S10/S11 + third-party detection | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENAI_BASE_URL` |
| Private CA | add `SSL_CERT_FILE` |
| mTLS gateway | add `VVAHARNESS_TLS_CLIENT_CERT` |
| Cost reporting | add `VVAHARNESS_PRICING_FILE` |

The one-line all-Anthropic row relies on the credential fallback:
`ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` substitutes for
`ANTHROPIC_SDK_API_KEY` whenever the run's backends are a subset of
`{sdk, deepagents}`. A `via: cli` role in the run withholds that fallback —
its token is a gateway JWT, not an interchangeable API key.

> **What has actually been verified.** The recipes above were exercised
> live through this route against one multi-vendor enterprise gateway
> (2026-08): `claude-opus-4-8` on `provider: anthropic`, and `gpt-5.5`,
> `glm-5.2`, `kimi-k2.7-code`, and `gemini-3.6-flash` on `provider: openai`
> (`gemini-2.5-pro`, `gemini-3.5-flash`, and `gemini-3.1-pro-preview` also
> responded there). "Responded" means a single-shot probe: the Gemini ids
> completed one-shot calls on this route but deterministically fail its
> *multi-turn agentic* sessions — see the Gemini caveat above; use
> `via: openai` for Gemini's agentic roles. No automated test in this
> repository exercises a
> non-OpenAI `base_url`, and no vendor's own endpoint is certified against
> this tool — validate on your own endpoint before relying on it, and treat
> any model id not listed here as unverified. This caution is about
> third-party model ids and endpoints; it does **not** apply to the tool's own
> shipped Anthropic defaults, which include `claude-opus-5` as the
> `default.yaml` S11 validation orchestrator alongside the `claude-opus-4-8`
> and `claude-opus-4-7` scan and remediation roles.

---

## Pydantic Data Models (`vvaharness/models/`)

These models carry structured analysis data through the scan pipeline. All are
Pydantic `BaseModel` subclasses.

---

### Taint analysis primitives

#### `TaintSymbolRef`

A reference to a single tainted symbol at a point in the dataflow graph.

| Field | Type | Description |
|---|---|---|
| `qnode` | `str` | Qualified node ID (e.g., `"pkg.mod.func.varname"`) |
| `symbol` | `str` | Short symbol name (e.g., `"user_id"`) |
| `kind` | `Literal` | One of: `param`, `local`, `return`, `arg`, `field`, `container`, `property` |

**Example use:** `src` and `dst` fields in `TaintTransferEdge` carry a
`TaintSymbolRef` that identifies the exact variable being tracked.

---

#### `TaintTransferEdge`

Base class for a single taint propagation step between two symbols.

| Field | Type | Description |
|---|---|---|
| `file` | `str` | Source file where the transfer occurs |
| `line` | `int` | Line number of the transfer |
| `function_qnode` | `str` | Qualified node of the enclosing function |
| `src` | `TaintSymbolRef` | Symbol taint flows *from* |
| `dst` | `TaintSymbolRef` | Symbol taint flows *to* |
| `transfer_kind` | `Literal` | Semantics of the transfer (see [transfer_kind values](#transfer_kind-values)) |

`transfer_kind` is coerced to `"assign"` when an unrecognised value is supplied.

**Example use:** An assignment `result = request.GET["q"]` produces a
`TaintTransferEdge` with `transfer_kind="assign"`, `src` pointing to the dict
access, and `dst` pointing to `result`.

---

#### `TaintEvidencePath`

A complete structured taint path from source to sink, used as evidence for a
finding.

| Field | Type | Description |
|---|---|---|
| `source_ref` | `str` | Human-readable label for the taint source |
| `sink_ref` | `str` | Human-readable label for the sink |
| `path_funcs` | `list[str]` | Ordered list of function QNames traversed |
| `edges` | `list[TaintTransferEdge]` | Ordered transfer edges along the path |
| `sink_cwe` | `list[str]` | CWE IDs associated with the sink (e.g., `["CWE-89"]`) |
| `sanitized` | `bool` | `True` if the final edge neutralises taint before the sink |

**Example use:** A SQL injection finding attaches a `TaintEvidencePath` showing
the chain from `request.GET["id"]` through one or more functions to a
`cursor.execute()` call.

---

### Control-flow graph

#### `CFGNode`

A block-shaped record reserved for a control-flow graph.

| Field | Type | Description |
|---|---|---|
| `block_id` | `str` | Block identifier (e.g., `"B0"`, `"B1"`) |
| `stmts` | `list` | Statements or instruction metadata in this block |
| `successors` | `list[str]` | Block IDs this block can reach |
| `condition` | `str \| None` | Branch condition text if this block ends in a branch; `None` otherwise |

**Current engine use:** schema only. The current scanner does not populate
per-function `CFGNode` records.

---

#### `CFG`

Control-flow graph container for a single function.

| Field | Type | Description |
|---|---|---|
| `blocks` | `dict[str, CFGNode]` | All basic blocks keyed by `block_id` |
| `entry` | `str` | ID of the entry block (typically `"B0"`) |
| `exit` | `str` | ID of the exit block |
| `function_name` | `str` | Function name, for reference |

**Current engine use:** schema only. The current scanner leaves the per-file
`cfgs` mapping empty, so vvaharness does not currently claim branch- or
path-sensitive CFG analysis.

---

### Condition-gated taint

#### `ConditionTaintEdge` *(extends `TaintTransferEdge`)*

A schema for a taint transfer gated by a branch condition. The current scanner
does not emit these edges.

| Field | Type | Description |
|---|---|---|
| `transfer_kind` | `"condition"` | Fixed discriminator |
| `condition_text` | `str` | Text of the controlling condition (e.g., `"user.role == 'admin'"`) |
| `is_tainted_condition` | `bool` | Whether the condition expression depends on a taint source |
| `confidence` | `"high" \| "medium"` | Confidence in the taint propagation through this branch |

Inherits `file`, `line`, `function_qnode`, `src`, `dst` from `TaintTransferEdge`.

---

### Reflection

#### `ReflectionFact`

A reflective or dynamic dispatch call site discovered during analysis.

| Field | Type | Description |
|---|---|---|
| `function_qnode` | `str` | Enclosing function |
| `line` | `int` | Source line |
| `call_type` | `Literal` | One of: `getmethod`, `invoke`, `getattr`, `construct`, `delegate` |
| `target_symbols` | `list[str]` | Symbols passed to `getMethod`/`getattr`/etc. |
| `receiver` | `str` | Object on which reflection is called |
| `language` | `"python" \| "java" \| "javascript" \| "csharp"` | Source language |

**Example use:** `getattr(obj, user_input)` in Python is recorded as a
`ReflectionFact` with `call_type="getattr"` and `target_symbols=["user_input"]`.

---

#### `ReflectionTaintEdge` *(extends `TaintTransferEdge`)*

A taint transfer through a dynamically resolved method or function.

| Field | Type | Description |
|---|---|---|
| `transfer_kind` | `"reflect"` | Fixed discriminator |
| `reflected_targets` | `list[str]` | QNames of the resolved reflection targets |
| `confidence` | `"low" \| "medium" \| "high"` | How well the target was resolved statically |
| `is_speculative` | `bool` | `True` when the target was inferred rather than proven |

**Example use:** When `getattr(obj, tainted_name)` cannot be fully resolved, a
`ReflectionTaintEdge` with `confidence="low"` and `is_speculative=True` is
emitted to preserve the potential flow.

---

### Cross-language bridges

#### `BridgeUncertaintyEdge`

A low-confidence cross-language handoff edge — a shell, subprocess, SQL-builder,
or template call site where taint may cross into another language. Instances are
serialized as plain dicts into `ContextPackage.uncertainty_edges` to keep wire
compatibility with existing checkpoints and prompts.

| Field | Type | Description |
|---|---|---|
| `src_qnode` | `str` | Qualified node the handoff leaves from |
| `dst_qnode` | `str` | Qualified node the handoff lands on |
| `reason` | `str` | Why the edge was recorded (default `"bridge_signal"`) |
| `confidence` | `float` | `0.0`–`1.0`; defaults to `0.25` |
| `edge_type` | `"bridge"` | Fixed discriminator |
| `bridge_kind` | `"shell" \| "subprocess" \| "sql_builder" \| "template"` | Kind of handoff |
| `language` | `str` | Source language of the handoff site |
| `file` | `str` | Source file of the handoff site |
| `line` | `int` | Source line |
| `snippet` | `str` | Short code excerpt at the handoff site |

**Example use:** a call site that shells out with a possibly tainted argument is
recorded with `bridge_kind="subprocess"` and a low `confidence`, preserving the
cross-language handoff as an uncertainty edge rather than a proven transfer.

---

### Framework markers and route binding

#### `FrameworkMarkerFact`

A framework annotation, decorator, or implicit type-based marker that introduces
user-controlled input into a function.

| Field | Type | Description |
|---|---|---|
| `function_qnode` | `str` | Function annotated or decorated by the marker |
| `line` | `int` | Source line of the annotation |
| `marker_type` | `Literal` | One of: `spring_annotation`, `django_view`, `aspnet_annotation`, `spring_implicit`, `django_dict_access`, `aspnet_implicit`, `express_handler`, `middleware` |
| `marker_name` | `str` | Annotation/attribute name (e.g., `"@RequestParam"`, `"request.GET"`) |
| `parameter_names` | `list[str]` | Parameters tainted by this marker |
| `framework` | `"spring" \| "django" \| "aspnet" \| "express"` | Web framework |
| `confidence` | `"high" \| "medium"` | `high` for explicit annotations; `medium` for implicit dict access |

**Example use:** the parameter annotation in
`String find(@RequestParam("id") String id)` is recorded as a
`FrameworkMarkerFact` with `marker_type="spring_annotation"` and
`parameter_names=["id"]`.

---

#### `RouteTaintFact`

A URL route with path parameters that bind to function arguments, marking those
arguments as tainted (user-controlled).

| Field | Type | Description |
|---|---|---|
| `function_qnode` | `str` | Function handling the route |
| `line` | `int` | Source line of the route declaration |
| `route_pattern` | `str` | Route pattern (e.g., `"/user/{id}"`, `"user/<int:pk>/"`) |
| `parameter_name` | `str` | Name of the tainted path parameter |
| `is_tainted` | `bool` | Defaults to `True` because URL parameters are user-controlled |
| `framework` | `"spring" \| "django" \| "aspnet" \| "express"` | Web framework |

**Example use:** `@GetMapping("/item/{itemId}")` produces a `RouteTaintFact`
with `route_pattern="/item/{itemId}"` and `parameter_name="itemId"`.

---

#### `ResponseDataflowFact`

A flow from an intermediate variable or return value into a framework response
sink — used to identify where tainted data reaches a response boundary.

| Field | Type | Description |
|---|---|---|
| `function_qnode` | `str` | Function containing the dataflow |
| `line` | `int` | Line of the response construction |
| `from_symbol` | `str` | Variable flowing into the response |
| `to_sink` | `str` | Response sink name (e.g., `"JsonResponse"`, `"HttpResponse"`, `"Ok"`) |
| `framework` | `"spring" \| "django" \| "aspnet"` | Web framework |
| `response_type` | `"json" \| "html" \| "text" \| "xml"` | Response content type |

**Example use:** `return JsonResponse({"data": user_input})` is recorded with
`from_symbol="user_input"`, `to_sink="JsonResponse"`, `response_type="json"`,
pointing to a potential XSS or injection reaching the HTTP response.

---

#### `FrameworkTaintEdge` *(extends `TaintTransferEdge`)*

A schema for a taint transfer through framework infrastructure — request
parameter binding, route path binding, or response construction. The current
scanner emits the marker/route/response facts above but does not construct
`FrameworkTaintEdge` instances.

| Field | Type | Description |
|---|---|---|
| `transfer_kind` | `"framework"` | Fixed discriminator |
| `marker_type` | `Literal` | One of: `spring_annotation`, `django_view`, `aspnet_annotation`, `spring_implicit`, `django_dict_access`, `aspnet_implicit` — unlike `FrameworkMarkerFact.marker_type`, the express markers are not accepted |
| `framework` | `"spring" \| "django" \| "aspnet"` | Web framework |
| `confidence` | `"high" \| "medium"` | Confidence in the framework-mediated transfer |

Inherits `file`, `line`, `function_qnode`, `src`, `dst` from `TaintTransferEdge`.

---

### `transfer_kind` values

| Value | Semantics |
|---|---|
| `source` | Introduces taint at a source symbol |
| `assign` | Direct variable assignment (`a = b`) |
| `arg_to_param` | Taint flows from call-site argument into callee parameter |
| `return_to_local` | Callee return value assigned to a local variable |
| `local_to_sink` | Local variable passed directly to a sink |
| `return_to_sink` | Return value used directly as a sink argument |
| `field_write` | Taint stored into an object field or attribute |
| `field_read` | Taint read from an object field or attribute |
| `container_put` | Taint added to a collection (`list.append`, `dict[k] = v`) |
| `container_get` | Taint retrieved from a collection (`dict[k]`, `list[i]`) |
| `sanitize` | Taint neutralised by a sanitiser (the final edge of a `sanitized=True` path) |
| `condition` | Taint gated by a branch condition — see `ConditionTaintEdge` |
| `reflect` | Taint via dynamic dispatch — see `ReflectionTaintEdge` |
| `framework` | Taint via framework binding/response — see `FrameworkTaintEdge` |
