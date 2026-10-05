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

# DeepAgents Route

`via: deepagents` is the shared agent runtime for configured detection,
remediation, and validation roles. It supports Anthropic and OpenAI-compatible
providers and is selected per role in the active profile.

For backend selection, see [models.md](models.md). For credentials, TLS, and
profile setup, see [SETUP_GUIDE.md](SETUP_GUIDE.md) and
[configuration.md](configuration.md).

## Execution shapes

Detection and post-scan roles take two shapes on this route:

- **Single-shot roles** send one prompt and return structured or text output.
  Shipped examples include threat modeling, decomposition, deep-dive analysis,
  deduplication, and chain analysis.
- **Agentic roles** can inspect the target with the tools allowed by the profile.
  Shipped examples include preprocessing, adversarial verification, remediation,
  and validation.

In three of the four shipped profiles this route also carries all four
exploit-verification roles (`exploit_verification.classify`, `.mapper`,
`.judge`, and `.attacker`); `sdk.yaml` routes them `via: sdk` instead. The
first three fit the two shapes above, but the **`attacker` is a distinct third
shape** (Beta — API only): it runs the streaming graph yet injects its own
live-HTTP `http_request` tool through a `tool_builder`, so it is **not
read-only** — it sends live attack traffic to the target. That tool appears in
no profile allowlist and is built directly rather than passing through the
allowlist stripping, so the read-only guarantee in *Tools and safety* below
does not cover it. See [exploit-verification.md](exploit-verification.md).

The host controls the working directory, tool permissions, output handling, and
persistence of scan artifacts.

## Providers and credentials

Set `via: deepagents` on a model role and select the provider explicitly when
needed:

```yaml
models:
  verify: {id: claude-sonnet-4-6, via: deepagents, provider: anthropic}
```

Supported providers are `anthropic` and `openai`. Anthropic-routed roles use
`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; OpenAI-routed roles use
`OPENAI_API_KEY`. Use the corresponding base URL variables for private or
compatible gateways.

Validation is a whole-panel decision: all validation personas use the
orchestrator's route and provider. A legacy `via: openai` validation setting is
normalized to DeepAgents with the OpenAI provider; see [validation.md](validation.md).

## Tools and safety

Agentic roles receive only the tools named in the relevant profile allowlist.
Detection and verification roles are read-only by default (`Read`, `Glob`, and
`Grep`). Remediation may use `Edit` and `Write` in a repository-confined
filesystem. Validation is read-only. Shipped profiles do not grant `Bash`. The
one exception to read-only is the exploit-verification `attacker` (see
[Execution shapes](#execution-shapes)): it injects a live-HTTP `http_request`
tool that is built outside the profile allowlist, so it sends live attack
traffic and is not read-only.

Tool exposure is layered. A tool outside the allowlist is never advertised to
the model, and a fail-closed `PermitTools` gate at the tool-execution seam
refuses any tool call — including a forged or hallucinated one — whose name is
outside the session's permitted set, answering with an error instead of
executing. On single-shot detection roles the permitted set is empty: the
model is offered zero tools — no filesystem tools, no shell, and no sub-agent
dispatch. Excluded tool objects still exist inside the compiled graph, so the
guarantee is "unreachable" (un-advertised *and* refused at the executor), not
"absent".

Run scans only against authorized repositories and approved model endpoints.
Prompt data may be sent to the configured provider. See [security.md](security.md)
for isolation, data-egress, and redaction guidance.

## Transport (OpenAI provider)

OpenAI-routed roles use the Responses API by default, with `store: false` so
the endpoint keeps no per-turn state. If a model's first Responses call fails,
the route retries once on Chat Completions, warns once, and keeps that choice
for the model for the rest of the run — unless the Chat Completions retry also
fails, in which case the learned choice is dropped and the original Responses
error surfaces. Set `use_responses_api: false` on the model node to force Chat
Completions — the escape hatch for an endpoint that misbehaves on the Responses
path — or `use_responses_api: true` to pin the Responses API and disable the
fallback. The scan manifest records the configured transport per role as
`resolved_transport`; a runtime-learned fallback shows up separately as the
`deepagents_responses_fallback` counter.

## TLS and limits

For a private gateway or TLS-intercepting proxy, configure the base URL and CA
bundle for the selected provider. DeepAgents uses the route-specific
certificate settings described in [SETUP_GUIDE.md](SETUP_GUIDE.md). Verify the
selected route with `vvaharness setup` and `vvaharness doctor`.

`max_turns` bounds agentic tool-loop turns and is the only real bound on this
route. `max_budget_usd` is accepted for configuration parity but is never
enforced here; compatible Claude CLI and Claude Agent SDK routes are the ones
that enforce a spend cap. Large prompts can exceed
the route context ceiling, and model replies can be truncated by the
output-token budget. See [outputs.md](outputs.md) for error and artifact guidance.

All findings and remediation proposals require human review.
