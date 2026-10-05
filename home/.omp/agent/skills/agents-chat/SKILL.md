---
name: agents-chat
description: Cross-role communication protocol for multi-model PraiseAssistant crews working the same engagement through an append-only log. Use when acting as Lead, Planner, or any discovery, gating, proof, judgment, or patch-validation role; when a finding is handed off or challenged; or when creating or updating agentschat.md.
---

# agentschat.md protocol

One append-only file per engagement. It is the shared state between models that
do not share a context window. Markdown in the file is a projection of the
durable, structured rows owned by the PraiseAssistant CLI; the log is
coordination, never authoritative state.

## Location

Linux and Kali, per engagement under the shared pentest workspace:

```
/home/kali/pentest-workspace/$target/agentschat.md
```

Use `/home/kali/pentest-workspace/$target/` as the engagement directory and keep
artifacts in its `evidence/` directory. Launch OMP with
`omp --cwd /home/kali/pentest-workspace/$target`. When delegating, include the
absolute engagement directory, log path, evidence path, and scope in the task
context; do not rely on the child's current directory.

## Rules

1. **Append only.** Never rewrite, reorder, or delete. If a conclusion is
   wrong, post a correction. A rewritten log is not evidence.
2. **One write per entry.** Compose the entry in full, then append in a single
   call. Never interleave concurrent writes.
3. **Header is mandatory.** UTC timestamp, role, observed model id, target slug.
4. **Every entry ends in an ask or a close.** An entry that neither requests
   action nor records a decision forces every other role to re-read it to
   discover nothing.
5. **No raw output.** Summarize, then point at the artifact path. Full HTTP
   bodies, stack traces, and tool dumps exhaust the reading roles.
6. **No secrets.** Credentials never enter the log. Record the location and the
   type only.
7. **The Skeptic closes findings.** The Skeptic's entry is a verdict:
   `confirmed`, `needs-more-proof`, `rejected`, or `duplicate`.

## Model id must be observed, not assumed

The header records the model that actually served the request, read from your
own context. Never copy a model id from the run configuration: an override can
fail to bind and silently fall back to the parent model.

A Skeptic that discovers the entry it is judging carries its own model family
must post an independence violation instead of a verdict. Two models of the same
family share their blind spot, which is the one thing a checker exists to avoid.
The CLI enforces this before accepting a final decision.

## Entry shape

```
### 2026-10-04T14:22:07Z | scout | opencode-go/deepseek-v4-pro:high | acme-corp
FINDING: /api/v2/invoices/{id} returns other tenants' invoice data.
EVIDENCE: candidate C-7, evidence/req-1.json; source_ref/sink_ref traced.
CONFIDENCE: high
ASK verifier: gate C-7.
ARTIFACT: /home/kali/pentest-workspace/acme-corp/evidence/req-1.json
```

## Roles

Roles are assigned by the PraiseAssistant router from the explicit
`PraiseAssistant-Task` header in a task — never from task wording. Each role
owns one stage of the lifecycle.

| Role | Stage | Emits | Never does |
|---|---|---|---|
| Lead | scope, priority | Scoping decisions, assignment | Investigate directly |
| Planner | plan | Hypothesis trees, work ordering | Claim a finding |
| Scout / Finder | recon / discover | Candidates with evidence + source/sink or boundary invariant | Issue a verdict, build a PoC |
| Verifier | gate | `pass` / `hold` / `drop` per candidate | Reproduce, judge, or fix |
| Exploiter | proof | Smallest reproducible PoC on a gated candidate | Rule on the finding, widen scope |
| Skeptic | verdict | `confirmed` / `needs-more-proof` / `rejected` / `duplicate` | Fix anything |
| Tester | patch | Four-gate `validate_fix` result | Hunt, prove, or rule on new findings |

## Handoff rules

A discovery role hands off when the candidate has concrete evidence and either
source/sink references or a named violated boundary invariant — no runtime
reproduction is required before gating.

The Verifier gates (`pass`) or drops the candidate. Only a gated (or already
reproduced) candidate is dispatched to the proof role.

The Exploiter hands to the Skeptic with the smallest reproducible PoC and its
artifact path. A `confirmed` verdict requires two distinct clean-state
reproductions with evidence artifacts and an independent checker — the CLI
asserts this; the roles do not police each other's repro counts by hand.

The Skeptic's rejection is final for that candidate but not for the class. Post
the class note so a sibling candidate is not re-tested blindly.

## Scope

This protocol is coordination, not authorization. Active testing requires a
stated program, asset, and in-scope basis before the first request, per the
`bounty-report` skill. Scope lives in `scope.json`; the PraiseAssistant CLI
enforces the allowed-asset allowlist, budgets, and throttling on every request.
