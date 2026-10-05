---
name: agents-chat
description: Cross-role communication protocol for multi-model pentest crews working the same target through an append-only chat file. Use when acting as Lead, Planner, Scout, Exploiter, or Skeptic on an engagement, when another role's finding needs to be handed off or challenged, or when creating or updating agentschat.md.
---

# agentschat.md protocol

One append-only file per engagement. It is the only shared state between models
that do not share a context window.

## Location

Windows, per the engagement convention:

```
C:\Users\$machineName\Projects\$target\agentschat.md
```

Linux and Kali, per engagement under the shared pentest workspace:

```
/home/kali/pentest-workspace/$target/agentschat.md
```

One file per target. Never one file for everything. Never share a file across
programs without different scope boundaries.

Use `/home/kali/pentest-workspace/$target/` as the engagement working directory
and keep artifacts in its `evidence/` directory. `$target` is a real engagement
slug with one program/scope boundary. Do not create a workspace-root log or
invent a target merely to initialize the workspace.

Launch OMP with `omp --cwd /home/kali/pentest-workspace/$target`. When delegating,
include the absolute engagement directory, log path, evidence path, and scope
in the task context; do not rely on the child's current directory.

## Rules

1. **Append only.** Never rewrite, reorder, or delete. If a conclusion is wrong,
   post a correction. A rewritten log is not evidence.
2. **One write per entry.** Compose the entry in full, then append in a single
   shell call with `>>`. Never `>`. Concurrent roles writing the same file will
   interleave and corrupt it if they do this differently.
3. **Header is mandatory.** UTC timestamp, role, model id, target slug.
4. **Every entry ends in an ask or a close.** An entry that neither requests
   action nor records a decision forces every other role to re-read it to
   discover nothing.
5. **No raw output.** Summarize, then point at the artifact path. Full HTTP
   bodies, stack traces, and tool dumps exhaust the reading roles.
6. **No secrets.** Credentials never enter the log. Record the location and the
   type only.
7. **Skeptic closes findings.** The Skeptic's entry is a verdict, not an
   opinion. `confirmed`, `needs-more-proof`, `rejected`, or `duplicate`.

## Model id must be observed, not assumed

The header records the model that actually served the request, read from your own
context. Never copy a model id from the run configuration: an override can fail to
bind and silently fall back to the parent model.

A Skeptic that discovers the entry it is judging carries its own model family must
post an independence violation instead of a verdict. Two models of the same family
share their blind spot, which is the one thing a checker exists to avoid.

## Entry shape

```
### 2026-10-04T14:22:07Z | scout | opencode-go/space-bunny-free | acme-corp
FINDING: /api/v2/invoices/{id} returns other tenants' invoice data.
EVIDENCE: GET /api/v2/invoices/9931 with a session scoped to tenant A returns 200
  and 4KB of tenant B's PII fields. Replayed twice from a clean session.
CONFIDENCE: high
ASK lead: confirm the tenant boundary is server-side before the exploiter builds a PoC.
ARTIFACT: /home/kali/pentest-workspace/acme-corp/evidence/inv-9931.json
```

## Role contracts

| Role | Emits | Never does |
|---|---|---|
| Lead | Scoping decisions, priority, target assignment | Investigate directly |
| Planner | Hypothesis trees, attack chain drafts | Claim a finding |
| Scout | Candidates with `file:line` or request evidence | Issue a verdict |
| Exploiter | Working PoC against an authorized target | Test anything outside the stated scope |
| Skeptic | Verdicts and the evidence for them | Fix anything |

## Handoff rules

A Scout hands off when the candidate has a reachable sink and reproducible
evidence. Everything short of that stays in the Scout's own output and costs the
Exploiter nothing.

An Exploiter hands to the Skeptic only with a PoC that reproduces twice from a
clean state. An unreproduced PoC is a Scout finding, not an Exploiter finding.

The Skeptic's rejection is final for that candidate but not for the class. Post
the class note so a sibling candidate is not re-tested blindly.

## Scope

This protocol is coordination, not authorization. Active testing requires a
stated program, asset, and in-scope basis before the first request, per the
`bounty-report` skill. Scope is per target, so the Lead posts it once at the top
of each engagement file.