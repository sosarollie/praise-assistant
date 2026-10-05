---
name: praiseassistant-workflow
description: The staged, evidence-driven pipeline that PraiseAssistant routes and enforces: plan, recon, discover, gate, proof, verdict, patch. Use when acting as any crew role in an engagement, when reading a PraiseAssistant-Task header, when recording candidates/verdicts/patches, or when you need the candidate lifecycle and tool mapping.
---

# PraiseAssistant workflow

PraiseAssistant is evidence-driven orchestration for authorized multi-agent
security work. It splits a hunt into explicit stages, owns state in a durable
per-engagement database, and enforces scope, budgets, throttling, and checker
independence in a CLI. OMP is the host; PraiseAssistant supplies the controls.

## How a task is routed

Crew subagents are routed by an explicit header, the first line of the task
text — never by the task's wording:

```
PraiseAssistant-Task: {"stage":"proof","candidate_id":"C-3","engagement_dir":"/abs/path","escalated":false}
```

Fields: `stage` (one of the stages below), `candidate_id` (required for proof,
verdict, and patch), `engagement_dir` (absolute engagement directory), and
`escalated` (boolean; optional `reason`). Only this header changes routing:
negated or contradictory wording in the body does nothing. Escalation to the
deep lane happens only when `escalated` is true. A task without this header is
an ordinary coding request and is left alone; inside an active engagement a
crew task missing the header is refused (fail closed).

## Stages and role ownership

| Stage | Role | Produces | Precondition |
|---|---|---|---|
| plan | planner | ranked hypothesis/work list | scope posted |
| recon | scout | surface map, candidates | scope posted |
| discover | finder | candidates with `file:line` or request evidence | scope posted |
| gate | verifier | `pass` / `hold` / `drop` per candidate | concrete evidence + source/sink or boundary invariant |
| proof | exploiter | smallest reproducible PoC | candidate is `gated` |
| verdict | skeptic | `confirmed` / `needs-more-proof` / `rejected` / `duplicate` | candidate is `reproduced` |
| patch | tester | four-gate `validate_fix` result | a proposed fix exists |

The deep lanes (`pentest-finder-deep`, `pentest-exploiter-deep`,
`pentest-skeptic-deep`) are escalations, selected only by the `escalated` flag,
not by keywords.

## Candidate lifecycle

```
candidate -> (substantiated, optional) -> gated -> reproduced -> confirmed
```

Terminal states also include `held`, `rejected`, and `duplicate`.

- Before `gated`: concrete evidence plus `source_ref`+`sink_ref`, or a named
  `boundary_invariant`. No runtime reproduction is required.
- `gated` (or `reproduced`) is required before proof dispatch.
- `confirmed` requires two distinct clean-state reproduction IDs, evidence
  artifacts, and a checker from a different known model family than the
  recorded candidate/proof producers. Missing artifacts fail closed.

Findings remain candidates until these checks pass.

## Tools

The five PraiseAssistant tools wrap fixed CLI commands. Use them instead of any
shell or network primitive:

| Tool | Fixed command(s) | Read/write |
|---|---|---|
| `praiseassistant_state` | `show [--candidate ID]` | read |
| `praiseassistant_chat` | `chat --role --model --summary (--ask|--close) [--evidence …]` | write |
| `praiseassistant_request` | `request --url --method --role --model [--candidate --clean-state]` | write |
| `praiseassistant_transition` | `candidate` / `gate` / `reproduce` / `verdict` / `validate_fix` | write |
| `praiseassistant_learning` | `learn list|observe|evaluate|promote|rollback` | mixed |

Writes take the observed model from the session (`provider/id`), never a value
you type. If the session has no observed model, the write is refused (fail
closed). Checker/verdict independence is enforced by the CLI against recorded
producer families, not by you.

## Active-scope guard

Inside an initialized engagement, the extension blocks shell, eval, browser,
remote/URL reads, and any unrecognized tool bridge. Only path-constrained local
`read`/`grep`/`glob` inside the engagement and declared source-asset
directories, the PraiseAssistant tools, `task`, `yield`, and `wait` are allowed.
Non-local protocols (http, https, ssh, `skill://`, `mcp://`, …) in inspection
paths are refused.

This is not OS isolation: a trusted user can disable the extension, so run
hostile code in a separate sandbox regardless.

## Scope

Active testing requires a stated program, asset, and in-scope basis recorded in
`scope.json`. The CLI enforces the allowed-asset allowlist, request budgets, and
throttling. No request goes outside the attested assets, and `init` never
implies authorization beyond them.
