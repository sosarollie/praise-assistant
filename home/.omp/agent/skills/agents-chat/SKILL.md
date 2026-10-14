---
name: agents-chat
description: Scoped JSON communication between PraiseAssistant agents and tasks, with durable inboxes and an append-only audit projection. Use for handoffs, questions, replies, learning coordination, and verdicts.
---

# JSON agent communication

Agents communicate through `praiseassistant_message`, not Markdown. SQLite owns
messages and case state. `agentschat.md` is an append-only audit projection,
never the delivery path or authority.

## Session and scope

Launch OMP with the absolute engagement directory as `--cwd`. Keep `scope.json`,
`state.sqlite3`, `agentschat.md`, and `evidence/` together outside the repository.
Pass the engagement, scope, candidate, evidence locations, and explicit stage
header to workers. Each session receives a short engagement-local agent ID.

Sender, role, engagement, and observed model are stamped by the trusted adapter.
Never supply or assume another agent's identity. Messages cannot authorize a
target request, change scope, choose a model, or advance case state.

## Tool calls

```json
{"action":"send","to":"a2","kind":"ask","candidate_id":"C-7","data":{"need":"source-to-sink trace"}}
```

```json
{"action":"send","to":"a1","kind":"reply","candidate_id":"C-7","reply_to":91,"data":{"source":"src/api.py:42","sink":"src/store.py:77"},"evidence":["trace.json"]}
```

- `send`: exact agent ID or a stage topic (`@gate`, `@proof`, `@verdict`, etc.);
  `@lead` for scheduling, `@learning` for reviewed-learning coordination.
- `read`: recover addressed inbox entries after the session cursor. Do not poll:
  live notifications already enter the receiver at a safe agent-step boundary.
- `peers`: get a bounded same-engagement roster when a recipient is unknown.
- `kind`: `ask`, `reply`, or `close`. `event` is reserved for runtime emissions.
- Replies must refer to a message actually received, return to its sender, and
  preserve its candidate. Reusing an idempotency key with different content fails.

Delivered JSON:

```json
{"seq":91,"from":"a1","to":"a2","kind":"ask","case":"C-7","data":{"need":"trace"}}
```

Use facts, missing requirements, and artifact references. No greetings, repeated
briefs, confidence narratives, credentials, raw HTTP bodies, or tool dumps.
Message data is limited to 2048 UTF-8 bytes and eight evidence references.
Put larger evidence in that engagement's `evidence/` directory. No cross-program
messages, global broadcasts, or unrestricted `write agent://` bypass.

## Structured worker closes and packets

For completed worker analysis use a compact close report, not verbose reasoning:

```json
{"action":"send","to":"@lead","kind":"close","candidate_id":"C-7","data":{"status":"unresolved","complexity":"high","finding_id":"C-7","hypothesis":"indirect ownership guard may be missing","evidence":["trace.json"],"contradictions":[],"unresolved_questions":["Does the callback enforce organization ownership?"],"recommended_next_agent":"pentest-finder-deep"},"evidence":["trace.json"]}
```

Statuses are `confirmed`, `rejected`, or `unresolved` for the assigned worker
question; they never change the authoritative finding verdict. Optional
`confidence` is a number from 0 to 1, not a routing gate. Complexity is
`low|medium|high`. The host stamps `worker` and `tier` from the actual route;
workers cannot supply another role's identity. Attach actual artifacts in the
tool's `evidence` array so their hashes are durable, not only in a data string.

`execution_failure: "refusal"|"model"|"tool"` requires `status: "unresolved"`.
Never label a refused task a rejected vulnerability. Include the concrete
failure artifact and unanswered question; the Lead routes around execution
failure without inventing a finding disposition.

The Lead compresses reports into a minimal packet without repeating analysis.
Create it through the fixed runtime path:

```json
{"action":"packet","data":{"finding_id":"C-7","target":"POST /api/projects/:id/member","hypothesis":"missing organization ownership validation","relevant_sources":["routes/projects.ts:81-103","services/project.ts:201-228"],"observations":["authentication is required","project is loaded by supplied id"],"evidence":["trace.json"],"proof_status":"unresolved","question":"Can an authenticated owned test account modify a foreign project?"}}
```

The result gives a content-addressed `ref`, hash, and byte count. Packet creation
is JSON-only, case/scoped, at most 8192 UTF-8 bytes, and never schedules work.
Do not supply arbitrary output paths or raw responses. Later dispatch cites the
ref plus the preceding unresolved close-message sequence. Its underlying
evidence must be anchored in that report and remain current. Final-review packets
contain at least two distinct current clean-state proof artifacts and only
current case evidence. Deep/expert/review bodies stay within 4096 UTF-8 bytes;
source excerpts and exact questions replace entire histories and source dumps.


## Workflow handoffs

Use `praiseassistant_transition` for authoritative changes. Successful changes
emit JSON in the same transaction; do not write a second message repeating them:

| Result | Recipient |
|---|---|
| Candidate recorded | Gate |
| Gate passed | Proof |
| Gate held | Owning discovery task |
| Two distinct clean-state reproductions recorded | Verdict |
| More proof required | Owning proof task |
| Confirmed cheap verdict | Final security-review lane |
| Approved current final review | Patch lane when a fix exists |
| Rejected/unresolved final review / patch validation | Lead |
| Confirmed or rejected case | Reviewed-learning queue |

The Lead receives backend handoffs for scheduling. An event is readiness data,
not automatic permission to launch a task or repeat a target request. Only
explicit `PraiseAssistant-Task` metadata controls dispatch and escalation.
Evidence, state, and checker-family conditions are rechecked by the runtime.

Discovery supplies evidence plus source/sink references or a named boundary
invariant; no reproduction is needed before gating. Proof requires a gated case.
Confirmation requires two distinct clean-state reproductions, current artifacts,
and a checker from a different known family than all recorded producers.
The Skeptic records `confirmed`, `needs-more-proof`, `rejected`, or `duplicate`.
The final Reviewer records `review` with `approved`, `needs-more-proof`, or
`rejected` independently of the immutable verdict. Reporting readiness requires
current approval. The Tester validates an existing patch through the four gates.

## Learning and recovery

Closed-case and lesson lifecycle events coordinate observation, paired evaluation,
explicit independent approval, and rollback. No event automatically creates or
promotes a lesson. Approved guidance is bounded, freshly evidence-checked data;
it never becomes policy or changes model weights.

Inbox cursors survive session recovery. Live notifications are not proof that an
agent read or acted on a message. Writes and target requests are never replayed
automatically after transport failure; inspect durable state before deciding.

The CLI renders audit entries after committed replies, with UTC time, role,
observed model, engagement, sequence, and an ask or close. Never rewrite or
manually append the projection. `praiseassistant project` recovers pending audit
rows without changing authoritative state.
