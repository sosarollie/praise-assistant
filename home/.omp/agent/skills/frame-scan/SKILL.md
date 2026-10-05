---
name: frame-scan
description: Run the Frame neuro-symbolic SAST agent (lambdasec/frame) to detect, exploit, and fix vulnerabilities in source code. Use for source-code vulnerability scanning, taint analysis findings, PoC generation against an authorized local target, SARIF output, or separation-logic entailment checks.
---

# Frame: sound static analysis + LLM security agent

Frame (`lambdasec/frame`) is installed as an isolated `uv tool`; the CLI is
`frame` on `PATH`. Sound symbolic core (taint + separation logic + Z3) fused
with an optional LLM layer.

Use it when the deliverable is a **code-level** finding with a proven dataflow
or a working PoC against a target you control — not for black-box web probing.

## Command surface

| Command | Purpose |
|---|---|
| `frame scan <path>` | Taint analysis + Z3 verification. `-f text\|json\|sarif`, `-o <file>`, `--fail-on <sev>`, `--min-severity`, `-p/--pattern`, `--no-verify` (faster, more FPs), `--timeout <ms>` |
| `frame scan <path> --ai` | Adds LLM detection + triage on top of the symbolic tier. Needs `FRAME_LLM_BASE_URL` + `FRAME_LLM_MODEL` |
| `frame exploit --target <url>` | Drives an LLM agent to exploit a **live, authorized** target. `--guidance <findings.json>` primes it with scan output, `--goal`, `--success-check <shell>`, `--max-steps`, `--trace-out <file>` |
| `frame fix <path> --guidance <findings.json>` | Generates patches, then re-scans to verify the bug is gone. `--diff` (default) or `--in-place` |
| `frame solve "<P> \|- <Q>"` | Separation-logic entailment check |
| `frame check <file>` / `frame repl` / `frame parse "<formula>"` | Batch entailments / interactive REPL / AST dump |

`--ai`, `exploit`, and `fix` are LLM-driven and only run with the env vars below
configured. Plain `frame scan` is fully local and needs nothing.

## LLM configuration

Frame talks to any OpenAI-compatible endpoint:

```bash
export FRAME_LLM_BASE_URL=https://<gateway>/v1
export FRAME_LLM_MODEL=<model-id>
export FRAME_LLM_API_KEY=<key>        # optional for local endpoints
```

Without them, `--ai`/`exploit`/`fix` fail fast; the symbolic tier is unaffected.
Other knobs: `FRAME_LLM_TEMPERATURE`, `FRAME_LLM_MAX_TOKENS`,
`FRAME_LLM_TIMEOUT`, `FRAME_LLM_JSON_MODE`, `FRAME_LLM_CACHE`,
`FRAME_LLM_AGENT_MAX_TOKENS`, `FRAME_LLM_EXPLOIT_MAX_STEPS`,
`FRAME_LLM_CONTEXT_LINES`, `FRAME_LLM_REPO_ROOT`, `FRAME_AGGRESSIVE_DETECTORS`.

## Standard workflow

1. **Baseline scan, JSON out.**
   ```bash
   frame scan ./repo -f json -o /tmp/frame.json --fail-on none
   ```
   `--fail-on none` keeps the exit code at 0 so a pipeline does not abort on findings.

2. **Read `summary` and `findings[]`.** Each finding carries `type`, `severity`,
   `file`, `line`, `description`, `sink_type`, `cwe_id`, `confidence`. Findings are
   tiered: symbolic results are proven; `--ai` findings are heuristic. Never
   present an LLM-tier finding with the confidence of a symbolic one.

3. **Sharpen on a subset.** `-p '**/*.py'` for a directory; `-l python` selects the
   frontend. Supported symbolic frontends: Python, Java, JS/TS, C/C++, C#. The LLM
   tier covers anything else (PHP, Ruby, Go) but only in the LLM tier.

4. **Verify against a running target** (only in-scope, authorized):
   ```bash
   frame exploit --target http://localhost:8080 --guidance /tmp/frame.json \
     --goal 'read the admin secret' --trace-out /tmp/exploit-trace.json
   ```
   `--success-check` runs a shell command after each step; exit 0 means solved.

5. **Remediate and confirm.** `frame fix ./repo --guidance /tmp/frame.json --diff`
   re-scans the patched copy, so the patch is only reported clean when the
   verifier agrees.

6. **SARIF for CI/reporting.**
   ```bash
   frame scan ./repo -f sarif -o results.sarif --fail-on high
   ```

## Detection coverage

Injection (SQL/NoSQL/ORM, XSS, command/code, SSTI, LDAP/XPath/XML, header/log),
access control (IDOR/BOLA CWE-639, authz bypass, mass assignment, session
fixation, CSRF), data exposure (path traversal, SSRF, open redirect, XXE,
hardcoded secrets, insecure deserialization), memory safety in C/C++.

## Pitfalls

- `--no-verify` disables Z3 proof; results are unverified and noisier. Use it only
  for a fast first pass on a large tree, then re-scan the interesting paths verified.
- Directory scans skip `.git`, `node_modules`, `.venv`, `__pycache__`, tool caches
  by default; `--no-default-excludes` overrides.
- `frame fix --in-place` **edits the target repo**. Show the `--diff` first.
- Findings without a reachable sink from untrusted input are noise — trace the
  source before writing them up.
- Never point `exploit` at a target outside the program's in-scope list.
