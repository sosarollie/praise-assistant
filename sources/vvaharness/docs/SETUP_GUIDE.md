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

# vvaharness — Setup Guide

Detailed install and configuration. For day-to-day usage and the full flag
reference, see **[USER_GUIDE.md](USER_GUIDE.md)**.

---

## 1. Prerequisites

| Need | Why |
|---|---|
| **Python ≥ 3.11** | required by package metadata. Installers reject older interpreters before any backend is selected. |
| **git** on `PATH` | required for batch clone mode (`--repo-file`). Also preferred, when present, by S10 fix mode — for the per-finding `git diff` artifact and as one layer of the edit-revert path. Without git both fall back to the harness's pre-edit snapshot: the diff is synthesized from it rather than being a real `git diff`, and revert uses the snapshot layer alone. Detection-only scans don't need it. |
| **External Claude Code CLI** | **not needed by any shipped profile's detection roles** — `default.yaml`, `taint.yaml` and `full.yaml` route every detection role plus S10/S11 `via: deepagents`, and `sdk.yaml` routes all of its `via: sdk`. It is required by the current S11 launcher when validation is spelled `via: cli` or `via: sdk`, and by any role you switch to `via: cli` yourself. All four exploit-verification roles ship `via: deepagents` in `default.yaml`, `full.yaml` and `taint.yaml`, and `via: sdk` in `sdk.yaml`. No shipped profile routes an EV role `via: cli`. SDK detection/S10 can use the Agent SDK's bundled executable. |
| **An Anthropic API key** | the one credential every shipped profile needs. `default.yaml`, `taint.yaml` and `full.yaml` route every detection role plus S10/S11 `via: deepagents` (Anthropic), which reads `ANTHROPIC_SDK_API_KEY`, `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` — any one covers a whole detection run. `sdk.yaml` prefers `ANTHROPIC_SDK_API_KEY` (the standard-key fallback applies while every role stays on sdk/deepagents). `OPENAI_API_KEY` is needed if you switch a role to `via: openai` yourself, and on `full.yaml` whenever you arm exploit verification — that profile ships its EV `judge` role on `provider: openai` (`via: deepagents`), so `full.yaml` additionally needs `OPENAI_API_KEY`, for its `judge` alone. |

---

## 2. Install

`vvaharness` is distributed as a source tree with a `pyproject.toml` — it is
**not** published to PyPI, so you install it **from this folder** rather than by
name. Installing it (any option below) builds the package into your environment
and puts the **`vvaharness`** command on your PATH, so you don't have to type
`python -m vvaharness …` each time. Run the commands from the project root
(where `pyproject.toml` lives). Pick the option that fits your platform.

Install under Python 3.11 or newer. If pip reports `No matching distribution
found` for `openai`, `claude-agent-sdk` or `deepagents`, the cause is the
interpreter, not a missing package — those are public on PyPI, and pip hides
releases whose own `Requires-Python` excludes your version. Rebuild the
environment under 3.11+ rather than relaxing any version constraint.

### Option A — pipx (recommended; fully isolated)

```bash
pipx install .
```

### Option B — virtual environment (recommended when pipx isn't available)

A venv keeps the install isolated; `vvaharness` is on your PATH whenever the
venv is active.

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip3 install .
vvaharness --help
```

**Windows — PowerShell**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
vvaharness --help
```

**Windows — cmd.exe**
```bat
python -m venv .venv
.\.venv\Scripts\activate.bat
pip install .
vvaharness --help
```

### Development install

```bash
pip install -e .     # editable — code changes take effect without reinstalling
```

All installs expose one command, **`vvaharness`**, and bundle the four
detection transports (Anthropic SDK, Claude CLI, OpenAI-compatible, and the
DeepAgents harness route) plus the DeepAgents/LangGraph agent
graph used by `remediate`/`validate`—you only need credentials
for the routes your config actually uses. All runtime
dependencies are declared in `pyproject.toml` and resolved by pip — there is
no separate requirements file and no extra flags needed. The tree-sitter
parsers for taint analysis are included in the standard install.

> **`vvaharness: command not found`?** The script directory isn't on your PATH.
> Use a venv (Option B), or fall
> back to `python3 -m vvaharness …` (works from any install, any OS).

---

## 3. Credentials & `.env`

```bash
cp .env.example .env
$EDITOR .env          # fill in the keys for the backends you use
```

`vvaharness` **auto-loads** the first trusted `.env` found at exactly the
current directory or user home, so you do **not** need to `source` it. It does
not search arbitrary ancestor directories. On POSIX, the file and its parent
must be owned by the current user and not group/world-writable. Variables you
export in your shell take precedence over `.env` (handy for CI). If the `.env`
resolves *inside* the `--repo` scan target (an attacker-influenced checkout), it
is ignored with a warning unless `VVAHARNESS_ALLOW_CWD_CONFIG=1` is set; that
opt-in does not bypass ownership or mode checks. The `.env.example` template
lists the common credential and endpoint variables:

| Variable | Backend / use |
|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | `via: cli` authentication (alternative to interactive `claude` → `/login`) |
| `ANTHROPIC_SDK_API_KEY` | direct `via: sdk` detection roles and `sdk.yaml` S10; it is not translated for S11, which uses external-Claude login/OAuth or standard Anthropic auth |
| `ANTHROPIC_SDK_BASE_URL` | optional gateway/region override for `via: sdk` |
| `ANTHROPIC_SDK_CA_CERT` / `ANTHROPIC_SDK_CLIENT_CERT` | optional absolute paths, interpolated into the profile's `sdk:` block — consumed by the direct Anthropic SDK detection transport and by Anthropic-routed `via: deepagents` **detection** roles (S10/S11 instead read `SSL_CERT_FILE` / `VVAHARNESS_TLS_CLIENT_CERT` from the process environment); the Claude Agent SDK paths (`sdk.yaml` S10/S11) do not consume them |
| `CLAUDE_CLI_CA_CERT` | optional absolute CA-bundle path for the direct `via: cli` adapter (→ `NODE_EXTRA_CA_CERTS` on its `claude` subprocess) |
| `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_BASE_URL` | DeepAgents with the Anthropic provider (default S10), and one authentication option for Agent-SDK S11; also substitutes for `ANTHROPIC_SDK_API_KEY` when every configured role is `via: sdk` or `via: deepagents` |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_CA_CERT` | key/base URL serve direct `via: openai` and DeepAgents/OpenAI; the CA var, interpolated into the profile's `openai:` block, serves the direct adapter and OpenAI-routed `via: deepagents` detection roles, and must be an absolute path |
| `SSL_CERT_FILE` / `SSL_CERT_DIR` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` | CA trust overrides for the DeepAgents clients — with a deliberate vendor split: Anthropic-routed roles honour **only** `SSL_CERT_FILE` / `SSL_CERT_DIR` (ambient `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` are ignored on that branch — see the notes under §3's TLS table), while OpenAI-routed roles honour all four. `SSL_CERT_FILE` is also the carrier the DeepAgents route uses for a profile `ca_cert` |
| `VVAHARNESS_TLS_CLIENT_CERT` (+ optional `VVAHARNESS_TLS_CLIENT_KEY`) | mTLS client certificate for every DeepAgents role (combined PEM, or cert + separate key); on detection roles the profile `client_cert` in the `sdk:`/`openai:` block sets it for you |
| `VVAHARNESS_PRICING_FILE` | optional path to an operator-supplied pricing table. No pricing is bundled: without it every stage's `cost_usd` is `null` in `run_manifest_*.json`, and one unpriced model also nulls the run total |
| `GITHUB_TOKEN` / `GIT_BASE_URL` | batch clone (`--repo-file`) of private repos / URL derivation |

**Interpolation of secret-named variables is restricted.** A `${VAR}` whose
name looks secret-bearing — it contains `API_KEY`, `APIKEY`, `TOKEN`,
`SECRET`, `PASSWORD`, `PASSWD`, `CREDENTIAL` or `PRIVATE_KEY`, or has an
`AUTH` name segment (as in `OAUTH` or `…_AUTH_…`) — may expand only into the
credential keys `sdk.api_key`, `openai.api_key`, `batch.git_token` and
`output.ingest_token`. Referencing one anywhere else in a profile is refused
at config load, whether or not the variable is set.

Start with the guided, no-spend readiness check:

```bash
vvaharness setup
```

Two optional flags extend it. `vvaharness setup --write-env` scaffolds a starter
`.env` from `.env.example` (which carries no `EV_*` variables, so an EV operator
still copies those from `.env.exploit.example` by hand). `vvaharness setup
--install-agents` writes the AI-agent instruction files (`AGENTS.md`,
`.github/copilot-instructions.md`, and `CLAUDE.md` plus a Claude skill when the
`claude` CLI is detected), never overwriting an existing file. Plain `setup` is
otherwise read-only, with one exception: run interactively (stdin is a TTY) with
remediation defaults missing, it prompts to persist an inputs directory.

After setup is green, optionally verify live connectivity. `doctor` sends a
small request to configured model backends and therefore spends model tokens:

```bash
vvaharness doctor
```

`doctor` honours `--config`, so `vvaharness doctor --config ./my.yaml` checks
the exact profile that scan will use.

### Claude Code CLI auth (S11 validation and any `via: cli` role)

Install the Claude Code CLI, then authenticate one of two ways:

- **Interactive:** run `claude`, then type `/login` inside the REPL.
- **Unattended / CI:** generate a token with `claude setup-token` and set
  `CLAUDE_CODE_OAUTH_TOKEN`.

### Exploit verification (optional; Beta — API only)

**Beta — API only.** Exploit verification needs a Postman/OpenAPI/Swagger
collection and can only verify findings that map to an HTTP endpoint;
everything else stays SAST-only. It is localhost-only, sends live attack
traffic, and is off unless `EV_API_COLLECTION` is set.

Two variables in `.env` switch it on — there is no CLI flag for either:

```bash
EV_API_COLLECTION=/abs/path/to/collection.json   # setting this is what enables EV
EV_TARGET_URL=http://127.0.0.1:5000              # scheme is mandatory; omitting the port defaults to 80/443
```

Postman v2 and OpenAPI 3.0 / Swagger 2.0 collections are auto-detected. **The
target must be on the local machine** — `127.0.0.0/8`, `::1`, or the name
`localhost` — enforced in code with no allowlist and no override; any other host
is refused. Exploit verification reads its own auth credentials from the
`EV_AUTH_*` environment variables only — never from a profile or a CLI flag — and
a collection may name the auth *scheme* but never a value. Other secrets can
still reach the target on the wire, so inventory all four channels: those
`EV_AUTH_*` variables, the client-key passphrase
`EV_TARGET_CLIENT_KEY_PASSPHRASE`, any token saved inside the collection's own
requests, and any hardcoded credential the attacker agent finds in the repository
and replays.
`.env.exploit.example` lists every `EV_AUTH_*` variable — copy the variables you need into `.env`
(only `.env`, resolved in the current directory or your home directory, is
loaded).

`.env.example`, `.env.exploit.example` and `docs/` are deliberately **not
packaged** with vvaharness — the install ships the `vvaharness` package only. An
operator who installed without a working copy of this source tree therefore has
neither the EV arming reference above nor the `docs/exploit-verification.md` it
points to; keep the source checkout (or copy those files from it) to reach them.

Check the setup cheaply before paying for a scan. `--stop-after ev` parses the
collection and probes the target's reachability, then stops **before S0** — no
call graph and no model spend:

```bash
vvaharness scan --repo /path/to/target --stop-after ev
```

A malformed collection fails at the gate and a dead target at the probe, both
exit `2`. Because `setup` and `doctor` run no exploit-verification checks —
they neither parse the collection nor probe the target — a green
`setup`/`doctor` says nothing about EV readiness, so this
`vvaharness scan --repo <path> --stop-after ev` run, with its offline
collection gate and reachability probe, is the EV readiness check. Full
reference: [exploit-verification.md](exploit-verification.md).

### Endpoints & TLS — base URLs and certificates

> **Public / subscription users: you can skip this whole section.** With just an
> Anthropic API key (`ANTHROPIC_SDK_API_KEY=sk-ant-…`) or a Claude CLI login
> (run `claude` then `/login`, or `claude setup-token`), the
> public endpoints are used automatically — **no base URL, no CA certificate,
> no extra flags.** This section is only for users behind a **private corporate
> AI gateway** (e.g. an internal endpoint with its own
> root CA). If that's not you, jump to *§4 Configuration profiles*.
>
> **Enterprise gateway, in short:** export `ANTHROPIC_BASE_URL=https://<gateway>/`,
> add `SSL_CERT_FILE=$HOME/cacerts.pem` if it uses a private CA (and
> `NODE_EXTRA_CA_CERTS=$HOME/cacerts.pem` too if the profile also uses the
> Node-based paths), and
> `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` if it returns `400 invalid beta flag`.
>
> **Prompt caching on a gateway costs nothing to check and a lot to miss.** Host
> detection only recognises Anthropic, Vertex and Bedrock, and fails closed on
> anything else — so on a profile that leaves `cache_route` unset, a working
> corporate gateway gets no cache markers on its `via: sdk` traffic and bills
> those prompt tokens uncached. Scope it before you chase it: only `via: sdk`
> reads `cache_route`, so on `default.yaml` — where every role is
> `via: deepagents` — it affects no shipped role at all: `cache_route` is
> inert there unless you re-route a role to `via: sdk` yourself, and
> `default.yaml` and `sdk.yaml` already declare `anthropic` anyway. When
> `setup` detects a gateway it does not recognise it now says so and prints the
> one-line opt-in: put `cache_route: anthropic` in a `config.local.yaml` beside your
> profile (git-ignored, merged over it), then run `vvaharness doctor --cache-probe`
> to confirm the gateway really honours the markers before a real scan. Leave it
> unset if the gateway rejects `cache_control` fields — results are identical either
> way, this is purely cost. The advisory is only actionable on `full.yaml` /
> `taint.yaml` — the profiles that leave `cache_route` unset.
>
> **Note.** `vvaharness setup` prints the
> `ANTHROPIC_BASE_URL` / `SSL_CERT_FILE` fix lines only for `sdk.yaml`, whose
> roles are all `via: sdk`, and only when its Anthropic-endpoint check fails and
> `setup` has detected a CA bundle. On `default.yaml`, `full.yaml` and
> `taint.yaml`, whose Anthropic-routed roles are `via: deepagents`, `setup` does
> not print them. Behind a gateway on those profiles, set the variables
> yourself — `export ANTHROPIC_BASE_URL=https://<gateway>/`, plus
> `export SSL_CERT_FILE=$Path/certs.pem` (or `ANTHROPIC_SDK_CA_CERT`) if the
> gateway uses a private CA.
> One scope caveat on those CA lines: `SSL_CERT_FILE` is what the Python
> Anthropic clients (`via: sdk` detection, Anthropic-routed `via: deepagents`)
> read — or give them the profile's `ca_cert` (`ANTHROPIC_SDK_CA_CERT`).
> They ignore `NODE_EXTRA_CA_CERTS`, which covers only the **Node-based**
> paths (the `claude` subprocess and the Agent-SDK S11 launcher) and
> OpenAI-routed DeepAgents roles (details in the TLS notes below).

**Base URLs are optional.** If you set only the API key(s) and leave the
`*_BASE_URL` variables unset, vvaharness uses the official public endpoints
automatically — it does **not** fail:

- Anthropic (`via: sdk`) → `https://api.anthropic.com`
- OpenAI (`via: openai`) → `https://api.openai.com/v1`

Set a base URL only to point at an internal gateway, a specific region, or any
OpenAI-compatible endpoint.

**A certificate is _never_ required for public endpoints.** TLS settings—the `ca_cert` /
`client_cert` config keys, `verify_ssl`, and every `*_CA_CERT` /
`*_CLIENT_CERT` env var—are optional on every route that reads them. Prefer
absolute paths for certificate env values: after `${VAR}` interpolation the
value lands in the profile's transport block, and a relative path there
resolves against the **selected YAML profile's directory** (not `.env`'s
location or the process working directory); network/UNC paths are refused. A
`via: deepagents` detection role reads `verify_ssl`, `ca_cert`, and
`client_cert` from
the `sdk:` (Anthropic) or `openai:` (OpenAI-compatible) block matching its
resolved vendor — never the `cli:` block — on top of provider base URLs and
normal process trust variables. When
their env vars are unset they expand to empty and inject **nothing**: no custom
HTTP client on the SDK/OpenAI side, no environment change on the `claude`
subprocess. Because `default.yaml` routes every stage S1–S11
`via: deepagents` (Anthropic), one credential covers a full run — any of
`ANTHROPIC_SDK_API_KEY`, `ANTHROPIC_API_KEY`, or `ANTHROPIC_AUTH_TOKEN` (see
§1); the SDK-named one takes precedence and is the only one that also carries
this `sdk:` block's gateway/mTLS settings. You add a cert only when
something in front of the endpoint demands it.

**When is a certificate needed?** Only behind a private gateway or a
TLS-intercepting corporate proxy whose server certificate chains to an
**internal root CA that isn't in your OS trust store**. For the public official
APIs (`api.anthropic.com`, `api.openai.com`) you need **no certificate and no CA
bundle at all** — the system trust store validates them.

| Situation | What to set | Applies to |
|---|---|---|
| Public endpoint (`api.anthropic.com` / `api.openai.com`) + a normal API key | **nothing** TLS-related | all backends |
| Private gateway / intercepting proxy whose server cert chains to an **internal root CA** | the per-backend or generic CA bundle env var (see table below) | sdk, openai, cli, deepagents |
| Gateway requires **mutual TLS (mTLS)** | `ANTHROPIC_SDK_CLIENT_CERT` (→ `sdk:` block) or `client_cert` in the `openai:` block for detection roles; `VVAHARNESS_TLS_CLIENT_CERT` in the environment for S10/S11 | direct Anthropic SDK detection, and every `via: deepagents` role — including the default S10/S11; not `via: cli`, direct `via: openai`, or the Claude Agent SDK S10/S11 paths |
| Throwaway/test env where you must skip verification (**insecure**) | `verify_ssl: false` in the backend's config block | sdk, openai, cli, deepagents (reads the matching `sdk:`/`openai:` block) |

Per-backend env vars / config keys:

| Backend (`via:`) | CA bundle (private/internal root CA) | mTLS client cert | Disable verification (insecure) |
|---|---|---|---|
| `sdk` (Anthropic) | `ANTHROPIC_SDK_CA_CERT` | `ANTHROPIC_SDK_CLIENT_CERT` | `verify_ssl: false` in the `sdk:` block |
| `openai` | `OPENAI_CA_CERT` | **not supported** | `verify_ssl: false` in the `openai:` block |
| `cli` (`claude` subprocess) | `CLAUDE_CLI_CA_CERT` → `NODE_EXTRA_CA_CERTS` | **not supported** (Node exposes no env path) | `verify_ssl: false` → `NODE_TLS_REJECT_UNAUTHORIZED=0` on the subprocess |
| `deepagents` | `ca_cert` in the matching `sdk:`/`openai:` block (detection roles; carried as `SSL_CERT_FILE`), or ambient trust — Anthropic-routed roles read `SSL_CERT_FILE` / `SSL_CERT_DIR` **only**; OpenAI-routed roles also read `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` | `client_cert` in the matching `sdk:`/`openai:` block (detection roles), or `VVAHARNESS_TLS_CLIENT_CERT` on any deepagents role (+ `VVAHARNESS_TLS_CLIENT_KEY` for a split key) | `verify_ssl: false` in the matching `sdk:`/`openai:` block (detection roles; loud MITM warning; a configured `ca_cert` wins over it) |

Notes:
- **mTLS is exposed by the direct Anthropic SDK transport and by every
  `via: deepagents` role** — including the default S10/S11. Detection roles
  read `verify_ssl` / `ca_cert` / `client_cert` from the `sdk:` (Anthropic)
  or `openai:` (OpenAI-compatible) block matching the role's resolved vendor,
  and never the `cli:` block; S10/S11 read `SSL_CERT_FILE` and
  `VVAHARNESS_TLS_CLIENT_CERT` from the process environment instead. Neither the direct
  OpenAI backend nor the direct `claude` CLI backend exposes a client-certificate
  path (Node exposes no env path for one). The Claude Agent SDK paths used by
  `sdk.yaml` S10/S11 still do not consume `ANTHROPIC_SDK_CLIENT_CERT`; a
  gateway that requires mTLS cannot serve those two routes.
- The `via: cli` backend injects TLS settings into the `claude` **subprocess**
  environment: `CLAUDE_CLI_CA_CERT` becomes `NODE_EXTRA_CA_CERTS`, and
  `verify_ssl: false` becomes `NODE_TLS_REJECT_UNAUTHORIZED=0`. Auth and
  endpoint are left to the CLI's own precedence (run `claude` then `/login`, or
  `CLAUDE_CODE_OAUTH_TOKEN`; `ANTHROPIC_BASE_URL` if already exported).
- A CA-cert path takes precedence over `verify_ssl` — uniformly on the `sdk`,
  `openai`, and `deepagents` routes — so a profile carrying both `ca_cert` and
  a leftover `verify_ssl: false` verifies against the private CA rather than
  running unverified. What happens when the path is set but the file is
  **missing** differs by route: `via: sdk` and `via: openai` warn and fall
  back to the block's `verify_ssl` setting, while `via: deepagents` (every
  role in `default.yaml`) fails the run — as it also does when `SSL_CERT_DIR`
  points at a directory that does not exist. A **present-but-malformed**
  CA bundle fails the run on every route (fail closed) — continuing on system
  trust would silently drop the operator's CA pin.
- **The Anthropic branch of the DeepAgents route ignores ambient
  `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE` — deliberately.** Those
  conventions are *additive* in their home tools, but here a CA path
  *replaces* system trust, so honouring a corporate-proxy CA ambiently would
  break public `api.anthropic.com` on any machine that merely exports them. A
  private-CA Anthropic gateway therefore needs `sdk.ca_cert`
  (`ANTHROPIC_SDK_CA_CERT`) or ambient `SSL_CERT_FILE` / `SSL_CERT_DIR`;
  anything else ends in `CERTIFICATE_VERIFY_FAILED`. The OpenAI-compatible
  branch honours the broader ambient set for historical compatibility.
- **mTLS failing to activate is a warning, not an error.** A `client_cert`
  chain that cannot be loaded — e.g. the path points at a CA bundle instead
  of a client certificate — prints
  `client_cert '<path>' could not be loaded (…) — mTLS is NOT active` and the
  run continues with server-authenticated TLS only. If an mTLS gateway
  rejects the connection, check stderr for that warning first.
- `verify_ssl` accepts a native YAML boolean (`true` / `false`) **or** a string
  boolean (`"false"`, `"true"`, `"0"`, `"1"`, `"no"`, `"yes"`, …). This matters
  when the value is supplied via an environment template such as
  `verify_ssl: ${VERIFY_SSL:-false}` (which expands to a string): the string is
  coerced to a real boolean, so `"false"` disables verification rather than
  being mistaken for a CA-bundle path. Any other string is still treated as a
  CA-bundle path.
- When a custom CA, verify-off, or mTLS is configured, the `sdk` / `openai`
  backends build their HTTP client via the SDK's own `DefaultHttpxClient`, so
  the tuned timeouts (~600 s) and the larger connection pool are preserved.
  The DeepAgents route does the same: its Anthropic branch injects
  `anthropic.DefaultHttpxClient` / `DefaultAsyncHttpxClient` and its OpenAI
  branch `openai.DefaultHttpxClient` / `DefaultAsyncHttpxClient`, so
  follow-redirects, connection limits, and TCP keepalive match a stock
  client — only the TLS `verify` material differs (robustness detail; no
  user-facing config).

---

## 4. Configuration profiles

`vvaharness` ships four profiles under `vvaharness/config/profiles/`:

- **`default.yaml`** — all-DeepAgents layout. S1–S9 (detection) run
  `via: deepagents` (`provider: anthropic`) on `claude-opus-4-7`
  (S1 `preprocess`: `claude-sonnet-4-6`). S10 remediate uses
  `claude-opus-4-8`, and S11 validation's orchestrator uses `claude-opus-5`.
  One credential covers every stage — any of `ANTHROPIC_SDK_API_KEY`
  (highest precedence, and the only one carrying the `sdk:` gateway/mTLS
  settings), `ANTHROPIC_API_KEY`, or `ANTHROPIC_AUTH_TOKEN`. No shipped
  profile runs the full S1–S11 pipeline on a
  Claude Code login alone. Used automatically when no `./config.yaml` is
  present. Detection tooling is read-only: `preprocess` and `verify` get the
  read-only Read/Glob/Grep agent graph, the other detection roles run a
  single completion with no tools, and no shipped profile grants Bash; see
  [`security.md`](security.md).
- **`sdk.yaml`** — every configured role is spelled `via: sdk`. Detection uses
  the Anthropic Python SDK, S10 translates `ANTHROPIC_SDK_API_KEY` into its
  Claude Agent SDK environment, and S11 uses the same Harness but pins an
  external `claude` executable. S11 can reuse Claude login/
  `CLAUDE_CODE_OAUTH_TOKEN`, or standard `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN`; the SDK-named key alone is not translated on that
  path. A standard Anthropic credential alone can cover the profile because
  sole-SDK detection accepts it as fallback. No route grants Bash. Its deepdive
  is temperature-capable (`0.4`), which is what majority voting requires, but the
  profile ships `step4.runs: 1` / `vote_threshold: 1`, so voting is **off**
  unless you raise `runs` yourself. `full.yaml` is the profile that ships voting
  on (`runs: 3` / `vote_threshold: 2`).
- **`full.yaml`** — the template for a multi-backend layout, and the only
  shipped profile with s4 voting on. **As shipped every role is
  `via: deepagents` (Anthropic)**, so one Anthropic credential runs it out of
  the box; commented `via: cli` / `via: sdk` / `via: openai` alternatives sit
  beside the roles that accept them. Uncomment a `via: cli` role and you must
  add Claude CLI auth; uncomment a `via: openai` role and you must add
  `OPENAI_API_KEY`. Copy it and edit:

  ```bash
  cp vvaharness/config/profiles/full.yaml ./config.yaml
  $EDITOR ./config.yaml
  ```

- **`taint.yaml`** — taint-first source→sink scanning with the callgraph engine.
  `default.yaml`, `full.yaml` and `taint.yaml` all enable the tree-sitter S0
  callgraph, but in different modes: `taint.yaml` uses **rules mode** (empty
  seed without operator-supplied source/sink YAML), while `default.yaml` and
  `full.yaml` use **LLM mode** (`callgraph_detection: llm` — a model-annotated
  seed that spends tokens).
  With a non-empty seed, Taint's `step1.mode: gap_fill` skips
  agentic S1 unless the repo has more than 500 source files, a
  web-api/web-app/service classification, and either zero sinks or at least
  10 entry points with fewer than 5 sinks. An empty seed is falsey and takes
  the agentic S1 path. The profile ships `catchall_mode: all` (full catch-all sweep;
  set `reachable_only` yourself to bound cost); confirm/refute prompt on taint
  chunks in S4 (single-run, Opus — `claude-opus-4-7` `via: deepagents`); the S9
  unreachable appendix (`output.emit_unreachable_appendix: true`) lists skipped
  files only when `reachable_only` is active. **S10 and S11 are disabled** in this
  profile (`step_remediate.enabled: false`, `step_validate.enabled: false`).
  Like `default.yaml` and `full.yaml`, every detection role is
  `via: deepagents` (Anthropic), so one Anthropic credential covers detection.
  The profile contains commented `via: cli` / `via: sdk` / `via: openai`
  alternatives for operators who intentionally switch backends. The profile's
  header comment (`vvaharness/config/profiles/taint.yaml`) is the canonical
  reference until full engine documentation exists. Use:
  `--config vvaharness/config/profiles/taint.yaml`.

S0 is profile-controlled via `step0.enabled`; `default.yaml`, `full.yaml`, and
`taint.yaml` enable it, while `sdk.yaml` disables it by omission.

### Generated source/sink rule files (taint profile)

S0 rules mode requires at least one usable generated source/sink rule file to
produce static matches. No generated source/sink corpus or implicit heuristic
baseline is bundled. With neither file, S0 returns an empty seed and the later
pipeline continues. In `taint.yaml`, that empty `SeedPackage` is falsey, so
`step1.mode: gap_fill` takes the agentic S1 path; the four-part gap-fill
escalation predicate is evaluated only for a non-empty seed.

To produce a rules-mode seed, generate external Semgrep-style source/sink files
from licensed local corpus clones and supply them through:

- `step0.sources_yaml` / `VVA_STEP0_SOURCES_YAML`
- `step0.sinks_yaml` / `VVA_STEP0_SINKS_YAML`

Those generated files are deliberately **not packaged** with vvaharness: their
third-party provenance and licences must remain explicit. `generic.kb.yaml` is
a different artifact used by S4's CWE confirm/refute prompt; it is not an S0
source/sink rule pack.

Build both files into an operator-owned directory. Do not write generated
artifacts into an installed `vvaharness/` package:

```bash
mkdir -p ./vvaharness-generated-rules
python -m vvaharness.rules.build_kb \
  --semgrep /path/to/semgrep-rules \
  --codeql /path/to/codeql \
  --sources-out ./vvaharness-generated-rules/sources.generated.yaml \
  --sinks-out ./vvaharness-generated-rules/sinks.generated.yaml
export VVA_STEP0_SOURCES_YAML="$PWD/vvaharness-generated-rules/sources.generated.yaml"
export VVA_STEP0_SINKS_YAML="$PWD/vvaharness-generated-rules/sinks.generated.yaml"
```

Build just one file (if you only have one corpus):

```bash
python -m vvaharness.rules.build_kb \
  --semgrep /path/to/semgrep-rules \
  --sources-out ./vvaharness-generated-rules/sources.generated.yaml
```

```bash
python -m vvaharness.rules.build_kb \
  --codeql /path/to/codeql \
  --sinks-out ./vvaharness-generated-rules/sinks.generated.yaml
```

Verify the files exist:

```bash
ls -lh ./vvaharness-generated-rules/sources.generated.yaml \
  ./vvaharness-generated-rules/sinks.generated.yaml
```

If you do not have corpus clones, the shipped profiles still run. `taint.yaml`'s
rules-mode S0 returns an empty seed and S1 continues agentically; `default.yaml`
and `full.yaml` already ship the LLM spec-discovery path
(`step0.callgraph_detection: llm`) — if annotation fails or yields no usable
specs, it falls back to the same configured external YAML. See
[vvaharness/rules/README.md](../vvaharness/rules/README.md) for the artifact
schemas, provenance requirements, and maintainer build workflow.

`vvaharness` automatically picks up a `./config.yaml` in the working directory
(it overrides the packaged default); `--config <file>` selects an explicit one.
A git-ignored `config.local.yaml` next to your config is deep-merged on top, for
machine-specific overrides you don't commit. On POSIX the overlay is honoured
only when the file is owned by you (or root) and not group/world-writable;
otherwise the command aborts with a config-overlay trust error telling you to
`chmod go-w` the file or set `VVAHARNESS_NO_LOCAL_CONFIG` to skip it.

Key sections (full reference in [configuration.md](configuration.md)):

- `models` — the `{id, via}` (plus `provider` on `via: deepagents`) per role
  (see §5).
- `step0` — deterministic seed enablement, mode, and external rule paths.
- `step1` … `step8` — per-stage budgets, exclusions, and tuning knobs.
- `step_remediate` / `step_validate` — the remediation (stage 10) and
  validation (stage 11) stages: `enabled`, budgets, and tool allowlists. In-scan
  S10/S11 are disabled in `default.yaml` and `taint.yaml`, and enabled in
  `sdk.yaml` and `full.yaml`. `--remediate` enables S10 only; S11 requires
  `step_validate.enabled: true` in the effective config (no scan `--validate`
  flag). Standalone `remediate` and `validate` remain available when disabled.
- `inject` — paths to optional context inputs (see §6).
- `batch` — clone token / base URL / skip patterns for `--repo-file` mode.
- `output.preserve_on_cleanup` — folders kept when a clone is purged.

> **Backend limits when repointing `models.remediate` / `models.validate`.**
> By default, `models.remediate` and `models.validate` both use `via: deepagents`
> with `ANTHROPIC_API_KEY`. If you
> override them: a `via: openai` validate role is routed to `via: deepagents` with
> the OpenAI provider, so it still needs `OPENAI_API_KEY` (plus `OPENAI_BASE_URL`
> for a custom endpoint). Remediation **fix mode** requires `via: cli`, `via: sdk`, or the
> repo-confined `via: deepagents` filesystem backend; a `via: openai` remediate
> role can only run `--mode report-only` (proposes fixes, applies none).
> Detection (S1–S9) and report-only remediation run on `via: cli`, `via: sdk`,
> or `via: openai`; every detection role also accepts `via: deepagents` — the
> single-shot roles (`autoexclude`, `graph_annotate`, `threatmodel`,
> `decompose`, `deepdive`, `dedup`, `chain`) as a zero-tool one-shot, and the
> agentic `preprocess` / `verify` as a read-only loop. See
> [models.md](models.md) and [remediation.md](remediation.md).

> **Scanning a less-trusted or sensitive target?** vvaharness assumes an
> authorized operator running against a trusted repository. For third-party code,
> forks, or anything an outside party can influence, apply the compensating
> controls in [`security.md` → Hardening for less-trusted or sensitive targets](security.md#hardening-for-less-trusted-or-sensitive-targets).

---

## 5. Backends & swapping roles

| `via:` | Transport | Auth | Notes |
|---|---|---|---|
| `cli` | `claude` CLI subprocess | run `claude` then `/login`, or `CLAUDE_CODE_OAUTH_TOKEN` | no shipped profile routes detection here by default — switch any role to `via: cli` yourself, and it is used by S11 validation. No shipped profile routes an EV role `via: cli`. Only backend capable of **Bash**, which still must be allowlisted |
| `sdk` | Anthropic Python SDK for detection; Claude Agent SDK for S10 fix/S11 | SDK key for detection/S10; S11 pins external `claude` and uses Claude login/OAuth or standard Anthropic auth (SDK key alone is insufficient) | detection honours `temperature`, `max_turns`; sandboxed Read/Glob/Grep; direct detection transport exposes **mTLS** (as does `via: deepagents` — see §3) |
| `openai` | OpenAI-compatible API | `OPENAI_API_KEY` | any compatible endpoint via `OPENAI_BASE_URL`; sandboxed Read/Glob/Grep |
| `deepagents` | DeepAgents/LangGraph harness: agent graph on S10/S11; a one-shot completion on the single-shot detection roles; a read-only agentic loop on `preprocess` and `verify` | `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` or `OPENAI_API_KEY` | S10 fix mode has repo-confined writes, S11 is read-only; the single-shot detection roles (`autoexclude`, `graph_annotate`, `threatmodel`, `decompose`, `deepdive`, `dedup`, `chain`) offer the model no tools at all; `preprocess` and `verify` get read-only Read/Glob/Grep; Bash denied |

The `cli`/`sdk` rows describe detection. S11 maps both selectors to the
read-only Claude Agent SDK Harness; S10 remains direct CLI for `via: cli` and
delegates fix-mode Edit/Write to the Agent SDK for `via: sdk`.

Swapping is config-only — no code change:

```yaml
models:
  deepdive: {id: <model-id>, via: openai}
  verify:   {id: <model-id>, via: sdk}
```

See [models.md](models.md) for the role→backend matrix.

---

## 6. Optional context inputs

The `inject` block points at optional files that enrich findings. Only the
`*.example.*` templates ship; copy them to the real names referenced by the
config (or point `inject.*` at your own paths):

```bash
cp inputs/cmdb.example.csv          inputs/cmdb.csv
cp inputs/known_cves.example.json   inputs/known_cves.json
cp inputs/design_controls.example.yaml inputs/design_controls.yaml
```

If a file is absent the pipeline still runs — the corresponding enrichment is
simply skipped (e.g. without a CMDB export, base CVSS + OffensivePriority are
still computed; only VulContextSeverity environmental scoring is skipped).

Relative `inject.*` paths resolve against the **active config's** directory, not
the target repo, so the `cp` recipe above only takes effect for a config whose
directory is the right number of levels above your `inputs/`. All four shipped
profiles use `../../../inputs/…` for `cve_file` / `controls_file` /
`cmdb_file`, which lands on the repo-root `inputs/` when you pass a profile in
place with `--config vvaharness/config/profiles/<profile>.yaml`. In a profile
copied to your own repo-root `./config.yaml`, that form resolves somewhere that
does not exist and you get `WARN: no CMDB file (<path>)` naming the path it
tried — harmless, and the scan continues. In a copied profile, rewrite those
three paths to `./inputs/…` or absolute paths (only `policy_file` /
`playbook_file` already ship as `./inputs/…`). The
real-data filenames (`inputs/cmdb.csv`, `inputs/repos.csv`,
`inputs/design_controls.yaml`, `inputs/known_cves.json`) are git-ignored, so
they aren't committed by an ordinary `git add` — only the shipped
`*.example.*` templates are tracked. (A `git add -f` can still force one in,
so don't override the ignore for a file holding real internal data.)

For batch scanning, see [repos-csv.md](repos-csv.md) and the example CSV at
`inputs/repos.example.csv` — copy it and delete everything above the
`AppId,RepoName,Path` header row first, because the CSV parser does not skip
the `#`-commented block the shipped file starts with.

---

## 7. Verifying the install

```bash
vvaharness --help
vvaharness doctor
vvaharness estimate --repo /path/to/some/repo
```

If `doctor` reports all configured backends present and reachable, you're ready
to `vvaharness scan` (see [USER_GUIDE.md](USER_GUIDE.md)).
