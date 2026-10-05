# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Wrapper around the `claude` CLI; all model calls go through here."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import cast

from vvaharness.backends.harness.models import AuthenticationError, ProxyError
from vvaharness.backends.llm import cache as _cache
from vvaharness.backends.llm.models import (
    CLI_CONN_TRANSIENT_RX,
    CLI_STATUS_429_RX,
    CLI_RETRYABLE_STATUS,
    CliConfig,
    EnvelopeResult,
    GuardrailBlocked,
    RATE_LIMIT_TRANSIENT_RX,
)
from vvaharness.backends.llm.tls import coerce_verify
from vvaharness.report.redact import redact
from vvaharness.util.json_extract import extract_json
from vvaharness.util.response_quality import check_response_quality, output_tokens_for_gate

# Token accounting is shared with the SDK backend (util/tokens.py); re-exported for legacy imports
from vvaharness.util.tokens import TOKENS, TokenUsage

# Only the main thread sees KeyboardInterrupt, so s4/s6 pool workers call abort() on Ctrl-C.

_ABORT = threading.Event()
_LIVE_LOCK = threading.Lock()
_LIVE: set[subprocess.Popen] = set()


def aborted() -> bool:
    return _ABORT.is_set()


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10)
        else:
            proc.kill()
    except Exception:
        pass


def abort() -> int:
    """Set the stop flag and kill every in-flight `claude` subprocess, returning the count signalled."""
    _ABORT.set()
    with _LIVE_LOCK:
        procs = list(_LIVE)
    for p in procs:
        _kill_tree(p)
    return len(procs)


def reset_abort() -> None:
    """Clear the global stop flag, so a programmatic abort() doesn't poison later repos in a batch run."""
    _ABORT.clear()


# Known canned-refusal strings from the classifier; exact match only, avoiding false positives.
_GUARDRAIL_REFUSALS = frozenset({
    "Your request was not allowed",
})


def _check_guardrail(env: dict) -> None:
    text = env.get("result")
    if (isinstance(text, str)
            and text.strip() in _GUARDRAIL_REFUSALS
            and (env.get("num_turns") or 1) <= 1
            and not env.get("is_error")):
        out_tok = ((env.get("usage") or {}).get("output_tokens"))
        raise GuardrailBlocked(
            "org content-guardrail blocked this prompt "
            f"(result={text!r}, num_turns={env.get('num_turns')}, "
            f"out_tok={out_tok}). The classifier on api.anthropic.com is "
            "rejecting the prompt content — this is NOT a pipeline bug. ")


def _spend_of(event: dict | None) -> tuple[int | None, float | None]:
    """(turns, usd) off a CLI result event, or (None, None) when it did not report them."""
    turns = (event or {}).get("num_turns")
    usd = (event or {}).get("total_cost_usd")
    return (turns if isinstance(turns, int) else None,
            float(usd) if isinstance(usd, (int, float)) else None)


def _parse_envelope(stdout: str) -> EnvelopeResult:
    """Parse `claude -p --output-format json` envelope (dict or list) into (result_text, usage)."""
    try:
        env = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        objs: list = []
        for ln in stdout.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                objs.append(json.loads(ln))
            except (json.JSONDecodeError, TypeError):
                continue
        if not objs:
            return EnvelopeResult(stdout.strip(), None)
        env = objs

    if isinstance(env, list):
        result_evt = next((e for e in reversed(env)
                           if isinstance(e, dict) and e.get("type") == "result"),
                          None)
        if result_evt:
            _check_guardrail(result_evt)
        usage = (result_evt or {}).get("usage")
        text = (result_evt or {}).get("result")
        if not isinstance(text, str) or not text.strip():
            last_asst = next(
                (e for e in reversed(env)
                 if isinstance(e, dict) and e.get("type") == "assistant"),
                None,
            )
            parts = [
                blk.get("text", "")
                for blk in ((last_asst or {}).get("message", {}) or {}).get("content", []) or []
                if isinstance(blk, dict) and blk.get("type") == "text"
            ]
            # No assistant text either: return "" (not the raw envelope) for a clean degrade.
            text = "".join(parts)
        turns, usd = _spend_of(result_evt)
        return EnvelopeResult(
            text.strip(), cast("TokenUsage", usage) if isinstance(usage, dict) else None,
            turns, usd,
        )

    if not isinstance(env, dict):
        return EnvelopeResult(stdout.strip(), None)
    _check_guardrail(env)
    result = env.get("result")
    if not isinstance(result, str):
        # Valid JSON envelope but no string result → empty, not the raw envelope.
        result = ""
    raw_usage = env.get("usage")
    turns, usd = _spend_of(env)
    return EnvelopeResult(
        result.strip(), cast("TokenUsage", raw_usage) if isinstance(raw_usage, dict) else None,
        turns, usd,
    )


# `cache_creation` is the per-TTL breakdown of cache_creation_input_tokens, whose total that
# field already carries — accounted for, not missed.
_PARSED_USAGE_CACHE_KEYS = frozenset({
    "cache_creation_input_tokens", "cache_read_input_tokens", "cache_creation",
})


def _note_unparsed_cache_keys(usage: dict | None) -> None:
    """Flag cache accounting the envelope reports under key names this module does not parse.

    Honest limitation of this route: the true wire response lives inside the `claude`
    subprocess and the envelope's `usage` is the CLI's own summary of it, so a gateway's foreign
    field names may never reach this dict at all — "no cache accounting observable" stays a
    legitimate outcome for `via: cli`.
    """
    _cache.report_unparsed_cache_keys(usage, _PARSED_USAGE_CACHE_KEYS,
                                      via="cli", label="cli")


def _find_claude_cmd() -> list[str]:
    """Resolve the claude CLI to an absolute-path command list, avoiding bare-name PATH resolution."""
    override = os.environ.get("VVAHARNESS_CLAUDE_BINARY")
    if override:
        if Path(override).is_file():
            print(f"  [cli] using VVAHARNESS_CLAUDE_BINARY={override}",
                  file=sys.stderr)
            return [override]
        print(f"  [cli] WARN: VVAHARNESS_CLAUDE_BINARY={override} not found; "
              f"falling back to PATH resolution", file=sys.stderr)
    if os.name == "nt":
        cmd_path = shutil.which("claude") or shutil.which("claude.cmd") or shutil.which("claude.CMD")
        if cmd_path:
            pkg = Path(cmd_path).parent / "node_modules" / "@anthropic-ai" / "claude-code"
            # ≥2.1.x ships a native binary — call it directly, no Node needed.
            native = pkg / "bin" / "claude.exe"
            if native.exists():
                return [str(native)]
            # ≤2.0.x: Node + cli.js
            cli_js = pkg / "cli.js"
            if cli_js.exists():
                node = shutil.which("node") or "node"
                return [node, str(cli_js)]
            # Last resort: the .cmd shim by full path — a bare "claude" fails WinError 2 on Windows.
            return [cmd_path]
        print("  [cli] WARN: 'claude' not found on PATH; using bare name",
              file=sys.stderr)
        return ["claude"]
    # Unix: pin to the absolute path PATH resolves to, instead of a bare name.
    resolved = shutil.which("claude")
    if resolved:
        return [resolved]
    print("  [cli] WARN: 'claude' not found on PATH; using bare name",
          file=sys.stderr)
    return ["claude"]


# Resolve once at import time
_CLAUDE_CMD = _find_claude_cmd()

# Ordered: acceptEdits never auto-approves Bash (no shell for injection); bypassPermissions last.
_PERMISSION_FALLBACKS = ("acceptEdits", "default", "bypassPermissions")

_caps_cache: dict | None = None


def _cli_capabilities() -> dict:
    """Probe `claude --help` once and memoise the flags/values this installed CLI accepts."""
    global _caps_cache
    if _caps_cache is not None:
        return _caps_cache
    help_text = ""
    try:
        r = subprocess.run([*_CLAUDE_CMD, "--help"], capture_output=True,
                           text=True, timeout=20)
        help_text = (r.stdout or "") + (r.stderr or "")
    except Exception:
        help_text = ""
    # Parse modes from choices list only; a blob scan false-matched "auto" in "auto-updater".
    modes: set[str] = set()
    m = re.search(r"--permission-mode\b.*?\(choices:\s*([^)]*)\)",
                  help_text, re.DOTALL)
    if m:
        modes = set(re.findall(r'"([^"]+)"', m.group(1)))
    _caps_cache = {
        "effort": "--effort" in help_text,
        "max_turns": "--max-turns" in help_text,
        "max_budget": "--max-budget-usd" in help_text,
        "permission_modes": modes,
        "probed": bool(help_text),
    }

    return _caps_cache


def _safe_permission_mode(requested: str) -> str:
    """Map a requested --permission-mode to one this CLI actually accepts, falling back if unsupported."""
    caps = _cli_capabilities()
    modes = caps["permission_modes"]
    if not modes:                      # couldn't read help — don't second-guess
        return requested
    if requested in modes:
        return requested
    for m in _PERMISSION_FALLBACKS:
        if m in modes:
            return m
    return next(iter(modes))


def _tail(text: str | None, n: int = 1200) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= n:
        return text
    return "...\n" + text[-n:]


def _short_cmd(cmd: list[str]) -> str:
    """Render argv with long args (system prompts) elided so error lines stay readable."""
    out = []
    for a in cmd:
        if len(a) > 80:
            head = a[:60].replace("\n", " ")
            out.append(f"{head}...<{len(a)} chars>")
        else:
            out.append(a)
    return " ".join(out)


def _extract_envelope_error(stdout: str | None) -> str | None:
    """If stdout is a claude --output-format json envelope carrying an error, return a one-line summary."""
    if not stdout:
        return None
    s = stdout.strip()
    # Anchor on whichever bracket comes first so the list envelope isn't truncated at an inner '{'.
    candidates = [p for p in (s.find("{"), s.find("[")) if p >= 0]
    if not candidates:
        return None
    try:
        env = json.loads(s[min(candidates):])
    except Exception:
        return None

    if isinstance(env, list):
        # Pull the terminal result event (or any error-bearing event).
        evt = next((e for e in reversed(env)
                    if isinstance(e, dict)
                    and (e.get("type") == "result"
                         or e.get("is_error")
                         or e.get("subtype") in ("error", "error_during_execution"))),
                   None)
        env = evt
    if not isinstance(env, dict):
        return None
    if not (env.get("is_error") or env.get("subtype") in ("error", "error_during_execution")):
        return None
    status = env.get("api_error_status")
    msg = env.get("result") or env.get("error") or env.get("message") or "unknown error"
    return f"{status} {msg}" if status else str(msg)


def _format_cli_error(prefix: str, cmd: list[str], result: subprocess.CompletedProcess) -> str:
    env_err = _extract_envelope_error(result.stdout)
    if env_err:
        return f"{prefix}: {env_err} (rc={result.returncode})"

    # stdout/stderr tails can include gateway/quoted-source tokens, so scrub before surfacing.
    # redact() runs BEFORE _tail(), never after: _tail keeps only the LAST n chars, so
    # redacting the tail lets a credential straddling the cut lose its leading anchor
    # (a JWT's `eyJ` header, a PEM's BEGIN line) and survive as an unmatched — and
    # therefore unmasked — suffix. Redacting the whole stream first masks it intact.
    err_tail = _tail(redact(result.stderr))
    out_tail = _tail(redact(result.stdout))
    parts = [
        f"{prefix} (rc={result.returncode})",
        f"cmd: {_short_cmd(cmd)}",
    ]
    if err_tail:
        parts.append(f"stderr tail:\n{err_tail}")
    if out_tail:
        parts.append(f"stdout tail:\n{out_tail}")
    if not err_tail and not out_tail:
        parts.append("no stdout/stderr captured")
    return "\n".join(parts)


# CLI reaches Node via env vars (ca_cert, verify_ssl, no_proxy); mTLS unsupported, no env path.

_cfg: CliConfig = {"verify_ssl": True, "ca_cert": None,
              "client_cert": None, "no_proxy": None, "effort": "high"}
_tls_extra: dict = {}


def _build_tls_env() -> dict:
    """Translate the stored TLS/proxy config into subprocess env vars."""
    out: dict = {}
    ca = _cfg["ca_cert"]
    verify = _cfg["verify_ssl"]
    # A CA bundle may arrive as ca_cert or string verify_ssl (mirrors sdk.py precedence).
    bundle = ca or (verify if isinstance(verify, str) else None)
    if bundle:
        if os.path.exists(bundle):
            out["NODE_EXTRA_CA_CERTS"] = bundle
        else:
            print(f"WARN [cli]: ca_cert '{bundle}' not found — not setting "
                  f"NODE_EXTRA_CA_CERTS for the claude subprocess",
                  file=sys.stderr)
    if verify is False:
        out["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        print("WARN [cli]: TLS verification disabled (verify_ssl=false) for the "
              "claude subprocess", file=sys.stderr)
    np = _cfg["no_proxy"]
    if np:
        out["NO_PROXY"] = np
        out["no_proxy"] = np
    if _cfg["client_cert"]:
        print("WARN [cli]: client_cert/mTLS is configured but the `claude` CLI "
              "backend cannot present a client certificate (Node exposes no "
              "env-var path for it). Use a `via: sdk` or `via: deepagents` "
              "role for mTLS gateways.",
              file=sys.stderr)
    return out


def configure(*, verify_ssl: bool | str | None = None,
              ca_cert: str | None = None,
              client_cert: str | tuple | None = None,
              no_proxy: str | None = None,
              effort: str | None = None) -> None:
    """Push gateway TLS/proxy settings into the `claude` subprocess environment; mTLS is unsupported here."""
    global _tls_extra
    if verify_ssl is not None:
        _cfg["verify_ssl"] = coerce_verify(verify_ssl)
    if ca_cert:
        _cfg["ca_cert"] = ca_cert
    if client_cert:
        _cfg["client_cert"] = client_cert
    if no_proxy:
        _cfg["no_proxy"] = no_proxy
    if effort:
        _cfg["effort"] = effort
    _tls_extra = _build_tls_env()


def _run(cmd: list[str], *, input: str | None = None,
         cwd: str | None = None, timeout: int = 600,
         env: dict | None = None,
         heartbeat_label: str | None = None,
         heartbeat_interval: int = 300,
         stream_cb=None) -> subprocess.CompletedProcess:
    """Central subprocess runner with optional periodic progress heartbeat."""
    proc_env = {**os.environ, **_tls_extra, **(env or {})}

    if stream_cb is not None:
        return _run_streaming(cmd, input=input, cwd=cwd, timeout=timeout,
                              proc_env=proc_env, stream_cb=stream_cb)

    if not heartbeat_label:
        return subprocess.run(
            cmd,
            input=input,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            env=proc_env,
            timeout=timeout,
        )

    start = time.monotonic()
    deadline = start + timeout
    pending_input = input

    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=proc_env,
    ) as proc:
        with _LIVE_LOCK:
            _LIVE.add(proc)
        try:
            while True:
                if _ABORT.is_set():
                    _kill_tree(proc)
                    out, err = proc.communicate()
                    raise RuntimeError("aborted by user (Ctrl-C)")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    out, err = proc.communicate()
                    raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)

                try:
                    out, err = proc.communicate(
                        input=pending_input,
                        timeout=min(float(heartbeat_interval), remaining),
                    )
                    break
                except subprocess.TimeoutExpired:
                    elapsed = int(time.monotonic() - start)
                    print(f"    [cli] {heartbeat_label} still running... {elapsed}s elapsed", file=sys.stderr)
                    pending_input = None
        except KeyboardInterrupt:
            _ABORT.set()
            _kill_tree(proc)
            try:
                proc.communicate(timeout=2)
            except Exception:
                pass
            raise
        finally:
            with _LIVE_LOCK:
                _LIVE.discard(proc)

        return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def _run_streaming(cmd: list[str], *, input: str | None, cwd: str | None,
                   timeout: int, proc_env: dict,
                   stream_cb) -> subprocess.CompletedProcess:
    """Run the CLI, forwarding each stdout line to *stream_cb* live, still capturing full output."""
    chunks: list[str] = []

    def _reader(pipe):
        for line in iter(pipe.readline, ""):
            chunks.append(line)
            try:
                stream_cb(line)
            except Exception:  # noqa: BLE001 — tracing must never break the run
                pass
        pipe.close()

    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=proc_env,
        bufsize=1,  # line-buffered
    ) as proc:
        with _LIVE_LOCK:
            _LIVE.add(proc)
        reader = threading.Thread(target=_reader, args=(proc.stdout,), daemon=True)
        reader.start()
        try:
            if input is not None:
                try:
                    proc.stdin.write(input)
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                reader.join(timeout=2)
                err = proc.stderr.read() if proc.stderr else ""
                raise subprocess.TimeoutExpired(
                    cmd, timeout, output="".join(chunks), stderr=err)
        except KeyboardInterrupt:
            _ABORT.set()
            _kill_tree(proc)
            raise
        finally:
            with _LIVE_LOCK:
                _LIVE.discard(proc)
        reader.join(timeout=5)
        err = proc.stderr.read() if proc.stderr else ""
    return subprocess.CompletedProcess(cmd, proc.returncode, "".join(chunks), err)


def stream_trace(line: str, *, out=None) -> None:
    """Render one `stream-json` event as a concise `--verbose` trace (tool calls, text, result)."""
    out = out or sys.stderr
    line = (line or "").strip()
    if not line:
        return
    try:
        evt = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return
    etype = evt.get("type")
    if etype == "assistant":
        for blk in (evt.get("message", {}) or {}).get("content", []) or []:
            if not isinstance(blk, dict):
                continue
            if blk.get("type") == "text" and blk.get("text", "").strip():
                print(f"    [agent] 💬 {redact(blk['text'].strip())[:400]}",
                      file=out, flush=True)
            elif blk.get("type") == "tool_use":
                name = blk.get("name", "?")
                args = blk.get("input", {}) or {}
                summ = ", ".join(f"{k}={v!r}" for k, v in args.items())
                summ = redact(summ)
                if len(summ) > 160:
                    summ = summ[:157] + "..."
                print(f"    [agent] 🔧 {name}({summ})", file=out, flush=True)
    elif etype == "user":
        # tool_result coming back to the model — show a short confirmation.
        for blk in (evt.get("message", {}) or {}).get("content", []) or []:
            if isinstance(blk, dict) and blk.get("type") == "tool_result":
                content = blk.get("content")
                if isinstance(content, list):
                    content = " ".join(
                        c.get("text", "") for c in content
                        if isinstance(c, dict))
                n = len(str(content or ""))
                print(f"    [agent] ↩ tool result ({n} chars)", file=out, flush=True)
    elif etype == "result":
        if evt.get("is_error"):
            print(f"    [agent] ✗ {redact(str(evt.get('result') or evt.get('error') or ''))[:200]}",
                  file=out, flush=True)


# The transient-prose classifiers (RATE_LIMIT_TRANSIENT_RX, CLI_CONN_TRANSIENT_RX) live in
# models.py, shared with the transport-owning backends.
# Hard usage-cap reset ("resets May 31, 7pm") — backoff won't help.
_RL_HARD_CAP = re.compile(r"hit your (usage )?limit.*resets", re.IGNORECASE)
_RL_MAX_RETRIES = 4
_RL_BACKOFF = (30, 60, 120, 240)
# A subprocess timeout retries at most this many times (may be a genuine hang), capping wall-clock.
_TIMEOUT_MAX_RETRIES = 1

# Claude Code may placeholder while sub-agents run; retry rather than treat it as empty output.
_PENDING_RESULT_RX = re.compile(
    r"__PENDING__"
    r"|still executing"
    r"|(?:task\s+is\s+)?still\s+pending"
    r"|waiting\s+for\s+(?:background\s+)?sub-?agent"
    r"|background\s+sub-?agent",
    re.IGNORECASE,
)
_PENDING_MAX_RETRIES = 3
_PENDING_BACKOFF = (5, 15, 30)


def _is_pending_result(text: str | None) -> bool:
    if not isinstance(text, str):
        return False
    return bool(_PENDING_RESULT_RX.search(text))


# Auth failures are synchronous, so 3 fast retries only absorb transient JWT clock-skew before
# we halt and ask the operator to refresh credentials (VVAH-E001).
_AUTH_FAILURE = re.compile(
    r"\b401\b"
    r"|unauthorized"
    r"|invalid[_ ]api[_ ]key"
    r"|invalid.*token|token.*(?:expired|invalid|revoked)"
    r"|authentication[_ ]failed"
    r"|access[_ ]denied",
    re.IGNORECASE,
)
_AUTH_MAX_RETRIES = 3
_AUTH_BACKOFF = (2, 4, 8)

# Proxy/TLS misconfiguration cannot heal on its own, so it is raised immediately (VVAH-E002).
_PROXY_FAILURE = re.compile(
    r"\b407\b"
    r"|proxy[_ ]auth"
    r"|tunnel[_ ](?:failed|error)"
    r"|CONNECT.*failed"
    r"|SSL.*CERTIFICATE"
    r"|CERTIFICATE.*VERIFY.*FAILED"
    r"|CERT_VERIFY_FAILED"
    r"|certificate[_ ]verify[_ ]failed",
    re.IGNORECASE,
)


def _terminal_result_fields(stdout: str | None
                            ) -> tuple[int | None, str | None, bool]:
    """Return (api_error_status, result_text, envelope_found) from the CLI's terminal result event."""
    if not stdout:
        return None, None, False
    s = stdout.strip()
    candidates = [p for p in (s.find("{"), s.find("[")) if p >= 0]
    if not candidates:
        return None, None, False
    try:
        env = json.loads(s[min(candidates):])
    except (json.JSONDecodeError, ValueError, TypeError):
        return None, None, False
    if isinstance(env, list):
        env = next((e for e in reversed(env)
                    if isinstance(e, dict) and e.get("type") == "result"), None)
        if env is None:
            return None, None, False      # truncated stream: no terminal event
    if not isinstance(env, dict):
        return None, None, False
    status = env.get("api_error_status")
    text = env.get("result") or env.get("error") or env.get("message")
    return (status if isinstance(status, int) else None,
            text if isinstance(text, str) else None,
            True)


def _is_transient_failure(result: subprocess.CompletedProcess) -> bool:
    """Classify a non-zero CLI exit: True only for a genuine transient worth retrying.
    Auth (VVAH-E001) and proxy (VVAH-E002) failures are handled by their own classifiers first."""
    status, text, found = _terminal_result_fields(result.stdout)
    if found:
        if status in CLI_RETRYABLE_STATUS:
            return True
        # A null-status transient phrase (e.g. "Overloaded") still retries; telemetry is separate.
        if status is None and text and (RATE_LIMIT_TRANSIENT_RX.search(text)
                                        or CLI_STATUS_429_RX.search(text)
                                        or CLI_CONN_TRANSIENT_RX.search(text)):
            return True
        return False
    # No parseable envelope: best-effort transient detection on raw text (no telemetry to match).
    blob = f"{result.stdout or ''}\n{result.stderr or ''}"
    return bool(RATE_LIMIT_TRANSIENT_RX.search(blob)
                or CLI_STATUS_429_RX.search(blob)
                or CLI_CONN_TRANSIENT_RX.search(blob))


def _is_auth_failure(result: subprocess.CompletedProcess) -> bool:
    """True when the CLI result indicates an authentication error (VVAH-E001)."""
    status, text, found = _terminal_result_fields(result.stdout)
    if found:
        if status == 401:
            return True
        return bool(text and _AUTH_FAILURE.search(text))
    blob = f"{result.stdout or ''}\n{result.stderr or ''}"
    return bool(_AUTH_FAILURE.search(blob))


def _is_proxy_failure(result: subprocess.CompletedProcess) -> bool:
    """True when the CLI result indicates a proxy/TLS error (VVAH-E002)."""
    status, text, found = _terminal_result_fields(result.stdout)
    if found:
        if status == 407:
            return True
        return bool(text and _PROXY_FAILURE.search(text))
    blob = f"{result.stdout or ''}\n{result.stderr or ''}"
    return bool(_PROXY_FAILURE.search(blob))


def _run_with_retry(cmd: list[str], *, label: str, **kw
                    ) -> subprocess.CompletedProcess:
    """_run() + exponential backoff on GENUINE transient failures only (see _is_transient_failure).
    Auth failures get _AUTH_MAX_RETRIES short retries then raise; proxy/TLS raises immediately."""
    attempt = 0
    auth_attempt = 0
    timeout_attempt = 0
    while True:
        try:
            result = _run(cmd, **kw)
        except subprocess.TimeoutExpired:
            # A timeout isn't a CompletedProcess; retry once (bounded) before propagating it.
            if _ABORT.is_set() or timeout_attempt >= _TIMEOUT_MAX_RETRIES:
                raise
            timeout_attempt += 1
            print(f"    [cli] {label}: timed out — retrying once "
                  f"({timeout_attempt}/{_TIMEOUT_MAX_RETRIES})", file=sys.stderr)
            continue
        if result.returncode == 0:
            return result
        _, text, _ = _terminal_result_fields(result.stdout)
        err_text = text or f"{result.stdout or ''}\n{result.stderr or ''}"
        if _is_proxy_failure(result):
            raise ProxyError(
                # redact() BEFORE [:400]: slicing first can cut a token mid-pattern,
                # leaving a prefix no redaction rule matches. Same trap as sdk.py.
                redact(err_text)[:400],
                status_code=407 if re.search(r"\b407\b", err_text) else None,
                backend="cli",
            )
        if _is_auth_failure(result):
            if auth_attempt < _AUTH_MAX_RETRIES:
                wait = _AUTH_BACKOFF[min(auth_attempt, len(_AUTH_BACKOFF) - 1)]
                print(f"    [cli] {label}: authentication error (attempt "
                      f"{auth_attempt + 1}/{_AUTH_MAX_RETRIES}); retrying in "
                      f"{wait}s", file=sys.stderr)
                time.sleep(wait)
                auth_attempt += 1
                continue
            raise AuthenticationError(redact(err_text)[:400], status_code=401,
                                      backend="cli")
        if _RL_HARD_CAP.search(err_text):
            print(f"    [cli] {label}: hard usage cap reached — not retrying",
                  file=sys.stderr)
            return result
        if attempt >= _RL_MAX_RETRIES or not _is_transient_failure(result):
            return result
        wait = _RL_BACKOFF[min(attempt, len(_RL_BACKOFF) - 1)]
        print(f"    [cli] {label}: transient upstream error (attempt "
              f"{attempt + 1}/{_RL_MAX_RETRIES}); retrying in {wait}s",
              file=sys.stderr)
        slept = 0
        while slept < wait:
            if _ABORT.is_set():
                raise RuntimeError("aborted by user (Ctrl-C)")
            time.sleep(min(5, wait - slept))
            slept += 5
        attempt += 1


def prompt(
    user_prompt: str | list[dict],
    *,
    model: str,
    system_prompt: str | None = None,
    json_schema: dict | None = None,
    output_format: str = "text",
    cwd: str | None = None,
    max_budget_usd: float | None = None,
    max_tokens: int | None = None,
    timeout: int = 1800,
    tag: str | None = None,
) -> str:
    """Single-shot prompt with no tools; returns the model's text response."""
    # The subprocess only accepts flat text, and this route never reaches the Messages API, so a
    # caller's cache_control markers are dropped with nothing lost — there is nothing to cache.
    if isinstance(user_prompt, list):
        user_prompt = "\n\n".join(
            b.get("text", "") for b in user_prompt
            if isinstance(b, dict) and b.get("type") == "text"
        )
    if _ABORT.is_set():
        raise RuntimeError("aborted by user (Ctrl-C)")
    cmd = [*_CLAUDE_CMD, "-p", "--model", model]
    if _cfg.get("effort") and _cli_capabilities()["effort"]:
        cmd += ["--effort", _cfg["effort"]]

    if system_prompt:
        cmd += ["--system-prompt", system_prompt]
    # Always request the JSON envelope (for .usage); text is unwrapped from .result on return.
    cmd += ["--output-format", "json"]
    if json_schema:
        cmd += ["--json-schema", json.dumps(json_schema)]
    # Forward the spend cap only when the CLI advertises --max-budget-usd (probe-gated).
    if max_budget_usd and _cli_capabilities().get("max_budget"):
        cmd += ["--max-budget-usd", str(max_budget_usd)]

    # Disable all tools — pure reasoning

    cmd += ["--tools", ""]

    # claude CLI reads max output tokens from env, not a flag.
    env = {"CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(max_tokens)} if max_tokens else None

    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [cli] prompt mode -> {model}{tag_sfx} ({len(user_prompt)} chars"
          f"{f', max_tokens={max_tokens}' if max_tokens else ''})",
          file=sys.stderr)

    result = _run_with_retry(
        cmd,
        label=f"prompt({model}){tag_sfx}",
        input=user_prompt,
        cwd=cwd,
        timeout=timeout,
        env=env,
        heartbeat_label=f"prompt mode ({model}){tag_sfx}",
    )

    if result.returncode != 0:
        raise RuntimeError(_format_cli_error("claude CLI failed", cmd, result))

    text, usage, turns, usd = _parse_envelope(result.stdout)
    _note_unparsed_cache_keys(usage)
    TOKENS.add(usage, usd=usd, turns=turns)
    if usage:
        _in = (int(usage.get('input_tokens', 0) or 0)
               + int(usage.get('cache_creation_input_tokens', 0) or 0)
               + int(usage.get('cache_read_input_tokens', 0) or 0))
        _cache_r = int(usage.get('cache_read_input_tokens', 0) or 0)
        _cache_w = int(usage.get('cache_creation_input_tokens', 0) or 0)
        _out = int(usage.get('output_tokens', 0) or 0)
        cache_info = f" (cache_read={_cache_r}, cache_write={_cache_w})" if (_cache_r or _cache_w) else ""
        print(f"    [cli] usage: in={_in}{cache_info} out={_out}", file=sys.stderr)
    _out_tokens = int((usage or {}).get("output_tokens", 0) or 0)
    check_response_quality(text, stage=tag or "",
                           output_tokens=output_tokens_for_gate(usage))
    return text


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,
    permission_mode: str = "auto",
    max_turns: int | None = None,  # only if CLI advertises it; else timeout bounds the loop.
    tag: str | None = None,
    stream_cb=None,                # optional: raw stream-json callback, live (--verbose trace).
    extra_tools=None,              # accepted for signature parity with the sdk /
    extra_dispatch=None,           # openai loops; the CLI cannot carry them (see
    # the guard below) and rejects them loudly.
) -> str:
    """Agentic mode — Claude gets tools to explore the repo (reads files, greps, etc.)."""

    # The CLI runs its loop inside a subprocess that only exposes its own
    # built-in tools, so it cannot carry a caller-supplied tool (e.g. exploit
    # verification's http_request). Fail before spawning anything and name the
    # backends that can. extra_dispatch is meaningless without extra_tools, so
    # keying the guard on extra_tools covers the pair.
    if extra_tools:
        raise NotImplementedError(
            "claude_cli.agentic cannot carry a caller-supplied tool; the CLI "
            "subprocess only exposes its own built-in tools. Route to via: sdk "
            "or via: openai for a loop that accepts extra_tools/extra_dispatch.")

    if _ABORT.is_set():
        raise RuntimeError("aborted by user (Ctrl-C)")
    cmd = [*_CLAUDE_CMD, "-p", "--model", model]
    if _cfg.get("effort") and _cli_capabilities()["effort"]:
        cmd += ["--effort", _cfg["effort"]]

    if system_prompt:
        cmd += ["--system-prompt", system_prompt]
    if allowed_tools:
        # Honour the allowlist as-given; Bash is never force-added (repos could prompt-inject RCE).
        cmd += ["--allowedTools"] + list(allowed_tools)
    # Forward the spend cap only when the CLI advertises --max-budget-usd (probe-gated).
    if max_budget_usd and _cli_capabilities().get("max_budget"):
        cmd += ["--max-budget-usd", str(max_budget_usd)]
    # Cap the loop only when the CLI accepts --max-turns (probe-gated), avoiding old-build errors.
    if max_turns and _cli_capabilities().get("max_turns"):
        cmd += ["--max-turns", str(int(max_turns))]

    cmd += ["--permission-mode", _safe_permission_mode(permission_mode)]
    cmd += ["--output-format", "stream-json", "--verbose"]

    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [cli] agentic mode -> {model}{tag_sfx}, cwd={cwd}", file=sys.stderr)

    # When streaming the live trace, the callback shows progress, so the heartbeat is suppressed.
    pending_attempt = 0
    while True:
        result = _run_with_retry(
            cmd,
            label=f"agentic({model}){tag_sfx}",
            input=user_prompt,
            cwd=cwd,
            timeout=3600,
            heartbeat_label=(None if stream_cb
                             else f"agentic mode ({model}){tag_sfx}"),
            stream_cb=stream_cb,
        )

        if result.returncode != 0:
            raise RuntimeError(_format_cli_error("claude CLI agentic failed", cmd, result))

        text, usage, turns, usd = _parse_envelope(result.stdout)
        _note_unparsed_cache_keys(usage)
        TOKENS.add(usage, usd=usd, turns=turns)
        if usage:
            _in = (int(usage.get('input_tokens', 0) or 0)
                   + int(usage.get('cache_creation_input_tokens', 0) or 0)
                   + int(usage.get('cache_read_input_tokens', 0) or 0))
            _cache_r = int(usage.get('cache_read_input_tokens', 0) or 0)
            _cache_w = int(usage.get('cache_creation_input_tokens', 0) or 0)
            _out = int(usage.get('output_tokens', 0) or 0)
            cache_info = f" (cache_read={_cache_r}, cache_write={_cache_w})" if (_cache_r or _cache_w) else ""
            print(f"    [cli] usage: in={_in}{cache_info} out={_out}", file=sys.stderr)

        if not _is_pending_result(text):
            return text

        pending_attempt += 1
        snippet = redact((text or "").strip().replace("\n", " "))[:200]
        if pending_attempt > _PENDING_MAX_RETRIES:
            raise RuntimeError(
                "claude CLI agentic returned an unfinished background-subagent "
                f"state after {_PENDING_MAX_RETRIES} retries; refusing to "
                f"continue with partial output. last_result={snippet!r}"
            )
        wait = _PENDING_BACKOFF[min(pending_attempt - 1,
                                    len(_PENDING_BACKOFF) - 1)]
        print(
            f"    [cli] agentic returned pending output; retrying in {wait}s "
            f"({pending_attempt}/{_PENDING_MAX_RETRIES})",
            file=sys.stderr,
        )
        slept = 0
        while slept < wait:
            if _ABORT.is_set():
                raise RuntimeError("aborted by user (Ctrl-C)")
            step = min(5, wait - slept)
            time.sleep(step)
            slept += step


def parse_json_response(text: str) -> dict | list:
    """Extract the actual JSON content from a `--output-format json` wrapped response."""
    try:
        envelope = json.loads(text)
        if isinstance(envelope, dict) and "result" in envelope:
            content = envelope["result"]
            if isinstance(content, str):
                return json.loads(content)
            return content
        return envelope
    except (json.JSONDecodeError, TypeError):
        pass

    return extract_json(text)
