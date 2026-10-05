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

"""ClaudeHarness: Claude Agent SDK concrete implementation of Harness."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import cast

from claude_agent_sdk import (
    ClaudeSDKClient,
    CLIConnectionError,
    CLIJSONDecodeError,
    CLINotFoundError,
    ProcessError,
    ResultMessage,
)
from claude_agent_sdk._errors import MessageParseError

from vvaharness.backends.harness.claude.models import SDK_ERROR_MAP
from vvaharness.backends.harness.claude.options import (
    build_oneshot_sdk_options,
    build_streaming_sdk_options,
)
from vvaharness.backends.harness.claude.translate import translate
from vvaharness.backends.harness.harness import Harness
from vvaharness.backends.harness.models import (
    HarnessCLINotFoundError,
    HarnessMessage,
    HarnessProcessError,
    HarnessResult,
    OneShotOptions,
    OneShotResult,
    StreamingOptions,
)
from vvaharness.util.tokens import TOKENS, TokenUsage


def _extract_sdk_persona_reports(session_id: str, cwd: object) -> list[dict]:
    """Read PersonaReport dicts from the last assistant message's JSON block in each transcript."""
    try:
        from claude_agent_sdk import (  # noqa: PLC0415 — optional SDK; absent build returns []
            get_subagent_messages,
            list_subagents,
        )
    except ImportError:
        return []
    try:
        agent_ids = list_subagents(session_id, directory=str(cwd))
        reports: list[dict] = []
        seen: set[tuple] = set()
        for agent_id in agent_ids:
            messages = get_subagent_messages(session_id, agent_id, directory=str(cwd))
            if not messages:
                continue
            for msg in reversed(messages):
                raw = getattr(msg, "message", {}) or {}
                content = raw.get("content", []) if isinstance(raw, dict) else []
                text = next(
                    (b.get("text", "") for b in content
                     if isinstance(b, dict) and b.get("type") == "text"),
                    "",
                )
                start = text.find("```json")
                end = text.find("```", start + 7) if start >= 0 else -1
                if start < 0 or end <= start:
                    continue
                try:
                    data = json.loads(text[start + 7:end].strip())
                    if isinstance(data, dict) and "persona" in data and "gates" in data:
                        key = (data.get("persona"), data.get("tracking_id"))
                        if key not in seen:
                            seen.add(key)
                            reports.append(data)
                except (ValueError, json.JSONDecodeError):
                    pass
                break
    except Exception:
        return []
    else:
        return reports


def _wrap_sdk_error(e: Exception) -> Exception:
    """Map an SDK exception to the appropriate HarnessError subclass."""
    if isinstance(e, ProcessError):
        return HarnessProcessError(
            str(e),
            exit_code=getattr(e, "exit_code", None),
            stderr=getattr(e, "stderr", None),
        )
    for sdk_type, harness_type in SDK_ERROR_MAP:
        if isinstance(e, sdk_type):
            return harness_type(str(e))
    return e


class ClaudeHarness(Harness):
    """Claude Agent SDK implementation of the Harness interface."""

    async def run_oneshot(
        self, prompt: str, options: OneShotOptions
    ) -> OneShotResult:
        """Run a single-turn invocation and return the structured result."""
        if options.cache_prefix:
            # No marker seam on the Agent SDK query path; the prefix is content.
            prompt = options.cache_prefix + prompt
        sdk_opts = build_oneshot_sdk_options(options)
        result_text: str | None = None
        structured: object = None
        subtype = ""
        is_error = False
        usage: TokenUsage | None = None
        total_cost_usd: float | None = None
        try:
            async with ClaudeSDKClient(options=sdk_opts) as client:
                await client.query(prompt)
                async for message in client.receive_response():
                    if isinstance(message, ResultMessage):
                        subtype = message.subtype
                        is_error = bool(message.is_error)
                        result_text = message.result
                        structured = message.structured_output
                        usage = cast("TokenUsage | None", message.usage)
                        total_cost_usd = message.total_cost_usd
                        # Feed process-wide counter; usage is cumulative per session.
                        TOKENS.add(usage, usd=total_cost_usd)
                        break
        except CLINotFoundError:
            raise HarnessCLINotFoundError(
                "Claude CLI binary not found"
            ) from None
        except (ProcessError, CLIConnectionError, CLIJSONDecodeError, MessageParseError) as e:
            raise _wrap_sdk_error(e) from e

        return OneShotResult(
            is_error=is_error,
            subtype=subtype,
            result_text=result_text,
            structured=structured,
            usage=usage,
            total_cost_usd=total_cost_usd,
        )

    def run_streaming(
        self, prompt: str, options: StreamingOptions
    ) -> AsyncIterator[HarnessMessage]:
        """Return an async iterator of typed harness messages for a streaming session."""
        sdk_opts = build_streaming_sdk_options(options)

        async def _gen() -> AsyncIterator[HarnessMessage]:
            try:
                async with ClaudeSDKClient(options=sdk_opts) as client:
                    await client.query(prompt)
                    async for message in client.receive_response():
                        for translated in translate(message):
                            if isinstance(translated, HarnessResult) and translated.session_id:
                                persona_dicts = _extract_sdk_persona_reports(
                                    translated.session_id, options.cwd
                                )
                                if persona_dicts:
                                    translated.state = {"sdk_persona_reports": persona_dicts}
                            yield translated
            except CLINotFoundError:
                raise HarnessCLINotFoundError(
                    "Claude CLI binary not found"
                ) from None
            except (ProcessError, CLIConnectionError, CLIJSONDecodeError, MessageParseError) as e:
                raise _wrap_sdk_error(e) from e

        return _gen()
