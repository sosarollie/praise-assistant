#!/usr/bin/env bash
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

# Stop hook: copies the Claude session transcript into the logging directory.
# The transcript contains the full conversation for all agents (top-level + sub-agents).
# Fail-open: if any step fails, exits 0 silently.
set +e

# The raw transcript is UNREDACTED (it can contain secrets/PII the agent read from
# the target repo). Persist it only when an operator explicitly opts in for debugging;
# by default it is never written, and the redacted session.jsonl is persisted instead.
[ -n "${VALIDATION_DEBUG_TRANSCRIPT:-}" ] || exit 0

_INPUT="$(cat)"
_TRANSCRIPT="$(echo "$_INPUT" | jq -r '.transcript_path // ""' 2>/dev/null | sed "s|^~|$HOME|")"
_LOG_DIR="${VALIDATION_LOG_DIR:-}"

[ -z "$_TRANSCRIPT" ] || [ ! -f "$_TRANSCRIPT" ] || [ -z "$_LOG_DIR" ] && exit 0

_DEST="$_LOG_DIR/subagents/transcript.jsonl"
mkdir -p "$(dirname "$_DEST")" 2>/dev/null
cp "$_TRANSCRIPT" "$_DEST" 2>/dev/null || true
exit 0
