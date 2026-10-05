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

"""Structured-output strategy selection: schema construction and per-provider overrides."""

from __future__ import annotations

from typing import Any

from langchain.agents.structured_output import ToolStrategy
from pydantic import BaseModel, Field, create_model

from vvaharness.backends.harness.models import OneShotOptions
from vvaharness.backends.harness.provider_routing import routes_to_anthropic


def _pydantic_response_format(schema: dict[str, Any]) -> type[BaseModel]:
    """Build an anonymous Pydantic model suitable for ToolStrategy."""
    type_map: dict[str, type] = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    required = set(schema.get("required", ()))
    fields: dict[str, tuple[type, Any]] = {}
    for name, prop in schema.get("properties", {}).items():
        base = type_map.get(prop.get("type"), str)
        default = Field(...) if name in required else Field(default=None)
        fields[name] = (base, default)
    return create_model("HarnessResponse", **fields)  # type: ignore[arg-type]


def _strategy_for(schema: type, model_id: str, provider: str | None) -> ToolStrategy | type:
    """Force tool-calling on the Anthropic route; every other route gets the bare schema."""
    if routes_to_anthropic(model_id, provider):
        return ToolStrategy(schema=schema)
    return schema


def _response_format(
    response_model: type | None, model_id: str, provider: str | None
) -> ToolStrategy | type | None:
    """Wrap an injected Pydantic model class as a strategy (None when unset)."""
    if response_model is None:
        return None
    return _strategy_for(response_model, model_id, provider)


def _oneshot_response_format(
    options: OneShotOptions,
) -> ToolStrategy | type | None:
    """Prefer an injected Pydantic model; else derive one from a JSON output schema."""
    if options.response_model is not None:
        return _strategy_for(options.response_model, options.model, options.model_provider)
    if options.output_schema is not None:
        derived = _pydantic_response_format(dict(options.output_schema))
        return _strategy_for(derived, options.model, options.model_provider)
    return None
