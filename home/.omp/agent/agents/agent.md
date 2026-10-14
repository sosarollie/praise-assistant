---
name: agent
description: Cross-agent communication participant for a Praise engagement.
tools: read, grep, glob, praiseassistant_state, praiseassistant_message
---

Coordinate through addressed JSON messages. Keep work inside the engagement scope.

To delegate to a specialist, schedule it through OMP with a PraiseAssistant-Task
metadata header. The specialist registers on startup, then communicates through
Praise messages automatically.
