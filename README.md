# Praise

Praise is a lightweight, communication-focused multi-agent coordination layer for OMP.
## What Praise Provides

- One engagement-bound SQLite state store.
- Agent registration with short local ids such as `a1`, `a2`.
- Addressed JSON messages: `ask`, `reply`, and `close`.
- Durable inboxes and audit projection recovery.
- A configured lead launcher.
- Role/model catalog generation for installed OMP integrations.

## Repository Layout

```text
praise/
  roles.json               # Source of truth for lead, communication roles, models
  cli.py                   # CLI commands
  runtime.py               # State, registration, messaging, scope
  policy.py                # Engagement asset validation
  evidence.py              # Evidence hashing helpers
scripts/
  install.py               # Installs OMP integration
home/.omp/agent/           # Owned OMP roles, extension, skills, rules
```

## Prerequisites

- Python 3.11 or newer.
- OMP installed and authenticated with your providers.
- Recommended OMP version: 18.6.1.

## Installation

```sh
cd /home/kali/Projects/praise-LLM-Assistant
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python scripts/install.py
export PATH="$HOME/.local/bin:$PATH"
praise --help
```

The installer deploys owned roles, extension files, workflow skills, rules, and the `praise` launcher.

## Engagement Setup

Initialize one engagement directory per coordination boundary.

```sh
export ENGAGEMENT="$HOME/pentest-workspace/my-project"
mkdir -p "$ENGAGEMENT"
praise init --directory "$ENGAGEMENT" \
  --program 'Coordination project' \
  --basis 'Agreed scope and operating rules' \
  --asset '/absolute/source/or/url' \
  --mode source
```

## Cross-Agent Communication

Register participants.

```sh
praise --engagement "$ENGAGEMENT" register \
  --session session-a --name worker-a --role agent \
  --model opencode-go/cat-jam-free:xhigh

praise --engagement "$ENGAGEMENT" register \
  --session session-b --name coordinator --role coordinator \
  --model opencode-go/cat-jam-free:xhigh
```

Send a message.

```sh
praise --engagement "$ENGAGEMENT" message \
  --from a1 --model opencode-go/cat-jam-free:xhigh \
  --to a2 --kind ask --data '{"need":"example"}'
```

Read messages.

```sh
praise --engagement "$ENGAGEMENT" inbox --agent a2
```

## Provider and Model Configuration

Praise maps roles to
model selectors in `praise/roles.json` and updates `~/.omp/agent/config.yml`.

### 1. Edit `praise/roles.json`

This is the source of truth for role and model assignment.

```json
{
  "schema_version": 2,
  "lead_model": "opencode-go/cat-jam-free:xhigh",
  "lead_recovery_model": "opencode-go/cat-jam-free:xhigh",
  "stages": {},
  "escalations": {},
  "experts": {},
  "roles": {
    "agent": {
      "models": ["opencode-go/cat-jam-free:xhigh"]
    },
    "coordinator": {
      "models": ["opencode-go/cat-jam-free:xhigh"]
    }
  }
}
```

Guidelines:

- Set `lead_model` to the model you want as session lead.
- Add one role per responsibility in your workflow.
- Use the smallest suitable model for each role.
- Use different families when you want independent judgment.
- Re-run `python scripts/install.py --overwrite` after changing this file.

### 2. Common provider selectors

Use provider prefixes that match your OMP installation, for example:

- `openai/...`
- `anthropic/...`
- `google/...`
- `opencode-go/...`
- `openai-codex/...`

Examples:

```json
"models": ["anthropic/claude-sonnet-4-5"]
"models": ["openai/gpt-4.1"]
"models": ["google/gemini-2.5-pro"]
```

### 3. Customize OMP role overrides

After installation, `~/.omp/agent/config.yml` contains generated role overrides:

```yaml
task:
  agentModelOverrides:
    agent: opencode-go/cat-jam-free:xhigh
    coordinator: opencode-go/cat-jam-free:xhigh
```

You may adjust these manually. Avoid assigning a higher-cost model when a lighter model
can perform the same communication task.

## Selecting Models For Existing Roles

The communication roles are predefined. Users do not implement custom roles. Each role
has its own model selector, and users choose which model to assign.

Current roles:

- `lead`
- `agent`
- `coordinator`

To change a role model:

1. Update `praise/roles.json`:

```json
"agent": {
  "models": ["openai/gpt-4.1"]
}
```

2. Re-run the installer:

```sh
python scripts/install.py --overwrite
```

3. Assign the matching model when registering:

```sh
praise --engagement "$ENGAGEMENT" register \
  --session s1 --name worker-a --role agent \
  --model openai/gpt-4.1
```

The model selected at registration becomes the observed model for that participant.

## Commands

```text
init       Initialize an engagement directory
lead       Launch configured lead
scope      Read scope without case or chat history
register   Bind a session to a local agent id
message    Send scoped JSON
inbox      Read addressed messages
peers      Read scoped agent roster
project    Recover audit projection
serve      Bound JSONL transport
```

## Tests

```sh
python -m unittest tests.test_install
```

## Notes

- Praise messages are coordination data, not authorization.
- Keep secrets and raw target data out of messages.
- Do not reuse another engagement's records or accounts.
