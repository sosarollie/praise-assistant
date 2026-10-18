# Praise

Praise coordinates specialized AI agents in **cybersecurity engagements and environments**. The main session is the lead: it runs on the model the terminal selected, delegates bounded tasks to fixed specialist roles, and any specialist can delegate to another when its expertise is needed.

Praise selects each specialist role's configured provider/model, registers the agent's host-observed identity, preserves parent–child relationships, and automatically delivers startup, completion, and peer messages inside the engagement. Agents use OMP's native task tool and Praise's communication tools; users configure specialist models and start the main session.

## Install

Requires Linux, Python 3.11+, and [OMP](https://github.com/can1357/oh-my-pi) with authenticated providers. The integration is exercised with OMP 18.10.2.

**1. Clone the repository**

```sh
git clone https://github.com/sosarollie/praise-assistant.git
cd praise-assistant
```

**2. Create and activate a virtual environment**

```sh
python3 -m venv .venv
. .venv/bin/activate
```

**3. Install the package**

```sh
python -m pip install .
```

**4. Install the Praise integration**

```sh
praise install
```

**5. Start the main session**

```sh
praise startLeadAgent \
  --directory "$HOME/pentest-workspace/my-engagement" \
  --program 'Owned source review' \
  --basis 'Authorized analysis of this local source' \
  --asset "$PWD"
```

Step 5 opens the main session, which begins the agentic workflow and delegates to specialists on its own using the terminal-selected model. See [Start an engagement](#start-an-engagement) for the full option set and resuming an existing engagement.

Keep the Python environment from steps 2–3 available: the installed launcher uses it. Add `$HOME/.local/bin` to `PATH` when using the launcher outside the activated environment.

## Configure providers and models

Authenticate the providers you intend to use with `omp login` or their supported API-key environment variables. Use `omp models` to check available model identifiers.

**Choose a provider and model for every role before starting an engagement.** `getAgents` prints the current selections as a table of role, provider, model, effort and specialization, marking selections that differ from the packaged defaults:

```sh
praise getAgents
praise setAgent --role analyst --model opencode-go/deepseek-v4.1-flash:high
praise getAgents --json
```

Selectors use `provider/model[:effort]`. Provider prefixes such as `openai`, `anthropic`, `google`, `opencode-go`, and `openai-codex` refer to OMP's configured providers. Authenticate the matching provider; an OpenAI API-key provider and the Codex login provider are separate choices.

Selections are saved atomically in `~/.omp/agent/praise.json`. Specialist dispatch reads that same file. The main session has no selector: it runs on the terminal-selected model, is registered as the `main` identity label, and is never matched against configuration. Reinstallation preserves schema-4 selections, and changes apply to newly started workers. Existing workers keep their bound identity; start a new worker to use a changed selector. Unavailable selections produce an error rather than a different model being substituted.

### Fixed roles and workspace recommendations

| Role | Specialization | Provider | Recommended model |
|---|---|---|---|
| `investigator` | Hard reasoning, adversarial challenge and controlled reproduction | `openai-codex` | `gpt-5.6-sol:xhigh` |
| `scout` | Broad read-heavy surface and source exploration without verdicts | `opencode-go` | `deepseek-v4.1-flash:high` |
| `analyst` | Narrow comparison, classification and output reduction without impact claims | `opencode-go` | `deepseek-v4.1-flash:high` |

The main session should normally run GPT-5.6 Sol and owns authorization, the hypothesis registry and final acceptance. Delegate at most four genuinely different paths in one native task batch. Every investigative assignment states its hypothesis, existing evidence, expected signal and disproof condition.

Scout and analyst optimize breadth and throughput. Their candidates are not confirmed findings: a fresh investigator must try to disprove them, and human review remains final. Because scout and analyst share the DeepSeek family, this setup does not claim model-family-independent review.

`xhigh` is the default for the difficult role; use `max` only after a paired comparison shows a quality benefit. Verify a model actually supports the selected effort suffix—an unsupported suffix may be ignored.

Roles are fixed; users select the models assigned to them. The router has no lexical auto-routing or fallback chain.

## Start an engagement

For an owned local source directory:

```sh
praise startLeadAgent \
  --directory "$HOME/pentest-workspace/my-engagement" \
  --program 'Owned source review' \
  --basis 'Authorized analysis of this local source' \
  --asset "$PWD"
```

This initializes the engagement and opens the main session on the terminal-selected model. Give it your objective; it can assign specialists without manual registration or message commands. Specialist definitions include native delegation tools, subject to OMP's depth and concurrency limits. The default depth of two supports a lead delegating to a worker that delegates to another specialist.

Resume an existing engagement with:

```sh
praise startLeadAgent --directory "$HOME/pentest-workspace/my-engagement"
```

Native OMP options or a non-interactive prompt can follow `--`:

```sh
praise startLeadAgent --directory "$HOME/pentest-workspace/my-engagement" \
  -- -p 'Inspect the supplied source and delegate a bounded evidence check.'
```

Each engagement keeps its scope, `state.sqlite3`, append-only `agentschat.md`, and `evidence/` together. Supply exact authorized assets and account boundaries; scope records and messages are coordination data, not testing permission.

## Commands

| Command | Purpose |
|---|---|
| `praise install` | Install the packaged agent definitions, extension, and coordination skill |
| `praise setAgent --role ROLE --model SELECTOR` | Persist the model selection for one fixed role |
| `praise getAgents` | Print the configured roles as a table of role, provider, model, effort, and specialization |
| `praise getAgents --engagement DIR` | Also print the registered participants with name, role, model, provenance, and parent |
| `praise getAgents --json` | Emit the same data as the schema-4 JSON object instead of tables |
| `praise startLeadAgent --directory DIR` | Initialize or resume an engagement and start the main session on the terminal-selected model |

Configured selectors and registered participants are distinct. A manually asserted selector is labeled `asserted`; OMP-derived identity is labeled `host`. A participant record is history, not proof that a worker is currently running. Both listings are aligned tables on standard output; `--json` keeps the machine-readable object for scripts and tooling.

## Upgrade and recovery

Stop running workers, install the updated package, then run:

```sh
praise install --dry-run
praise install --overwrite
```

The installer prints its backup path. Schema-4 reinstalls preserve the selected models byte-for-byte. A schema-3 catalog is replaced with the fixed three-role defaults rather than guessing how eight conflicting role selections should collapse; the original catalog and removed role files remain in the printed rollback backup. Unrelated OMP settings are preserved.

Runtime schema 4 preserves historical participants, direct messages and reply links. Messages addressed to removed role topics are archived, and removed-role workers cannot resume. Stop running workers before upgrading, restart OMP after installation, and start new workers under the three current roles.

Restore installed files and the previous role catalog with:

```sh
praise install --restore-backup /absolute/path/to/printed-backup
```

Rollback refuses to erase files changed since installation. Engagement database migration is transactional but is not reverted by installation rollback; keep a consistent engagement backup before upgrading.

For an isolated OMP agent directory, set `PI_CODING_AGENT_DIR` before installation and use the same value for subsequent Praise and OMP commands. `praise install --home /path/to/test-home` is available for isolated installation checks.

## Development checks

```sh
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/router.test.mjs
```

The Python package includes its integration assets, so wheel installations use the same installer as source checkouts.

## License

Praise is licensed under the [MIT License](LICENSE).
