# Praise

Praise coordinates specialized AI agents in **cybersecurity engagements and environments**. A lead delegates bounded tasks to fixed specialist roles, and any specialist can delegate to another when its expertise is needed.

Praise selects each role's configured provider/model, registers the agent's host-observed identity, preserves parent–child relationships, and automatically delivers startup, completion, and peer messages inside the engagement. Agents use OMP's native task tool and Praise's communication tools; users configure the models and start the lead.

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

**5. Start the agentic lead**

```sh
praise startLeadAgent \
  --directory "$HOME/pentest-workspace/my-engagement" \
  --program 'Owned source review' \
  --basis 'Authorized analysis of this local source' \
  --asset "$PWD"
```

Step 5 opens the configured lead chat, which then begins the agentic workflow and delegates to specialists on its own. See [Start an engagement](#start-an-engagement) for the full option set and resuming an existing engagement.

Keep the Python environment from steps 2–3 available: the installed launcher uses it. Add `$HOME/.local/bin` to `PATH` when using the launcher outside the activated environment.

## Configure providers and models

Authenticate the providers you intend to use with `omp login` or their supported API-key environment variables. Use `omp models` to check available model identifiers.

**Choose a provider and model for every role before starting an engagement.** The table below is our workspace recommendation; `getAgents` shows your current selections.

```sh
praise getAgents
praise setAgent --role finder --model openai/gpt-4.1
praise getAgents
```

Selectors use `provider/model[:effort]`. Provider prefixes such as `openai`, `anthropic`, `google`, `opencode-go`, and `openai-codex` refer to OMP's configured providers. Authenticate the matching provider; an OpenAI API-key provider and the Codex login provider are separate choices.

Selections are saved atomically in `~/.omp/agent/praise.json`. Dispatch and lead startup read that same file. Reinstallation preserves selections, and changes apply to newly started agents. Existing sessions keep their bound identity; restart the lead to change its running model. Unavailable selections produce an error rather than a different model being substituted.

### Fixed roles and workspace recommendations

| Role | Specialization | Provider | Recommended model |
|---|---|---|---|
| `lead` | Coordinate scope, specialist assignments, progress, and final synthesis | `opencode-go` | `step-5-preview-free:xhigh` |
| `planner` | Plan the authorized work, dependencies, and bounded task slices | `opencode-go` | `step-5-preview-free:high` |
| `scout` | Map supplied surfaces and locate relevant code or artifacts | `opencode-go` | `step-5-preview-free:high` |
| `finder` | Investigate security issues and trace source evidence | `opencode-go` | `deepseek-v4.1-flash:high` |
| `verifier` | Check evidence, reachability, and security invariants | `opencode-go` | `step-5-preview-free:high` |
| `exploiter` | Develop minimal reproductions within explicit authorization | `opencode-go` | `deepseek-v4.1-flash:high` |
| `skeptic` | Challenge conclusions, assumptions, and alternative explanations | `opencode-go` | `glm-5.3-flash:high` |
| `reviewer` | Independently review conclusions and supporting artifacts | `openai-codex` | `gpt-daybreak-blue-latest:high` |
| `tester` | Validate proposed changes against the assigned requirements | `opencode-go` | `glm-5.3-flash:high` |

These are the defaults for one reason: **the two evidence-producing roles (`finder`, `exploiter`) use one model family, and every checking role must come from a different family** so a reviewer is never grading its own class of reasoning. `deepseek-v4.1-flash` carries production because it traced the most distinct defects in comparison testing; `step-5-preview-free` carries the orchestrator, checking and planning because it is also free and supports effort control; `glm-5.3-flash:high` covers second-opinion and change validation.

The lead runs at `:xhigh` while its specialists run at `:high`. Orchestrating scope, delegation and synthesis is where haste costs the most work, and step-5's effort ceiling is `xhigh`, so the lead uses the deepest available setting instead of a faster peer.

Note that the lead, planner, scout and verifier now share the step-5 family. That is acceptable only because the lead coordinates and never renders a finding verdict — the roles that do judge evidence (`skeptic`, `reviewer`, `tester`) remain in different families from the producers.

Verify a model actually supports thinking before assigning an effort suffix — an unsupported suffix is silently ignored, so a selector like `provider/model:high` on a model with no effort levels costs you nothing and buys you nothing.

Roles are fixed; users select the models assigned to them. Assign different model families when your engagement requires independent review.

## Start an engagement

For an owned local source directory:

```sh
praise startLeadAgent \
  --directory "$HOME/pentest-workspace/my-engagement" \
  --program 'Owned source review' \
  --basis 'Authorized analysis of this local source' \
  --asset "$PWD"
```

This initializes the engagement and opens the configured lead chat. Give the lead your objective; it can assign specialists without manual registration or message commands. Specialist definitions include native delegation tools, subject to OMP's depth and concurrency limits. The default depth of two supports a lead delegating to a worker that delegates to another specialist.

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
| `praise getAgents` | Show configured roles, models, and specializations |
| `praise getAgents --engagement DIR` | Also show registered participants, parent relationships, and model provenance |
| `praise startLeadAgent --directory DIR` | Initialize or resume an engagement and start the configured lead |

Configured selectors and registered participants are distinct. A manually asserted selector is labeled `asserted`; OMP-derived identity is labeled `host`. A participant record is history, not proof that a worker is currently running.

## Upgrade and recovery

Stop running workers, install the updated package, then run:

```sh
praise install --dry-run
praise install --overwrite
```

The installer prints its backup path. It migrates previous role selections, removes obsolete owned integration files, and preserves unrelated OMP settings. Restart OMP after installation; existing sessions retain loaded extensions.

Restore an installation with:

```sh
praise install --restore-backup /absolute/path/to/printed-backup
```

Rollback refuses to erase files changed since installation. Engagement histories are preserved by the transactional schema-3 migration; keep a consistent engagement backup before upgrading. Installation rollback restores deployed files, not an engagement database.

For an isolated OMP agent directory, set `PI_CODING_AGENT_DIR` before installation and use the same value for subsequent Praise and OMP commands. `praise install --home /path/to/test-home` is available for isolated installation checks.

## Development checks

```sh
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/router.test.mjs
```

The Python package includes its integration assets, so wheel installations use the same installer as source checkouts.

## License

Praise is licensed under the [MIT License](LICENSE).
