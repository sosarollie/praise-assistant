/**
 * Crew router: automatic agent and model selection for the pentest crew.
 *
 * Two levers, both part of the extension API:
 *   - `tool_call` on the task tool rewrites the `agent` field of each spawn item
 *     from the item's own task text, so nobody has to name a role by hand.
 *   - `before_subagent_spawn` pins the child's model, which outranks
 *     `task.agentModelOverrides`, and filters checkers by the parent's family.
 *     Checkers also verify the actual finding producer's family in the log.
 *
 * Loaded from ~/.omp/agent/extensions/, auto-discovered at startup.
 */

const CREW = {
  // Flash carries bounded discovery; Daybreak Blue handles planning and gated
  // adjudication. Precision-critical proofs remain on DeepSeek Pro.
  "pentest-scout": { models: ["opencode-go/deepseek-v4.1-flash:high"], family: "deepseek" },
  scout: { models: ["opencode-go/muse-spark-1.3-contributor:low"], family: "muse" },
  "pentest-planner": { models: ["openai-codex/gpt-daybreak-blue-latest:high"], family: "gpt" },
  "pentest-finder": { models: ["opencode-go/deepseek-v4.1-flash:high"], family: "deepseek" },
  "pentest-finder-deep": { models: ["opencode-go/deepseek-v4-pro:max"], family: "deepseek" },
  "pentest-verifier": { models: ["opencode-go/mimo-v2.6-flash:high"], family: "mimo" },
  "pentest-exploiter": { models: ["opencode-go/deepseek-v4-pro:high"], family: "deepseek" },
  "pentest-exploiter-deep": {
    models: ["opencode-go/deepseek-v4-pro:max"],
    family: "deepseek",
  },
  // Prefer a checker outside the parent's family. The checker must also compare
  // its observed model with the actual finding producer recorded in the log.
  "pentest-skeptic": {
    models: ["opencode-go/glm-5.3-flash:high", "opencode-go/mimo-v2.6-flash:high", "opencode-go/grok-4.7:high"],
    family: "glm",
    independent: true,
  },
  "pentest-skeptic-deep": {
    models: ["openai-codex/gpt-daybreak-blue-latest:max", "opencode-go/grok-4.7:high"],
    family: "gpt",
    independent: true,
  },
  "pentest-tester": {
    models: ["opencode-go/glm-5.3-flash:high", "opencode-go/mimo-v2.6-flash:high", "opencode-go/grok-4.7:high"],
    family: "glm",
    independent: true,
  },
  "security-reviewer": { models: ["openai-codex/gpt-daybreak-blue-latest:high"], family: "gpt" },
  sonic: { models: ["opencode-go/space-bunny-free:low"], family: "free" },
  task: { models: ["opencode-go/space-bunny-free:high"], family: "free" },
};

// Strict, high-signal patterns only. A misfire here is expensive twice over: the
// wrong prompt runs, and the wrong model pays for it. Checkers and the exploiter
// are therefore reachable only on unmistakable phrasing, and anything ambiguous
// falls through to the finder, which is the cheap common case.
const ROUTES = [
  [/\b(adversarial review|second opinion|independent (review|verification|check))\b/i, "pentest-skeptic-deep"],
  [/\b(issue a verdict|rule on (this|the) (candidate|finding)|false positive|is (this|it) a (real )?(vulnerability|finding)|duplicate)\b/i, "pentest-skeptic"],
  [/\b(does (the|this) (patch|fix) (close|hold|work)|re-?verify the (patch|fix)|reintroduc)\b/i, "pentest-tester"],
  [/\b(multi-step|privilege escalation|lateral movement|chained exploit|attack chain)\b/i, "pentest-exploiter-deep"],
  [/(\bpoc\b|proof of concept|exploit (it|this|the)|reproduce the (vulnerability|bug)|prove (that )?it works)\b/i, "pentest-exploiter"],
  [/\bdefensive source review\b/i, "security-reviewer"],
  [/\b(escalated cross-file dataflow|escalated (source|vulnerability) (review|analysis)|deep source analysis)\b/i, "pentest-finder-deep"],
  [/\b(test plan|what to test|attack surface|hypothesis|prioriti[sz]|engagement plan|scope the)\b/i, "pentest-planner"],
  [/\b(gate:|dedupe|filter the candidates|triage the (batch|candidates))\b/i, "pentest-verifier"],
  [/\b(subdomain|js bundle|endpoints?|burp|sitemap|security\.txt|osint)\b/i, "pentest-scout"],
];

// No match means analysis-shaped work, which is the finder's job.
const DEFAULT_AGENT = "pentest-finder";

function classify(text) {
  const body = String(text ?? "");
  for (const [pattern, agent] of ROUTES) {
    if (pattern.test(body)) return agent;
  }
  return DEFAULT_AGENT;
}

function familyOf(selector) {
  const id = String(selector ?? "").split("/").pop().split(":")[0];
  if (/^space-bunny|^ox-alpha|longcat.*free/i.test(id)) return "free";
  if (/^muse/i.test(id)) return "muse";
  if (/^longcat/i.test(id)) return "longcat";
  if (/^deepseek/i.test(id)) return "deepseek";
  if (/^glm/i.test(id)) return "glm";
  if (/^grok/i.test(id)) return "grok";
  if (/^gpt|^o[0-9]|^codex/i.test(id)) return "gpt";
  if (/^qwen/i.test(id)) return "qwen";
  if (/^kimi/i.test(id)) return "kimi";
  if (/^mimo/i.test(id)) return "mimo";
  if (/^minimax/i.test(id)) return "minimax";
  return id || "unknown";
}

let injected = false;

export default function crewRouter(pi) {
  const log = (m) => {
    try {
      pi.logger?.info(`[crew-router] ${m}`);
    } catch {}
  };
  log("loaded");
  pi.on("tool_call", async (event) => {
    try {
      if (event?.toolName !== "task") return undefined;
      const input = event.input;
      log(`tool_call task keys=${Object.keys(input ?? {}).join(",")}`);
      if (!input) return undefined;

      const isBatch = Array.isArray(input.tasks);
      if (!isBatch && typeof input.task !== "string") return undefined;
      if (isBatch && !input.tasks.every((i) => i && typeof i === "object" && typeof i.task === "string")) {
        return undefined;
      }
      const items = isBatch ? input.tasks : [input];

      let changed = false;
      const next = items.map((item) => {
        const current = item.agent;
        const alreadyCrew = Boolean(current && current !== "task" && CREW[current]);
        const wantsCrew = alreadyCrew || !current || current === "task";
        if (!wantsCrew) return item;
        const agent = alreadyCrew ? current : classify(`${item.name ?? ""} ${item.task ?? ""}`);
        if (agent === current) return item;
        changed = true;
        return { ...item, agent };
      });

      if (!changed) {
        log(`no rewrite; requested=${items.map((i) => i.agent ?? "none").join("|")}`);
        return undefined;
      }
      log(`rewrite -> ${next.map((i) => i.agent).join("|")}`);
      return isBatch ? { input: { ...input, tasks: next } } : { input: next[0] };
    } catch {
      // Never throw. A tool_call handler that throws blocks the call.
      return undefined;
    }
  });

  pi.on("before_subagent_spawn", async (event, ctx) => {
    try {
      const agent = event?.agent;
      const entry = CREW[agent];
      const parentRaw = event?.parentModel ?? event?.model ?? ctx?.model ?? "";
      const parentId =
        typeof parentRaw === "string" ? parentRaw : (parentRaw?.selector ?? parentRaw?.id ?? "");
      const parentFamily = familyOf(parentId);
      log(`before_subagent_spawn agent=${agent} parent=${parentId || "?"}`);
      if (!entry) return undefined;

      const pick =
        entry.independent && parentFamily
          ? entry.models.find((m) => familyOf(m) !== parentFamily) ?? entry.models[0]
          : entry.models[0];

      if (entry.independent && parentFamily && familyOf(pick) === parentFamily) {
        return {
          block: true,
          reason:
            `crew router: refusing to spawn ${agent} on ${parentFamily}, the same family as the spawning ` +
            `parent. No checker outside the parent's family is available.`,
        };
      }

      const note =
        entry.independent && parentFamily
          ? `crew router: ${agent} to ${pick} (parent is ${parentFamily}, checker family held separate)`
          : `crew router: ${agent} to ${pick}`;
      return { model: pick, note };
    } catch {
      return undefined;
    }
  });

  pi.on("before_agent_start", async () => {
    try {
      if (injected) return undefined;
      injected = true;
      return {
        message: {
          customType: "crew-protocol",
          content:
            "Pentest crew active. Delegate by describing the work, not the role: spawn a subagent for " +
            "sweeps and recon, one for a proof of concept, one for an adversarial verdict, one for planning. " +
            "The crew router assigns the role and model. All crew agents coordinate through the engagement " +
            "log described in skill://agents-chat; read that skill before the first post.",
          attribution: "system",
        },
      };
    } catch {
      return undefined;
    }
  });
}