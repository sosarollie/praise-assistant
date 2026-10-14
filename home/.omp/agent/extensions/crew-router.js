/**
 * PraiseAssistant crew router.
 *
 * Routes crew subagents by an explicit, machine-authored task-metadata header —
 * never by regex over task wording — and enforces the scoped proof-of-concept
 * request path inside an active engagement.
 *
 * Header (first line of a crew task's `task` text, exactly):
 *
 *   PraiseAssistant-Task: {"stage":"proof","candidate_id":"C...","engagement_dir":"/absolute/path","escalated":false}
 *
 * Only this header selects routing; task wording never selects a lane.
 * Non-normal tiers require a bounded reason, evidence packet and durable
 * unresolved predecessor. Deep is the first escalation; expert selects Pro HIGH,
 * and expert-max explicitly selects MAX only after an unresolved HIGH report.
 * Narrow escalation/review tasks reject oversized bodies and transcript dumps.
 *
 * Trusted dispatch: the extension uses a bound resident JSONL PraiseAssistant
 * CLI with `dispatch --stage …`, which validates
 * engagement/candidate state and returns the authoritative `agent` + `model`
 * selection (checkers are chosen against recorded producer families, not merely
 * the parent). The extension respects that selection instead of re-picking by
 * parent family. A failed dispatch blocks the spawn; it never falls back to a
 * default agent.
 *
 * Fail closed:
 *   - unknown stage / missing or non-absolute engagement_dir / malformed JSON
 *     -> block the task;
 *   - CLI dispatch error or unknown agent/model state -> block the task;
 *   - write tools require an observed model from `ctx.model` (provider/id);
 *     an absent model fails the tool instead of fabricating an identity.
 *
 * No tool-surface guard: an active engagement does not restrict `bash`, `eval`,
 * `write`, `edit`, browser, network or filesystem access. Scope tracking is
 * used only for routing, data injection and the CLI-backed PraiseAssistant
 * tools; the operator reviews what agents do.
 *
 * The resident transport is module-shared by engagement. Scope, routing,
 * identity and durable inbox cursors remain isolated in each factory closure.
 */

import { acquireJsonClient } from "./json-client.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";


const HEADER_PREFIX = "PraiseAssistant-Task:";

// Stages fixed by the contract. Used only as a fallback when crew.json is not
// available; the generated catalog is otherwise the single source of truth.
const FALLBACK_STAGES = Object.freeze([
  "plan",
  "recon",
  "discover",
  "gate",
  "proof",
  "verdict",
  "review",
  "patch",
]);
const DEFAULT_STAGE_SET = new Set(FALLBACK_STAGES);

const INJECT_BUDGET = 16_000;
const CURSOR_ENTRY = "praiseassistant-inbox";
const TIERS = new Set(["normal", "deep", "expert", "expert-max"]);
const HEADER_BUDGET = 2048;
const TASK_BUDGET = 4096;

function routedTier(header) {
  return header.tier || (header.escalated ? "deep" : "normal");
}

function routedAgent(catalog, header) {
  const tier = routedTier(header);
  return tier === "normal" ? catalog?.stages?.[header.stage]
    : tier === "deep" ? catalog?.escalations?.[header.stage]
    : catalog?.experts?.[header.stage];
}

function modelBase(selector) {
  return selector.replace(/:(minimal|low|medium|high|max)$/, "");
}

function narrowTaskError(text, header, context = "") {
  if (routedTier(header) === "normal" && header.stage !== "review") return null;
  const lines = text.trimStart().split(/\r?\n/);
  if (Buffer.byteLength(lines.shift() || "") > HEADER_BUDGET) return "task header exceeds bounded metadata budget";
  if (typeof context !== "string") return "narrow shared context must be a bounded string";
  const body = [context, lines.join("\n")].filter(Boolean).join("\n");
  if (Buffer.byteLength(body) > TASK_BUDGET) return "escalation/review task body exceeds 4096-byte budget";
  if (/(?:^|\n)\s*(?:#{1,6}\s*)?(?:full\s+)?(?:conversation|chat|transcript|message\s+history|session\s+history)\s*[:\n]|(?:^|\n)\s*(?:user|assistant|system)\s*:|<\|(?:im_start|im_end|start_header_id)\|>/i.test(body)) {
    return "escalation/review task must be a narrow question, not a transcript";
  }
  return null;
}

const VALID_MODES = new Set(["blackbox", "source", "audit", "patch", "development"]);

// ---------------------------------------------------------------------------
// Pure helpers (exported for tests).
// ---------------------------------------------------------------------------

/** Extract and validate the PraiseAssistant-Task header from task text. */
export function parseTaskHeader(text, stages = DEFAULT_STAGE_SET) {
  if (typeof text !== "string") return { kind: "none" };
  // First non-empty line only; the header must sit there and nowhere else.
  let first = "";
  for (const line of String(text).split(/\r?\n/)) {
    const t = line.trim();
    if (t) {
      first = t;
      break;
    }
  }
  if (!first.startsWith(HEADER_PREFIX)) return { kind: "none" };
  const payload = first.slice(HEADER_PREFIX.length).trim();
  let header;
  try {
    header = JSON.parse(payload);
  } catch {
    return { kind: "invalid", reason: "header JSON is not valid" };
  }
  if (!header || typeof header !== "object" || Array.isArray(header)) {
    return { kind: "invalid", reason: "header must be a JSON object" };
  }
  const reason = validateHeader(header, stages);
  if (reason) return { kind: "invalid", reason };
  return { kind: "ok", header };
}

/** Validate the fixed header fields. Returns an error string, else null. */
export function validateHeader(header, stages = DEFAULT_STAGE_SET) {
  if (typeof header.stage !== "string" || !header.stage) return "missing stage";
  if (!stages.has(header.stage)) return `unknown stage "${header.stage}"`;
  if (typeof header.engagement_dir !== "string" || !header.engagement_dir) {
    return "missing engagement_dir";
  }
  if (!path.isAbsolute(header.engagement_dir)) {
    return "engagement_dir must be an absolute path";
  }
  if (header.escalated !== undefined && typeof header.escalated !== "boolean") {
    return "escalated must be a boolean";
  }
  if (header.candidate_id !== undefined && typeof header.candidate_id !== "string") {
    return "candidate_id must be a string";
  }
  if (header.reason !== undefined && typeof header.reason !== "string") {
    return "reason must be a string";
  }
  const allowed = new Set(["stage", "engagement_dir", "escalated", "candidate_id", "reason", "tier", "packet", "attempt"]);
  if (Object.keys(header).some((key) => !allowed.has(key))) return "unknown task metadata field";
  if (header.tier !== undefined && !TIERS.has(header.tier)) return "unknown tier";
  const tier = routedTier(header);
  if (header.escalated === false && tier !== "normal") return "escalated=false conflicts with non-normal tier";
  if (header.escalated === true && tier === "normal") return "escalated=true conflicts with normal tier";
  if (header.stage === "review" && tier !== "normal") return "review requires normal tier";
  if (header.reason !== undefined && Buffer.byteLength(header.reason) > 512) return "reason exceeds 512 bytes";
  if (header.packet !== undefined && (typeof header.packet !== "string" || !header.packet ||
      path.isAbsolute(header.packet) || header.packet.includes("\\") ||
      header.packet.includes(":") || Buffer.byteLength(header.packet) > 512 ||
      header.packet.split("/").some((part) => !part || part === "." || part === ".."))) {
    return "packet must be a confined relative evidence reference";
  }
  if (header.attempt !== undefined && (!Number.isSafeInteger(header.attempt) || header.attempt < 1)) return "attempt must be a positive durable sequence";
  if (tier === "normal" && header.attempt !== undefined) return "normal routing cannot carry predecessor attempt";
  if (tier !== "normal") {
    if (!header.reason?.trim()) return "escalation requires unresolved reason";
    if (!header.packet) return "escalation requires packet";
    if (!header.attempt && !(header.stage === "verdict" && tier === "deep")) return "escalation requires predecessor attempt";
  }
  if (header.stage === "review" && !header.packet) return "review requires packet";
  return null;
}

/** Build the fixed dispatch argv for a validated header. */
export function buildDispatchArgs(header) {
  const args = ["--engagement", header.engagement_dir, "dispatch", "--stage", header.stage];
  if (header.candidate_id) args.push("--candidate", header.candidate_id);
  args.push("--tier", routedTier(header));
  if (header.escalated) args.push("--escalated");
  if (header.reason) args.push("--reason", header.reason);
  if (header.packet) args.push("--packet", header.packet);
  if (header.attempt !== undefined) args.push("--attempt", String(header.attempt));
  return args;
}

/** Observed model identifier from ctx (provider/id), never a tool-supplied value. */
export function observedModel(ctx) {
  let m = ctx && ctx.model;
  if (!m && ctx && ctx.models && typeof ctx.models.current === "function") {
    try {
      m = ctx.models.current();
    } catch {
      m = undefined;
    }
  }
  if (!m || typeof m !== "object") return null;
  const provider = typeof m.provider === "string" ? m.provider : m.spec && m.spec.provider;
  const id = typeof m.id === "string" ? m.id : m.spec && m.spec.id;
  if (typeof provider === "string" && typeof id === "string" && provider && id) {
    return `${provider}/${id}`;
  }
  if (typeof m.selector === "string" && m.selector) return m.selector;
  return null;
}

function canonicalPath(value) {
  let cursor = path.resolve(value);
  const suffix = [];
  for (;;) {
    try {
      return path.join(fs.realpathSync(cursor), ...suffix);
    } catch {
      const parent = path.dirname(cursor);
      if (parent === cursor) return path.resolve(value);
      suffix.unshift(path.basename(cursor));
      cursor = parent;
    }
  }
}

/** Load generated crew.json from the agent root (one level above extensions). */
export function loadCatalog(readFileSyncFn, moduleDir) {
  try {
    const dir = moduleDir || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const raw = readFileSyncFn(path.join(dir, "crew.json"), "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return {
      stages: parsed.stages && typeof parsed.stages === "object" ? parsed.stages : {},
      escalations:
        parsed.escalations && typeof parsed.escalations === "object" ? parsed.escalations : {},
      experts: parsed.experts && typeof parsed.experts === "object" ? parsed.experts : {},
      roles: parsed.roles && typeof parsed.roles === "object" ? parsed.roles : {},
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Factory.
// ---------------------------------------------------------------------------

export function createCrewRouter(pi, deps = {}) {
  const z = pi.zod;
  const readFileSync = deps.readFileSync || fs.readFileSync;
  const writeFileSync = deps.writeFileSync || fs.writeFileSync;
  const mkdtempSync = deps.mkdtempSync || fs.mkdtempSync;
  const rmSync = deps.rmSync || fs.rmSync;
  const tmpdir = deps.tmpdir || os.tmpdir;
  const cliCmd = deps.cliCmd || process.env.PRAISEASSISTANT_CLI || "praiseassistant";

  const catalog = deps.catalog !== undefined ? deps.catalog : loadCatalog(readFileSync, deps.moduleDir);
  const stages = new Set(
    catalog && Object.keys(catalog.stages || {}).length > 0 ? Object.keys(catalog.stages) : FALLBACK_STAGES,
  );
  const roleNames = catalog && catalog.roles ? new Set(Object.keys(catalog.roles)) : null;

  const log = (m) => {
    try {
      pi.logger && pi.logger.info(`[praiseassistant] ${m}`);
    } catch {
      /* ignore */
    }
  };

  // Per-session state. This closure is created fresh for every factory
  // invocation, so sibling/child sessions never share it.
  const session = {
    activeScope: null, // { engagementDir, mode, scopeJson }
    dispatched: new Map(), // agent -> Set of dispatched selectors; no last-item overwrite
    injected: false,
    client: null,
    identity: null,
    identityModel: null,
    identityQueue: Promise.resolve(),
    role: "lead",
    worker: "lead",
    tier: "normal",
    route: null,
    routeError: null,
    candidate: null,
    unsubscribe: null,
    cursor: 0,
    recovered: false,
    drainQueue: Promise.resolve(),
    stopped: false,
  };

  async function runCli(args) {
    if (session.stopped) return { ok: false, error: "session is shut down" };
    try {
      const bound = args[0] === "--engagement" ? args[1] : session.activeScope?.engagementDir;
      const eng = resolveEngagement({ engagement_dir: bound });
      if (eng.error) throw new Error(eng.error);
      if (!session.activeScope) {
        session.activeScope = {
          engagementDir: canonicalPath(eng.dir), mode: "blackbox", scopeJson: null,
        };
      }
      if (!session.client) session.client = acquireJsonClient(session.activeScope.engagementDir, {
        command: cliCmd, ...deps.clientOptions,
      });
      const command = args[0] === "--engagement" ? args.slice(2) : args;
      const json = deps.requestRunner
        ? await deps.requestRunner(command, session.activeScope.engagementDir)
        : await session.client.request(command);
      return { ok: true, json };
    } catch (error) {
      return { ok: false, error: error?.message || String(error) };
    }
  }

  async function establishScope(engagementDir) {
    const eng = resolveEngagement({ engagement_dir: engagementDir });
    if (eng.error) throw new Error(eng.error);
    if (session.activeScope?.scopeJson) return session.activeScope;
    if (session.scopeLoading) return session.scopeLoading;
    session.scopeLoading = (async () => {
      const state = await runCli(["--engagement", engagementDir, "scope"]);
      if (!state.ok || !state.json || !VALID_MODES.has(state.json.mode)) {
        throw new Error(state.error || "invalid scope response");
      }
      const scopeJson = state.json;
      session.activeScope = {
        engagementDir: canonicalPath(engagementDir), mode: scopeJson.mode, scopeJson,
      };
      return session.activeScope;
    })();
    try { return await session.scopeLoading; }
    finally { session.scopeLoading = null; }
  }

  async function ensureIdentity(ctx, directory) {
    const previous = session.identityQueue;
    const pending = previous.catch(() => {}).then(async () => {
      if (session.stopped) throw new Error("session is shut down");
      if (session.routeError) throw new Error(session.routeError);
      const model = observedModel(ctx);
      if (!model) throw new Error("no observed model in this session; write refused");
      const sessionId = ctx?.sessionManager?.getSessionId();
      const name = ctx?.agent?.id;
      if (!sessionId || !name) throw new Error("host session and agent identity are required");
      await establishScope(directory);
      if (session.route && modelBase(model) !== modelBase(session.route.model)) throw new Error("observed worker model differs from validated dispatch");
      if (session.identity && session.identityModel === model) return session.identity;
      if (!session.identity) {
        if (ctx.agent.kind === "main") {
          session.role = "lead";
          session.worker = "lead";
          session.tier = "normal";
        } else if (!session.route) {
          throw new Error("worker requires validated task route");
        }
      }
      const args = ["register", "--session", sessionId, "--name", name, "--role", session.role, "--model", model];
      if (session.candidate) args.push("--candidate", session.candidate);
      const result = await runCli(args);
      if (!result.ok || typeof result.json?.agent !== "string") throw new Error(result.error || "invalid registration");
      session.identity = result.json;
      session.identityModel = model;
      if (!session.recovered) {
        const entries = ctx.sessionManager.getEntries();
        const delivered = new Set();
        for (const entry of entries) {
          const message = entry.type === "custom_message" ? entry : entry.message;
          const isEnvelope = message?.customType === "praiseassistant-message";
          const isSnapshot = message?.customType === "praiseassistant-scope";
          const isRead = message?.role === "toolResult" && message.toolName === "praiseassistant_message";
          if (!isEnvelope && !isSnapshot && !isRead) continue;
          try {
            const content = typeof message.content === "string" ? message.content
              : message.content.filter((part) => part.type === "text").map((part) => part.text).join("");
            const value = JSON.parse(content);
            if (isSnapshot && value.agent !== session.identity.agent) continue;
            for (const envelope of isEnvelope ? [value] : value.messages || []) {
              if (Number.isSafeInteger(envelope.seq)) delivered.add(envelope.seq);
            }
          } catch { /* unrelated or incomplete host history is not an acknowledgement */ }
        }
        for (const entry of entries) {
          if (entry.type === "custom" && entry.customType === CURSOR_ENTRY && entry.data?.agent === session.identity.agent &&
              entry.data?.engagement === session.activeScope.engagementDir && Number.isSafeInteger(entry.data.cursor) && entry.data.cursor >= 0 &&
              Number.isSafeInteger(entry.data.after) && entry.data.after <= session.cursor &&
              Array.isArray(entry.data.seqs) && entry.data.seqs.every((seq) => delivered.has(seq))) {
            session.cursor = Math.max(session.cursor, entry.data.cursor);
          }
        }
        session.recovered = true;
      }
      session.unsubscribe?.();
      session.unsubscribe = session.client.subscribe(session.identity, () => {
        session.pendingPush = true;
        if (session.injected && !session.stopped) return schedulePush();
      });
      return session.identity;
    });
    session.identityQueue = pending;
    return pending;
  }

  function schedulePush() {
    if (session.pushDrain) return session.pushDrain;
    const pending = (async () => {
      do { await drainInbox(true); } while (session.pendingPush && !session.stopped);
    })();
    session.pushDrain = pending;
    pending.finally(() => {
      if (session.pushDrain === pending) {
        session.pushDrain = null;
        if (session.pendingPush && session.injected && !session.stopped) schedulePush().catch((error) => log(error.message));
      }
    }).catch(() => {});
    return pending;
  }

  function drainInbox(push = false, startup = false, prepare = null) {
    const pending = session.drainQueue.catch(() => {}).then(async () => {
      const collected = [];
      if (push) session.pendingPush = false;
      let more = true;
      while (more && !session.stopped) {
        const result = await runCli(["inbox", "--agent", session.identity.agent, "--after", String(session.cursor), "--limit", startup ? "1" : "32"]);
        if (!result.ok) throw new Error(result.error);
        const page = result.json;
        if (!Array.isArray(page.messages) || !Number.isSafeInteger(page.cursor) || page.cursor < session.cursor ||
            typeof page.more !== "boolean" || (page.more && page.cursor === session.cursor)) throw new Error("invalid inbox page");
        for (const message of page.messages) {
          if (push) pi.sendMessage({
            customType: "praiseassistant-message", content: JSON.stringify(message), display: false,
          }, { deliverAs: "aside" });
          else collected.push(message);
        }
        // Enqueue is not durable acknowledgement: aside may wait for a boundary.
        // Recovery validates this provisional checkpoint against message history.
        if (push) persistCursor(page.cursor, page.messages);
        else {
          const content = prepare ? prepare(collected) : undefined;
          persistCursor(page.cursor, page.messages);
          return { messages: collected, cursor: page.cursor, more: page.more, ...(content ? { content } : {}) };
        }
        more = page.more;
      }
      return { messages: collected, cursor: session.cursor, more: false };
    });
    session.drainQueue = pending;
    return pending;
  }

  function persistCursor(cursor, messages) {
    pi.appendEntry(CURSOR_ENTRY, {
      engagement: session.activeScope.engagementDir, agent: session.identity.agent, cursor,
      after: session.cursor, seqs: messages.map((message) => message.seq),
    });
    session.cursor = cursor;
  }

  function resolveEngagement(params) {
    const dir = params && params.engagement_dir ? params.engagement_dir : session.activeScope && session.activeScope.engagementDir;
    if (!dir) return { error: "no engagement directory: supply engagement_dir or run inside an active engagement" };
    if (!path.isAbsolute(dir)) return { error: "engagement_dir must be an absolute path" };
    if (session.activeScope && canonicalPath(dir) !== canonicalPath(session.activeScope.engagementDir)) {
      return { error: "cross-engagement access is refused in an active session" };
    }
    return { dir };
  }

  function textResult(text, details) {
    return { content: [{ type: "text", text }], details: details || {} };
  }

  function transitionResult(data) {
    const compact = {};
    for (const key of ["id", "candidate_id", "status", "decision", "distinct_clean_states", "result", "gates"]) {
      if (data[key] !== undefined) compact[key] = data[key];
    }
    return textResult(JSON.stringify(compact), { ok: true, data });
  }

  function writeTempJson(payload) {
    const dir = mkdtempSync(path.join(tmpdir(), "praiseassistant-"));
    const file = path.join(dir, "input.json");
    writeFileSync(file, JSON.stringify(payload), "utf8");
    return { dir, file };
  }

  function cleanupTemp(dir) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }

  async function dispatchViaCli(header) {
    const res = await runCli(buildDispatchArgs(header));
    if (!res.ok) return { ok: false, error: res.error };
    const p = res.json;
    if (!p || typeof p !== "object" || typeof p.agent !== "string" || !p.agent || typeof p.model !== "string" || !p.model) {
      return { ok: false, error: "dispatch returned an unknown agent/model state" };
    }
    const agent = routedAgent(catalog, header);
    const tier = routedTier(header);
    const definition = catalog?.roles?.[agent];
    const models = tier === "expert-max" ? [definition?.max_model] : definition?.models;
    if (p.agent !== agent || !Array.isArray(models) || !models.includes(p.model) ||
        (p.tier !== undefined && p.tier !== tier) || (p.stage !== undefined && p.stage !== header.stage)) {
      return { ok: false, error: "dispatch does not match configured stage/tier/model" };
    }
    if (tier !== "normal" || header.stage === "review") {
      if (!p.packet || p.packet.ref !== header.packet || typeof p.packet.sha256 !== "string" ||
          !/^[a-f0-9]{64}$/.test(p.packet.sha256) || !p.packet.data || typeof p.packet.data !== "object" ||
          Array.isArray(p.packet.data) || Buffer.byteLength(JSON.stringify(p.packet.data)) > 8192) {
        return { ok: false, error: "dispatch missing validated bounded packet" };
      }
    }
    return { ok: true, agent: p.agent, model: p.model, payload: p };
  }

  // -- typed tools ---------------------------------------------------------

  pi.registerTool({
    name: "praiseassistant_state",
    label: "PraiseAssistant State",
    description:
      "Read engagement or candidate state from the trusted PraiseAssistant CLI (praiseassistant show). Read-only; returns bounded JSON. Requires an active engagement or an explicit engagement_dir.",
    parameters: z.object({
      candidate_id: z.string().optional(),
      engagement_dir: z.string().optional(),
      full: z.boolean().optional(),
    }),
    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const eng = resolveEngagement(params);
      if (eng.error) return textResult(`praiseassistant_state failed: ${eng.error}`, { ok: false });
      const args = ["--engagement", eng.dir, "show"];
      if (!params.full) args.push("--compact");
      if (params.candidate_id) args.push("--candidate", params.candidate_id);
      const res = await runCli(args);
      if (!res.ok) return textResult(`praiseassistant_state failed: ${res.error}`, { ok: false });
      return textResult(JSON.stringify(res.json), { ok: true, data: res.json });
    },
  });

  pi.registerTool({
    name: "praiseassistant_message",
    label: "PraiseAssistant Message",
    description: "Send compact JSON to a registered same-engagement agent or role topic, create a bounded evidence packet, read the incremental inbox, or list registered addresses. Sender, role and model are bound to the host session.",
    parameters: z.object({
      action: z.string(),
      to: z.string().optional(),
      kind: z.string().optional(),
      data: z.object({}).passthrough().optional(),
      candidate_id: z.string().optional(),
      reply_to: z.number().optional(),
      evidence: z.array(z.string()).optional(),
      key: z.string().optional(),
      engagement_dir: z.string().optional(),
    }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const eng = resolveEngagement(params);
      if (eng.error) return textResult(`praiseassistant_message failed: ${eng.error}`, { ok: false });
      try {
        const identity = await ensureIdentity(ctx, eng.dir);
        let result;
        if (params.action === "read") {
          result = { ok: true, json: await drainInbox() };
        } else if (params.action === "peers") {
          const args = ["peers"];
          if (session.candidate) args.push("--candidate", session.candidate);
          result = await runCli(args);
        } else if (params.action === "packet") {
          if (!params.data || typeof params.data !== "object" || Array.isArray(params.data)) throw new Error("packet requires a JSON object");
          if (session.candidate && params.candidate_id && params.candidate_id !== session.candidate) throw new Error("packet candidate differs from session binding");
          const candidate = session.candidate || params.candidate_id || params.data.finding_id;
          if (candidate && params.data.finding_id && params.data.finding_id !== candidate) throw new Error("packet finding differs from session binding");
          const packet = { ...params.data, ...(candidate ? { finding_id: candidate } : {}) };
          if (Buffer.byteLength(JSON.stringify(packet)) > 8192) throw new Error("packet exceeds 8192-byte budget");
          const tmp = writeTempJson(packet);
          try {
            result = await runCli(["packet", "--input", tmp.file, "--model", observedModel(ctx), "--agent", identity.agent]);
          } finally { cleanupTemp(tmp.dir); }
        } else if (params.action === "send") {
          if (!["ask", "reply", "close"].includes(params.kind) || !params.to ||
              !params.data || typeof params.data !== "object" || Array.isArray(params.data)) throw new Error("send requires to, ask|reply|close kind, and a JSON object");
          const report = { ...params.data };
          if (params.kind === "close" && report.status !== undefined) {
            if (report.execution_failure !== undefined && report.status !== "unresolved") throw new Error("execution failure/refusal must remain unresolved, never rejected");
            report.worker = session.worker;
            report.tier = session.tier;
            if (session.candidate && report.finding_id !== undefined && report.finding_id !== session.candidate) throw new Error("report finding differs from session binding");
          }
          const data = JSON.stringify(report);
          if (Buffer.byteLength(data) > 2048 || (params.evidence?.length || 0) > 8) throw new Error("message data or artifact references exceed bounds");
          if (session.candidate && params.candidate_id && params.candidate_id !== session.candidate) throw new Error("message candidate differs from session binding");
          const args = ["message", "--from", identity.agent, "--model", observedModel(ctx), "--to", params.to, "--kind", params.kind, "--data", data];
          const candidate = session.candidate || params.candidate_id;
          if (candidate) args.push("--candidate", candidate);
          if (params.reply_to !== undefined) {
            if (!Number.isSafeInteger(params.reply_to) || params.reply_to < 1) throw new Error("reply_to must be a positive sequence");
            args.push("--reply-to", String(params.reply_to));
          }
          if (params.key) args.push("--key", params.key);
          for (const ref of params.evidence || []) args.push("--evidence", ref);
          result = await runCli(args);
        } else throw new Error("action must be send|packet|read|peers");
        if (!result.ok) throw new Error(result.error);
        return textResult(JSON.stringify(result.json), { ok: true, data: result.json });
      } catch (error) {
        return textResult(`praiseassistant_message failed: ${error.message}`, { ok: false });
      }
    },
  });

  pi.registerTool({
    name: "praiseassistant_request",
    label: "PraiseAssistant Request",
    description:
      "Perform one scoped proof-of-concept HTTP request through the PraiseAssistant CLI (praiseassistant request). The CLI enforces the engagement's allowed-asset allowlist, TLS, byte caps, budgets and throttling, and records a redacted artifact. Never make requests outside the allowed assets.",
    parameters: z.object({
      url: z.string(),
      method: z.string().optional(),
      role: z.string(),
      candidate_id: z.string().optional(),
      clean_state_id: z.string().optional(),
      headers_json: z.string().optional(),
      headers_file: z.string().optional(),
      body: z.string().optional(),
      engagement_dir: z.string().optional(),
    }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const model = observedModel(ctx);
      if (!model) return textResult("praiseassistant_request failed: no observed model in this session; write refused (fail closed).", { ok: false });
      if (session.routeError) return textResult(`praiseassistant_request failed: ${session.routeError}`, { ok: false });
      const eng = resolveEngagement(params);
      if (eng.error) return textResult(`praiseassistant_request failed: ${eng.error}`, { ok: false });
      const method = typeof params.method === "string" && params.method ? params.method.toUpperCase() : "GET";
      if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(method)) {
        return textResult(`praiseassistant_request failed: unknown method "${method}".`, { ok: false });
      }
      let headerFile;
      if (params.headers_json && params.headers_file) {
        return textResult("praiseassistant_request failed: use headers_json or headers_file, not both.", { ok: false });
      }
      if (params.headers_file) {
        headerFile = canonicalPath(path.resolve(ctx?.cwd || eng.dir, params.headers_file));
      }
      const args = ["--engagement", eng.dir, "request", "--url", params.url, "--method", method, "--role", params.role, "--model", model];
      if (params.candidate_id) args.push("--candidate", params.candidate_id);
      if (params.clean_state_id) args.push("--clean-state", params.clean_state_id);
      if (headerFile) args.push("--headers-file", headerFile);
      if (params.headers_json) args.push("--headers-json", params.headers_json);
      if (params.body !== undefined && params.body !== null) args.push("--body", params.body);
      const res = await runCli(args);
      if (!res.ok) return textResult(`praiseassistant_request failed: ${res.error}`, { ok: false });
      return textResult(JSON.stringify(res.json), { ok: true, data: res.json });
    },
  });

  const fixGate = z.object({ status: z.string(), evidence: z.array(z.string()) });

  pi.registerTool({
    name: "praiseassistant_transition",
    label: "PraiseAssistant Transition",
    description:
      "Move a candidate through its lifecycle via fixed CLI commands: candidate, gate, reproduce, verdict, review, and validate_fix. Review is the independent final report lane; observed model identity is never supplied by the caller.",
    parameters: z.object({
      action: z.string(),
      candidate_id: z.string().optional(),
      // candidate creation
      finding: z
        .object({
          title: z.string().optional(),
          summary: z.string().optional(),
          source_ref: z.string().optional(),
          sink_ref: z.string().optional(),
          boundary_invariant: z.string().optional(),
          evidence: z.array(z.string()).optional(),
          tool: z.string().optional(),
          tool_version: z.string().optional(),
        })
        .optional(),
      // gate / reproduce / verdict / validate_fix
      decision: z.string().optional(),
      reason: z.string().optional(),
      run_id: z.string().optional(),
      clean_state_id: z.string().optional(),
      evidence: z.array(z.string()).optional(),
      validate_fix: z
        .object({
          root_cause: fixGate.optional(),
          instance_coverage: fixGate.optional(),
          no_new_vulnerabilities: fixGate.optional(),
          security_best_practices: fixGate.optional(),
        })
        .optional(),
      engagement_dir: z.string().optional(),
    }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const model = observedModel(ctx);
      if (!model) return textResult("praiseassistant_transition failed: no observed model in this session; write refused (fail closed).", { ok: false });
      const eng = resolveEngagement(params);
      if (eng.error) return textResult(`praiseassistant_transition failed: ${eng.error}`, { ok: false });
      let identity;
      try { identity = await ensureIdentity(ctx, eng.dir); }
      catch (error) { return textResult(`praiseassistant_transition failed: ${error.message}`, { ok: false }); }
      const action = params.action;

      if (action === "candidate") {
        const f = params.finding || {};
        const hasEvidence = Array.isArray(f.evidence) && f.evidence.length > 0;
        if (!hasEvidence) {
          return textResult("praiseassistant_transition failed: candidate requires evidence; trace completeness is checked at the gate.", { ok: false });
        }
        const payload = { ...f, producer_model: model, producer_agent: identity.agent };
        const tmp = writeTempJson(payload);
        try {
          const res = await runCli(["--engagement", eng.dir, "candidate", "--input", tmp.file, "--agent", identity.agent]);
          if (!res.ok) return textResult(`praiseassistant_transition failed: ${res.error}`, { ok: false });
          return transitionResult(res.json);
        } finally {
          cleanupTemp(tmp.dir);
        }
      }

      if (action === "gate") {
        const decision = params.decision;
        if (!["pass", "hold", "drop"].includes(decision)) {
          return textResult(`praiseassistant_transition failed: gate decision must be pass|hold|drop, got "${decision}".`, { ok: false });
        }
        const args = ["--engagement", eng.dir, "gate", "--candidate", params.candidate_id, "--decision", decision, "--reason", params.reason || "", "--model", model];
        args.push("--agent", identity.agent);
        const res = await runCli(args);
        if (!res.ok) return textResult(`praiseassistant_transition failed: ${res.error}`, { ok: false });
        return transitionResult(res.json);
      }

      if (action === "reproduce") {
        if (!params.run_id || !params.clean_state_id || !params.evidence || params.evidence.length === 0) {
          return textResult("praiseassistant_transition failed: reproduce requires run_id, clean_state_id, and at least one evidence ref.", { ok: false });
        }
        const args = ["--engagement", eng.dir, "reproduce", "--candidate", params.candidate_id, "--run-id", params.run_id, "--clean-state", params.clean_state_id, "--evidence", params.evidence[0], "--model", model];
        args.push("--agent", identity.agent);
        const res = await runCli(args);
        if (!res.ok) return textResult(`praiseassistant_transition failed: ${res.error}`, { ok: false });
        return transitionResult(res.json);
      }

      if (action === "verdict") {
        const decision = params.decision;
        if (!["confirmed", "needs-more-proof", "rejected", "duplicate"].includes(decision)) {
          return textResult(`praiseassistant_transition failed: verdict decision must be confirmed|needs-more-proof|rejected|duplicate, got "${decision}".`, { ok: false });
        }
        const args = ["--engagement", eng.dir, "verdict", "--candidate", params.candidate_id, "--decision", decision, "--reason", params.reason || "", "--model", model];
        args.push("--agent", identity.agent);
        for (const e of params.evidence || []) args.push("--evidence", e);
        const res = await runCli(args);
        if (!res.ok) return textResult(`praiseassistant_transition failed: ${res.error}`, { ok: false });
        return transitionResult(res.json);
      }

      if (action === "review") {
        if (!["approved", "needs-more-proof", "rejected"].includes(params.decision) ||
            !params.candidate_id || !params.reason?.trim() || !params.evidence?.length) {
          return textResult("praiseassistant_transition failed: review requires candidate, approved|needs-more-proof|rejected decision, reason, and evidence.", { ok: false });
        }
        const args = ["--engagement", eng.dir, "review", "--candidate", params.candidate_id,
          "--decision", params.decision, "--reason", params.reason, "--model", model, "--agent", identity.agent];
        for (const ref of params.evidence) args.push("--evidence", ref);
        const res = await runCli(args);
        if (!res.ok) return textResult(`praiseassistant_transition failed: ${res.error}`, { ok: false });
        return transitionResult(res.json);
      }

      if (action === "validate_fix") {
        const gates = params.validate_fix || {};
        const known = ["root_cause", "instance_coverage", "no_new_vulnerabilities", "security_best_practices"];
        for (const k of known) {
          const v = gates[k];
          if (v !== undefined && (!v || !["pass", "partial", "fail", "skip"].includes(v.status) || !Array.isArray(v.evidence))) {
            return textResult(`praiseassistant_transition failed: validate_fix gate "${k}" must be pass|partial|fail|skip.`, { ok: false });
          }
        }
        const tmp = writeTempJson(gates);
        try {
          const args = ["--engagement", eng.dir, "validate-fix", "--candidate", params.candidate_id, "--model", model, "--input", tmp.file];
          args.push("--agent", identity.agent);
          const res = await runCli(args);
          if (!res.ok) return textResult(`praiseassistant_transition failed: ${res.error}`, { ok: false });
          return transitionResult(res.json);
        } finally {
          cleanupTemp(tmp.dir);
        }
      }

      return textResult(`praiseassistant_transition failed: unknown action "${action}" (expected candidate|gate|reproduce|verdict|review|validate_fix).`, { ok: false });
    },
  });

  pi.registerTool({
    name: "praiseassistant_learning",
    label: "PraiseAssistant Learning",
    description:
      "Evidence-backed workflow learning through the PraiseAssistant CLI (learn). list is read-only; observe/evaluate/promote/rollback are writes. Reviewer/producer model identities come from the observed session model, never the caller.",
    parameters: z.object({
      command: z.string(),
      lesson_id: z.string().optional(),
      candidate_id: z.string().optional(),
      summary: z.string().optional(),
      evidence: z.string().optional(),
      cases: z.array(z.object({ id: z.string().optional(), expected: z.boolean().optional(), baseline: z.boolean().optional(), learned: z.boolean().optional(), evidence: z.string().optional() })).optional(),
      reason: z.string().optional(),
      approved: z.boolean().optional(),
      full: z.boolean().optional(),
      query: z.string().optional(),
      engagement_dir: z.string().optional(),
    }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const eng = resolveEngagement(params);
      if (eng.error) return textResult(`praiseassistant_learning failed: ${eng.error}`, { ok: false });
      const command = params.command;

      if (command === "list") {
        const args = ["--engagement", eng.dir, "learn", "list"];
        if (!params.full) args.push("--compact", "--limit", "8");
        if (params.query) args.push("--query", params.query);
        if (params.approved) args.push("--approved");
        const res = await runCli(args);
        if (!res.ok) return textResult(`praiseassistant_learning failed: ${res.error}`, { ok: false });
        return textResult(JSON.stringify(res.json), { ok: true, data: res.json });
      }
      const model = observedModel(ctx);
      if (!model) return textResult("praiseassistant_learning failed: no observed model in this session; write refused.", { ok: false });

      if (command === "observe") {
        const model = observedModel(ctx);
        if (!model) return textResult("praiseassistant_learning failed: no observed model in this session; write refused (fail closed).", { ok: false });
        if (!params.candidate_id || !params.summary || !params.evidence) {
          return textResult("praiseassistant_learning failed: observe requires candidate_id, summary, and evidence.", { ok: false });
        }
        const args = ["--engagement", eng.dir, "learn", "observe", "--candidate", params.candidate_id, "--summary", params.summary, "--model", model, "--evidence", params.evidence];
        const res = await runCli(args);
        if (!res.ok) return textResult(`praiseassistant_learning failed: ${res.error}`, { ok: false });
        return textResult(JSON.stringify(res.json), { ok: true, data: res.json });
      }

      if (command === "evaluate") {
        if (!params.lesson_id || !Array.isArray(params.cases)) {
          return textResult("praiseassistant_learning failed: evaluate requires lesson_id and a cases array.", { ok: false });
        }
        const tmp = writeTempJson({ cases: params.cases });
        try {
          const args = ["--engagement", eng.dir, "learn", "evaluate", "--lesson", params.lesson_id, "--input", tmp.file, "--model", model];
          const res = await runCli(args);
          if (!res.ok) return textResult(`praiseassistant_learning failed: ${res.error}`, { ok: false });
          return textResult(JSON.stringify(res.json), { ok: true, data: res.json });
        } finally {
          cleanupTemp(tmp.dir);
        }
      }

      if (command === "promote") {
        const model = observedModel(ctx);
        if (!model) return textResult("praiseassistant_learning failed: no observed model in this session; write refused (fail closed).", { ok: false });
        if (!params.lesson_id || !params.reason) {
          return textResult("praiseassistant_learning failed: promote requires lesson_id and reason.", { ok: false });
        }
        const args = ["--engagement", eng.dir, "learn", "promote", "--lesson", params.lesson_id, "--reviewer-model", model, "--reason", params.reason];
        const res = await runCli(args);
        if (!res.ok) return textResult(`praiseassistant_learning failed: ${res.error}`, { ok: false });
        return textResult(JSON.stringify(res.json), { ok: true, data: res.json });
      }

      if (command === "rollback") {
        if (!params.lesson_id || !params.reason) {
          return textResult("praiseassistant_learning failed: rollback requires lesson_id and reason.", { ok: false });
        }
        const args = ["--engagement", eng.dir, "learn", "rollback", "--lesson", params.lesson_id, "--reason", params.reason, "--model", model];
        const res = await runCli(args);
        if (!res.ok) return textResult(`praiseassistant_learning failed: ${res.error}`, { ok: false });
        return textResult(JSON.stringify(res.json), { ok: true, data: res.json });
      }

      return textResult(`praiseassistant_learning failed: unknown command "${command}" (expected list|observe|evaluate|promote|rollback).`, { ok: false });
    },
  });

  // -- event handlers ------------------------------------------------------

  pi.on("tool_call", async (event, ctx) => {
    try {
      const name = event && event.toolName;
      if (session.activeScope && session.routeError) return { block: true, reason: `praiseassistant: invalid worker route: ${session.routeError}` };

      if (name !== "task") return undefined;
      const input = event && event.input;
      if (!input) return undefined;

      const isBatch = Array.isArray(input.tasks);
      const items = isBatch ? input.tasks : [input];
      if (isBatch && !items.every((i) => i && typeof i === "object")) return undefined;
      if (!isBatch && typeof input.task !== "string") return undefined;

      const parsed = items.map((item) => parseTaskHeader(typeof item.task === "string" ? item.task : "", stages));
      const invalid = parsed.find((item) => item.kind === "invalid");
      if (invalid) return { block: true, reason: `praiseassistant: invalid PraiseAssistant-Task metadata: ${invalid.reason}` };
      const headers = parsed.filter((item) => item.kind === "ok");
      if (!headers.length) return undefined;
      if (!observedModel(ctx)) return { block: true, reason: "praiseassistant: no observed model for routed spawn; fail closed." };
      for (let index = 0; index < parsed.length; index++) {
        if (parsed[index].kind !== "ok") continue;
        const error = narrowTaskError(items[index].task, parsed[index].header, input.context);
        if (error) return { block: true, reason: `praiseassistant: ${error}` };
      }
      const directory = headers[0].header.engagement_dir;
      if (headers.some((item) => canonicalPath(item.header.engagement_dir) !== canonicalPath(directory))) {
        return { block: true, reason: "praiseassistant: cross-engagement task batch refused" };
      }
      const eng = resolveEngagement({ engagement_dir: directory });
      if (eng.error) return { block: true, reason: `praiseassistant: ${eng.error}` };
      await establishScope(directory);
      const dispatched = await Promise.all(parsed.map((item) => item.kind === "ok" ? dispatchViaCli(item.header) : null));
      const failure = dispatched.find((item) => item && !item.ok);
      if (failure) return { block: true, reason: `praiseassistant: dispatch failed: ${failure.error}` };
      for (let index = 0; index < dispatched.length; index++) {
        const disp = dispatched[index];
        if (!disp) continue;
        const requested = items[index].model ?? (isBatch ? input.model : undefined);
        if (requested !== undefined && requested !== disp.model &&
            !(Array.isArray(requested) && requested.length === 1 && requested[0] === disp.model)) {
          return { block: true, reason: "praiseassistant: caller model selector differs from validated dispatch; no substitution allowed" };
        }
      }
      const next = items.map((item, index) => {
        const disp = dispatched[index];
        if (!disp) return item;
        const selectors = session.dispatched.get(disp.agent) || new Set();
        selectors.add(disp.model);
        session.dispatched.set(disp.agent, selectors);
        return { ...item, agent: disp.agent, model: disp.model };
      });
      return isBatch ? { input: { ...input, tasks: next } } : { input: next[0] };
    } catch (error) {
      if (session.activeScope) return { block: true, reason: `praiseassistant: routing failed closed: ${String(error)}` };
      return undefined;
    }
  });

  pi.on("before_subagent_spawn", async (event) => {
    try {
      const scope = session.activeScope;
      if (!scope) return undefined;
      const agent = event && event.agent;
      if (!agent) return undefined;

      const isCrew = (roleNames && roleNames.has(agent)) || session.dispatched.has(agent);
      if (!isCrew) {
        return {
          block: true,
          reason: `praiseassistant: refusing to spawn non-crew agent "${agent}" inside an active engagement.`,
        };
      }
      const selectors = session.dispatched.get(agent);
      if (!selectors || !selectors.size) {
        return {
          block: true,
          reason: `praiseassistant: crew agent "${agent}" spawned without a PraiseAssistant-Task dispatch record; fail closed.`,
        };
      }
      const patterns = event.patterns || [];
      const exact = [...selectors].filter((selector) => patterns.includes(selector));
      const bases = [...selectors].filter((selector) => patterns.includes(modelBase(selector)));
      const model = exact.length === 1 ? exact[0]
        : exact.length ? null
        : bases.length === 1 ? bases[0]
        : patterns.length === 0 && selectors.size === 1 ? [...selectors][0] : null;
      if (!model) return { block: true, reason: "praiseassistant: cannot bind this spawn to one dispatched model; refusing an ambiguous route." };
      return { model, note: `praiseassistant: ${agent} -> ${model}` };
    } catch (error) {
      if (session.activeScope) return { block: true, reason: `praiseassistant: spawn failed closed: ${String(error)}` };
      return undefined;
    }
  });

  pi.on("before_agent_start", async (event, ctx) => {
    try {
      const prompt = event && event.prompt ? event.prompt : "";
      const parsed = parseTaskHeader(prompt, stages);
      let header = null;
      if (parsed.kind === "ok") header = parsed.header;

      if (header) {
        const eng = resolveEngagement({ engagement_dir: header.engagement_dir });
        if (eng.error) throw new Error(eng.error);
        session.activeScope = await establishScope(header.engagement_dir);
        const error = narrowTaskError(prompt, header);
        if (error) throw new Error(error);
        if (ctx?.agent?.kind !== "main" && !session.route) {
          const route = await dispatchViaCli(header);
          if (!route.ok) throw new Error(route.error);
          if (ctx?.agent?.name !== route.agent || !observedModel(ctx) ||
              modelBase(observedModel(ctx)) !== modelBase(route.model)) throw new Error("worker identity/model differs from validated task route");
          session.route = route;
          session.role = header.stage;
          session.worker = route.agent;
          session.tier = routedTier(header);
          session.candidate = header.candidate_id || null;
        }
      } else if (!session.activeScope) {
        // Secondary path: the session was launched with cwd = an initialized
        // engagement directory (scope.json present).
        try {
          const cwd = ctx && ctx.cwd;
          if (cwd && readFileSync(path.join(cwd, "scope.json"), "utf8")) {
            session.activeScope = await establishScope(cwd);
          }
        } catch {
          /* not an engagement dir */
        }
      }

      const scope = session.activeScope;
      if (!scope) return undefined;
      if (parsed.kind === "invalid") throw new Error(`invalid PraiseAssistant-Task metadata: ${parsed.reason}`);
      if (ctx?.agent?.kind !== "main" && !session.route &&
          (catalog?.experts && Object.values(catalog.experts).includes(ctx?.agent?.name) ||
           Object.values(catalog?.escalations || {}).includes(ctx?.agent?.name) ||
           ctx?.agent?.name === catalog?.stages?.review)) throw new Error("narrow worker requires validated task metadata");
      await ensureIdentity(ctx, scope.engagementDir);
      const narrow = session.route && (session.tier !== "normal" || session.role === "review");
      if (narrow) {
        if (session.injected) return undefined;
        const caseContext = { id: session.candidate, stage: session.role, tier: session.tier };
        const projection = session.route.payload.case;
        if (projection) {
          if (projection.id !== session.candidate) throw new Error("dispatch case differs from session binding");
          for (const key of ["status", "review_status"]) {
            if (projection[key] !== undefined) {
              if (typeof projection[key] !== "string" || Buffer.byteLength(projection[key]) > 64) throw new Error("invalid compact case status");
              caseContext[key] = projection[key];
            }
          }
          if (projection.report_ready !== undefined) {
            if (typeof projection.report_ready !== "boolean") throw new Error("invalid compact report readiness");
            caseContext.report_ready = projection.report_ready;
          }
          if (projection.producer_models !== undefined) {
            if (!Array.isArray(projection.producer_models) || projection.producer_models.length > 16 ||
                projection.producer_models.some((model) => typeof model !== "string" || Buffer.byteLength(model) > 512)) throw new Error("invalid compact producer models");
            caseContext.producer_models = projection.producer_models;
          }
        }
        const content = JSON.stringify({
          agent: session.identity.agent, role: session.role, worker: session.worker, tier: session.tier,
          case: caseContext,
          packet: session.route.payload.packet,
        });
        if (Buffer.byteLength(content) > INJECT_BUDGET) throw new Error("packet context exceeds bounded JSON budget");
        session.injected = true;
        // Historical inbox remains available through explicit incremental read;
        // do not append unrelated transcripts to a narrow expert/review packet.
        return { message: { customType: "praiseassistant-scope", content, display: false } };
      }
      const lessons = deps.requestRunner
        ? (await runCli(["learn", "list", "--approved", "--compact", "--limit", "4"])).json
        : await session.client.approvedLessons();
      if (session.injected) {
        await drainInbox(true);
        const lessonSnapshot = JSON.stringify(lessons);
        if (session.lessonSnapshot === lessonSnapshot) return undefined;
        session.lessonSnapshot = lessonSnapshot;
        return { message: { customType: "praiseassistant-learning", content: lessonSnapshot, display: false } };
      }
      const showArgs = ["show", "--compact"];
      if (session.candidate) showArgs.push("--candidate", session.candidate);
      const state = await runCli(showArgs);
      if (!state.ok) throw new Error(state.error);
      const inbox = await drainInbox(false, true, (messages) => {
        const context = {
          agent: session.identity.agent, role: session.role,
          ...(session.candidate ? { case: session.candidate } : {}),
          state: state.json, messages, lessons: lessons.lessons,
        };
        const content = JSON.stringify(context);
        if (Buffer.byteLength(content) > INJECT_BUDGET) throw new Error("startup context exceeds bounded JSON budget");
        return content;
      });
      session.injected = true;
      session.lessonSnapshot = JSON.stringify(lessons);
      if (inbox.more || session.pendingPush) schedulePush().catch((error) => log(error.message));
      return { message: { customType: "praiseassistant-scope", content: inbox.content, display: false } };
    } catch (error) {
      session.routeError = error.message;
      if (session.activeScope) {
        return { message: { customType: "praiseassistant-error", content: JSON.stringify({ error: error.message }), display: false } };
      }
      return undefined;
    }
  });

  pi.on("session_shutdown", () => {
    session.stopped = true;
    session.unsubscribe?.();
    session.client?.release();
    session.client = null;
  });

  log("loaded");
}

export default function crewRouter(pi) {
  return createCrewRouter(pi, {});
}
