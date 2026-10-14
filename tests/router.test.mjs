import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFile, spawn as spawnProcess } from "node:child_process";
import { promisify } from "node:util";
import http from "node:http";

import {
  parseTaskHeader,
  validateHeader,
  buildDispatchArgs,
  loadCatalog,
  createCrewRouter,
} from "../home/.omp/agent/extensions/crew-router.js";
import { acquireJsonClient } from "../home/.omp/agent/extensions/json-client.mjs";

const STAGES = new Set(["plan", "recon", "discover", "gate", "proof", "verdict", "review", "patch"]);

function header(overrides = {}) {
  return `PraiseAssistant-Task: ${JSON.stringify({
    stage: "proof",
    candidate_id: "C-1",
    engagement_dir: "/tmp/eng",
    escalated: false,
    ...overrides,
  })}`;
}

function makeZod() {
  const optional = { optional: () => optional, passthrough: () => optional };
  return {
    string: () => optional,
    number: () => optional,
    boolean: () => optional,
    array: () => optional,
    object: () => optional,
  };
}

function makePi() {
  const tools = [];
  const handlers = {};
  const entries = [];
  const messages = [];
  const listeners = new Set();
  return {
    zod: makeZod(),
    tools,
    handlers,
    entries, messages, listeners,
    appendEntry(customType, data) { entries.push({ type: "custom", customType, data }); },
    sendMessage(message, options) {
      if (this.deliveryError) throw new Error("delivery unavailable");
      messages.push({ message, options });
      if (!this.deliveryDeferred) entries.push({ type: "custom_message", ...message });
      for (const listener of listeners) listener(message);
    },
    logger: { info() {} },
    registerTool(def) {
      tools.push(def);
    },
    on(event, handler) {
      (handlers[event] ||= []).push(handler);
    },
  };
}

// Explicit injected request runner for focused routing fixtures.
function makeExec(handler) {
  const fn = async (command, directory) => {
    const args = ["--engagement", directory, ...command];
    if (command[0] === "scope") return { mode: "source" };
    const result = handler(args, fn.calls.length);
    fn.calls.push(args);
    if (result?.reject) throw new Error(result.reject.stderr || result.reject.message || "cli failed");
    return JSON.parse(result?.stdout || "{}");
  };
  fn.calls = [];
  return fn;
}

const emptyFs = {
  readFileSync: () => {
    throw new Error("no file");
  },
  writeFileSync: () => {},
  mkdtempSync: (p) => p,
  rmSync: () => {},
};

// Real CLI fixtures exercise the frontend/backend contract without model calls.
async function localFixture(t, url) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "praiseassistant-router-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, "eng");
  const source = path.join(root, "source");
  fs.mkdirSync(source);
  const repository = fileURLToPath(new URL("../", import.meta.url));
  const spawn = promisify(execFile);
  const exec = (_file, args, options = {}) => spawn("python3", ["-m", "praiseassistant", ...args], { ...options, cwd: repository });
  const init = ["init", "--directory", directory, "--program", "local fixture", "--basis", "isolated regression controls", "--asset", source];
  if (url) init.push("--mode", "audit", "--asset", url, "--max-requests", "3", "--interval", "0");
  await exec("", init);
  fs.writeFileSync(path.join(directory, "evidence", "trace.json"), '{"fixture":"controlled evidence"}');
  const pi = makePi();
  const catalog = JSON.parse(fs.readFileSync(new URL("../praiseassistant/roles.json", import.meta.url), "utf8"));
  const processes = [];
  const clientOptions = { command: "python3", prefix: ["-m", "praiseassistant"], cwd: repository,
    spawn(command, args, options) { const child = spawnProcess(command, args, options); processes.push(child); return child; },
  };
  createCrewRouter(pi, { clientOptions, catalog });
  t.after(() => pi.handlers.session_shutdown[0]());
  const ctx = contextFor(pi, directory);
  const startup = await pi.handlers.before_agent_start[0]({ prompt: "local regression" }, ctx);
  const tool = (name) => pi.tools.find((entry) => entry.name === name);
  const invoke = (name, params, context = ctx) => tool(name).execute("fixture", params, undefined, undefined, context);
  const create = async (context = ctx) => {
    const result = await invoke("praiseassistant_transition", {
      action: "candidate",
      finding: { evidence: ["trace.json"], boundary_invariant: "synthetic tenant isolation" },
    }, context);
    assert.equal(result.details.ok, true);
    return result.details.data;
  };
  return { root, directory, pi, ctx, invoke, create, repository, catalog, startup, processes, clientOptions };
}
const tmpdir = () => "/tmp";

let sessionNumber = 0;
function contextFor(pi, directory, identity = {}) {
  const number = ++sessionNumber;
  return {
    cwd: directory, model: { provider: "opencode-go", id: "glm-5.3-flash" },
    agent: { kind: "main", id: `Fixture${number}`, name: "main", ...identity },
    sessionManager: { getSessionId: () => `session-${number}`, getEntries: () => pi.entries },
  };
}

function toolInvoker(pi, ctx) {
  return (name, params) => pi.tools.find((entry) => entry.name === name).execute("fixture", params, undefined, undefined, ctx);
}

function nextMessages(pi, count) {
  return new Promise((resolve) => {
    const received = [];
    const listener = (message) => {
      if (message.customType !== "praiseassistant-message") return;
      received.push(JSON.parse(message.content));
      if (received.length === count) { pi.listeners.delete(listener); resolve(received); }
    };
    pi.listeners.add(listener);
  });
}

// ---------------------------------------------------------------------------
// Header parsing and fixed-field validation.
// ---------------------------------------------------------------------------

test("parses an exact first-line header", () => {
  const r = parseTaskHeader(header(), STAGES);
  assert.equal(r.kind, "ok");
  assert.equal(r.header.stage, "proof");
  assert.equal(r.header.candidate_id, "C-1");
  assert.equal(r.header.engagement_dir, "/tmp/eng");
});

test("negated body wording does not change the explicit stage", () => {
  const text = `${header({ stage: "verdict" })}\nDo NOT issue a verdict. This is routine, no adversarial review, not a deep analysis.`;
  const r = parseTaskHeader(text, STAGES);
  assert.equal(r.kind, "ok");
  assert.equal(r.header.stage, "verdict");
});

test("a header on a later line is not recognized (exact first line only)", () => {
  const r = parseTaskHeader(`some prose\n${header()}`, STAGES);
  assert.equal(r.kind, "none");
});

test("unknown stage fails closed", () => {
  const r = parseTaskHeader(header({ stage: "explode" }), STAGES);
  assert.equal(r.kind, "invalid");
  assert.match(r.reason, /unknown stage/);
});

test("missing engagement_dir fails closed", () => {
  const r = parseTaskHeader(
    `PraiseAssistant-Task: ${JSON.stringify({ stage: "proof" })}`,
    STAGES,
  );
  assert.equal(r.kind, "invalid");
  assert.match(r.reason, /engagement_dir/);
});

test("non-absolute engagement_dir fails closed", () => {
  const r = parseTaskHeader(header({ engagement_dir: "relative/path" }), STAGES);
  assert.equal(r.kind, "invalid");
  assert.match(r.reason, /absolute/);
});

test("malformed JSON fails closed", () => {
  const r = parseTaskHeader(`PraiseAssistant-Task: {not json`, STAGES);
  assert.equal(r.kind, "invalid");
  assert.match(r.reason, /not valid/);
});


// ---------------------------------------------------------------------------
// Routing and dispatch through a mocked pi host.
// ---------------------------------------------------------------------------

const CATALOG = {
  stages: {
    plan: "pentest-planner",
    recon: "pentest-scout",
    discover: "pentest-finder",
    gate: "pentest-verifier",
    proof: "pentest-exploiter",
    verdict: "pentest-skeptic",
    patch: "pentest-tester",
    review: "security-reviewer",
  },
  escalations: { discover: "pentest-finder-deep", proof: "pentest-exploiter-deep", verdict: "pentest-skeptic-deep" },
  experts: { discover: "pentest-finder-expert", proof: "pentest-exploiter-expert" },
  roles: {
    "pentest-exploiter": { models: ["opencode-go/deepseek-v4.1-flash:high"] },
    "pentest-exploiter-deep": { models: ["opencode-go/deepseek-v4.1-flash:high"] },
    "pentest-exploiter-expert": { models: ["opencode-go/deepseek-v4-pro:high"], max_model: "opencode-go/deepseek-v4-pro:max" },
    "security-reviewer": { models: ["openai-codex/gpt-daybreak-blue-latest:high"], independent: true },
    "pentest-skeptic": { models: ["opencode-go/deepseek-v4.1-flash:high"], independent: true },
  },
};

function routedPi(exec) {
  const pi = makePi();
  const deps = { requestRunner: exec, ...emptyFs, tmpdir, catalog: CATALOG, cliCmd: "praiseassistant" };
  createCrewRouter(pi, deps);
  const toolCall = pi.handlers.tool_call[0];
  pi.handlers.tool_call[0] = (event, ctx = contextFor(pi, "/tmp/eng")) => toolCall(event, ctx);
  return pi;
}

function dispatchExec(map) {
  return makeExec((args) => {
    const stage = args[args.indexOf("--stage") + 1];
    const out = map[stage];
    if (!out) return { reject: { stderr: `{"error":"no agent for ${stage}"}`, code: 2 } };
    return { stdout: JSON.stringify(out) };
  });
}

test("routes a batch of plural proof/verdict tasks from headers, not wording", async () => {
  const exec = dispatchExec({
    proof: { stage: "proof", agent: "pentest-exploiter", model: "opencode-go/deepseek-v4.1-flash:high" },
    verdict: { stage: "verdict", agent: "pentest-skeptic", model: "opencode-go/deepseek-v4.1-flash:high" },
  });
  const pi = routedPi(exec);
  const handler = pi.handlers.tool_call[0];

  const input = {
    tasks: [
      { name: "a", task: `${header({ stage: "proof" })}\nDo NOT write any proof of concept.` },
      { name: "b", task: `${header({ stage: "verdict" })}\nThis is routine, do not escalate.` },
    ],
  };
  const result = await handler({ toolName: "task", input });

  assert.ok(result && result.input && result.input.tasks, "expected a rewritten batch");
  assert.deepEqual(
    result.input.tasks.map((t) => t.agent),
    ["pentest-exploiter", "pentest-skeptic"],
  );
  assert.deepEqual(
    result.input.tasks.map((t) => t.model),
    ["opencode-go/deepseek-v4.1-flash:high", "opencode-go/deepseek-v4.1-flash:high"],
  );
});

test("a failed dispatch returns block, never a fallback agent", async () => {
  const exec = makeExec(() => ({ reject: { stderr: '{"error":"candidate not gated"}', code: 2 } }));
  const pi = routedPi(exec);
  const handler = pi.handlers.tool_call[0];

  const result = await handler({ toolName: "task", input: { task: header({ stage: "proof" }) } });
  assert.ok(result && result.block, "expected a block");
  assert.equal(result.input, undefined);
});

test("non-crew keyword wording without a header is left untouched", async () => {
  const pi = routedPi(makeExec(() => ({ stdout: "{}" })));
  const handler = pi.handlers.tool_call[0];

  const result = await handler({
    toolName: "task",
    input: { task: "issue a verdict on this candidate, false positive or duplicate" },
  });
  assert.equal(result, undefined, "no header means no routing");
});

test("a header-less task inside an active scope is left untouched", async () => {
  const exec = dispatchExec({
    proof: { stage: "proof", agent: "pentest-exploiter", model: "opencode-go/deepseek-v4.1-flash:high" },
  });
  const pi = routedPi(exec);
  const handler = pi.handlers.tool_call[0];

  await handler({ toolName: "task", input: { task: header({ stage: "proof" }) } });
  const result = await handler({ toolName: "task", input: { task: "do some generic thing" } });
  assert.equal(result, undefined, "no header means no routing, not a block");
});

test("escalation requires the flag and an unresolved reason, never suggestive wording", async (t) => {
  const fixture = await localFixture(t);
  const candidate = await fixture.create({
    ...fixture.ctx, model: { provider: "opencode-go", id: "deepseek-v4-pro" },
  });
  await fixture.invoke("praiseassistant_transition", {
    action: "gate", candidate_id: candidate.id, decision: "pass", reason: "source fixture trace",
  });
  const handler = fixture.pi.handlers.tool_call[0];
  const route = (metadata, body = "") => handler({
    toolName: "task",
    input: { task: header({ stage: "proof", candidate_id: candidate.id, engagement_dir: fixture.directory, ...metadata }) + body },
  }, fixture.ctx);
  const ordinary = await route({ escalated: false }, "\nDeep escalation is not needed.");
  assert.equal(ordinary.input.agent, "pentest-exploiter");
  const workerPi = makePi();
  const worker = await anotherFactory(t, fixture, {
    pi: workerPi,
    ctx: { ...contextFor(workerPi, fixture.directory, { kind: "sub", name: "pentest-exploiter" }),
      model: { provider: "opencode-go", id: "deepseek-v4.1-flash" } },
    prompt: header({ stage: "proof", candidate_id: candidate.id, engagement_dir: fixture.directory }),
  });
  const close = await worker.invoke("praiseassistant_message", {
    action: "send", to: "@lead", kind: "close", candidate_id: candidate.id,
    data: { status: "unresolved", finding_id: candidate.id, hypothesis: "synthetic control",
      evidence: ["trace.json"], contradictions: [], unresolved_questions: ["cross-request chain gap"],
      recommended_next_agent: null, worker: "spoofed", tier: "expert-max" },
    evidence: ["trace.json"],
  });
  assert.equal(close.details.ok, true, close.content[0].text);
  const packet = await fixture.invoke("praiseassistant_message", { action: "packet", data: minimalPacket(candidate.id) });
  assert.equal(packet.details.ok, true, packet.content[0].text);
  const deep = await route({ escalated: true, reason: "cross-request chain remains unresolved",
    packet: packet.details.data.ref, attempt: close.details.data.seq });
  assert.equal(deep.input.agent, "pentest-exploiter-deep");
  assert.equal(deep.input.model, "opencode-go/deepseek-v4.1-flash:high");
  const missingReason = await route({ escalated: true });
  assert.equal(missingReason.block, true);
});

// ---------------------------------------------------------------------------
// Per-session state isolation and the spawn re-check.
// ---------------------------------------------------------------------------

test("active scope is isolated per factory invocation (session)", async () => {
  const execA = dispatchExec({ proof: { stage: "proof", agent: "pentest-exploiter", model: "opencode-go/deepseek-v4.1-flash:high" } });
  const piA = routedPi(execA);
  const piB = routedPi(makeExec(() => ({ stdout: "{}" })));

  await piA.handlers.tool_call[0]({ toolName: "task", input: { task: header({ stage: "proof" }) } });

  // Scope is per factory closure: neither session restricts the tool surface.
  const freeA = await piA.handlers.tool_call[0]({ toolName: "bash", input: { command: "id" } });
  assert.equal(freeA, undefined, "session A must not guard bash");
  const freeB = await piB.handlers.tool_call[0]({ toolName: "bash", input: { command: "id" } });
  assert.equal(freeB, undefined, "session B must remain unguarded");
});

test("before_subagent_spawn respects the dispatch model and blocks undispatch crew spawns", async () => {
  const exec = dispatchExec({ proof: { stage: "proof", agent: "pentest-exploiter", model: "opencode-go/deepseek-v4.1-flash:high" } });
  const pi = routedPi(exec);
  const toolCall = pi.handlers.tool_call[0];
  const spawn = pi.handlers.before_subagent_spawn[0];

  await toolCall({ toolName: "task", input: { task: header({ stage: "proof" }) } });

  const allowed = await spawn({ agent: "pentest-exploiter", invocationKind: "task", patterns: [] });
  assert.equal(allowed.model, "opencode-go/deepseek-v4.1-flash:high");

  const blocked = await spawn({ agent: "pentest-skeptic", invocationKind: "task", patterns: [] });
  assert.ok(blocked && blocked.block);
  assert.match(blocked.reason, /without a PraiseAssistant-Task dispatch record/);
});

// ---------------------------------------------------------------------------
// Tool write guards (observed model required).
// ---------------------------------------------------------------------------

test("JSON messages refuse a write without an observed model", async () => {
  const exec = makeExec(() => ({ stdout: "{}" }));
  const pi = routedPi(exec);
  const tool = pi.tools.find((t) => t.name === "praiseassistant_message");
  const result = await tool.execute("id", { action: "send", to: "@lead", kind: "ask", data: { x: 1 }, engagement_dir: "/tmp/eng" }, undefined, undefined, {});
  assert.equal(result.details.ok, false);
  assert.match(result.content[0].text, /no observed model/);
  assert.equal(exec.calls.length, 0, "must not call the CLI without a model");
});


test("praiseassistant_request rejects an unknown method", async () => {
  const exec = makeExec(() => ({ stdout: "{}" }));
  const pi = routedPi(exec);
  const tool = pi.tools.find((t) => t.name === "praiseassistant_request");
  const result = await tool.execute(
    "id",
    { url: "https://x", method: "TRACE", role: "scout", engagement_dir: "/tmp/eng" },
    undefined,
    undefined,
    { model: { provider: "opencode-go", id: "deepseek-v4-pro" } },
  );
  assert.equal(result.details.ok, false);
  assert.match(result.content[0].text, /unknown method/);
});

test("tool producer identity cannot be replaced by caller metadata", async (t) => {
  const fixture = await localFixture(t);
  const created = await fixture.invoke("praiseassistant_transition", {
    action: "candidate",
    finding: {
      evidence: ["trace.json"], boundary_invariant: "synthetic control",
      producer_model: "opencode-go/deepseek-v4-pro",
    },
  });
  assert.equal(created.details.ok, true);
  const candidate_id = created.details.data.id;
  const selfReview = await fixture.invoke("praiseassistant_transition", {
    action: "verdict", candidate_id, decision: "rejected", reason: "fixture, not a finding",
  });
  assert.equal(selfReview.details.ok, false);
  const independent = await fixture.invoke("praiseassistant_transition", {
    action: "verdict", candidate_id, decision: "rejected", reason: "fixture, not a finding",
  }, { ...fixture.ctx, model: { provider: "opencode-go", id: "mimo-v2.6-flash" } });
  assert.equal(independent.details.data.status, "rejected");
});

test("typed patch gates reach the real CLI and cannot bypass a failed safety gate", async (t) => {
  const fixture = await localFixture(t);
  const candidate = await fixture.create({
    ...fixture.ctx, model: { provider: "opencode-go", id: "deepseek-v4-pro" },
  });
  const gates = Object.fromEntries(
    ["root_cause", "instance_coverage", "no_new_vulnerabilities", "security_best_practices"]
      .map((name) => [name, { status: "pass", evidence: ["trace.json"] }]),
  );
  const fixed = await fixture.invoke("praiseassistant_transition", {
    action: "validate_fix", candidate_id: candidate.id, validate_fix: gates,
  });
  assert.equal(fixed.details.data.result, "fixed");
  const unsafe = await fixture.invoke("praiseassistant_transition", {
    action: "validate_fix", candidate_id: candidate.id,
    validate_fix: { ...gates, no_new_vulnerabilities: { status: "fail", evidence: ["trace.json"] } },
  });
  assert.equal(unsafe.details.data.result, "not-fixed");
});

test("a family conflict cannot select an alternate cheap checker or authorize a partial batch", async (t) => {
  const fixture = await localFixture(t);
  const independentSource = await fixture.create();
  const conflictingSource = await fixture.create({
    ...fixture.ctx, model: { provider: "opencode-go", id: "deepseek-v4.1-flash" },
  });
  const routed = await fixture.pi.handlers.tool_call[0]({
    toolName: "task",
    input: { tasks: [independentSource, conflictingSource].map((candidate) => ({
      task: header({ stage: "verdict", candidate_id: candidate.id, engagement_dir: fixture.directory }),
    })) },
  }, fixture.ctx);
  assert.equal(routed.block, true);
  assert.equal(routed.input, undefined);
  const spawn = await fixture.pi.handlers.before_subagent_spawn[0]({
    agent: "pentest-skeptic", invocationKind: "task", patterns: [],
  });
  assert.equal(spawn.block, true);
});

test("an active session cannot read or dispatch into a sibling engagement", async (t) => {
  const fixture = await localFixture(t);
  const sibling = path.join(fixture.root, "sibling");
  fs.mkdirSync(sibling);
  const state = await fixture.invoke("praiseassistant_state", { engagement_dir: sibling });
  assert.equal(state.details.ok, false);
  assert.match(state.content[0].text, /cross-engagement/);
  const dispatched = await fixture.pi.handlers.tool_call[0]({
    toolName: "task", input: { task: header({ stage: "plan", engagement_dir: sibling }) },
  }, fixture.ctx);
  assert.equal(dispatched.block, true);
  assert.match(dispatched.reason, /cross-engagement/);
});

test("an active engagement does not restrict the tool surface", async (t) => {
  const fixture = await localFixture(t);
  const fire = (toolName, input) => fixture.pi.handlers.tool_call[0]({ toolName, input }, fixture.ctx);
  for (const [toolName, input] of [
    ["read", { path: "omp://" }],
    ["read", { path: "/etc/hostname" }],
    ["read", { path: "https://example.com/x" }],
    ["grep", { path: "/etc" }],
    ["glob", { path: "/home/**" }],
    ["bash", { command: "id" }],
    ["write", { path: "/tmp/praiseassistant-unrestricted.txt", content: "x" }],
    ["edit", { path: path.join(fixture.directory, "scope.json"), old_string: "x", new_string: "y" }],
  ]) {
    assert.equal(await fire(toolName, input), undefined, `expected ${toolName} ${input.path || input.command} to pass through`);
  }
});

test("header files resolve relative to the session cwd", async (t) => {
  const hits = [];
  const server = http.createServer((request, response) => {
    hits.push(request.url);
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ authorized: request.headers.authorization === "fixture-account-a", witness: "one synthetic record" }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/allowed`;
  const fixture = await localFixture(t, url);
  const outside = path.join(fixture.root, "outside-headers.json");
  fs.writeFileSync(outside, '{"Authorization":"outside-control"}');
  fs.writeFileSync(path.join(fixture.directory, "evidence", "provided.json"), '{"Authorization":"fixture-account-a"}');
  const allowed = await fixture.invoke("praiseassistant_request", {
    url, role: "fixture", headers_file: "evidence/provided.json",
  });
  assert.equal(allowed.details.data?.response_body?.authorized, true, allowed.content[0].text);
  assert.equal(allowed.details.data.response_body.witness, "one synthetic record");
  assert.deepEqual(hits, ["/allowed"]);
  // An absolute header file outside the engagement is no longer refused.
  const outsideRun = await fixture.invoke("praiseassistant_request", { url, role: "fixture", headers_file: outside });
  assert.equal(outsideRun.details.ok, true, outsideRun.content[0].text);
  assert.equal(outsideRun.details.data.response_body.authorized, false);
});

async function anotherFactory(t, fixture, { pi = makePi(), ctx, prompt = "local regression", directory = fixture.directory } = {}) {
  ctx ||= contextFor(pi, directory);
  createCrewRouter(pi, { clientOptions: fixture.clientOptions, catalog: fixture.catalog });
  t.after(() => pi.handlers.session_shutdown[0]());
  const startup = await pi.handlers.before_agent_start[0]({ prompt }, ctx);
  return { pi, ctx, startup, invoke: toolInvoker(pi, ctx) };
}

test("two actual factories share one resident service and address JSON replies live", { timeout: 15_000 }, async (t) => {
  const fixture = await localFixture(t);
  const other = await anotherFactory(t, fixture);
  const initial = JSON.parse(fixture.startup.message.content);
  const second = JSON.parse(other.startup.message.content);
  assert.equal(fixture.processes.length, 1);
  assert.notEqual(initial.agent, second.agent);
  const peers = await fixture.invoke("praiseassistant_message", { action: "peers" });
  assert.ok(peers.details.data.agents.some((peer) => peer.id === second.agent));
  const delivered = nextMessages(other.pi, 1);
  const sent = await fixture.invoke("praiseassistant_message", {
    action: "send", to: second.agent, kind: "ask", data: { question: "gate?" }, key: "ask-one",
    from: second.agent, role: "verdict", model: "spoofed/model", engagement: "/other",
  });
  assert.equal(sent.details.ok, true, sent.content[0].text);
  assert.equal("_messages" in sent.details.data, false);
  const [ask] = await delivered;
  assert.equal(ask.from, initial.agent);
  assert.equal(ask.to, second.agent);
  assert.equal(ask.seq, sent.details.data.seq);
  assert.deepEqual(ask.data, { question: "gate?" });
  assert.deepEqual(other.pi.messages[0].options, { deliverAs: "aside" });
  const replyDelivered = nextMessages(fixture.pi, 1);
  const replied = await other.invoke("praiseassistant_message", {
    action: "send", to: ask.from, kind: "reply", reply_to: ask.seq, data: { answer: "held" },
  });
  assert.equal(replied.details.ok, true, replied.content[0].text);
  const [reply] = await replyDelivered;
  assert.equal(reply.reply, ask.seq);
  assert.equal(reply.from, second.agent);
  assert.deepEqual(reply.data, { answer: "held" });
  const wrongReply = await fixture.invoke("praiseassistant_message", {
    action: "send", to: second.agent, kind: "reply", reply_to: ask.seq, data: { answer: "forged" },
  });
  assert.equal(wrongReply.details.ok, false);
  const duplicate = await fixture.invoke("praiseassistant_message", {
    action: "send", to: second.agent, kind: "ask", data: { question: "gate?" }, key: "ask-one",
  });
  assert.equal(duplicate.details.data.seq, ask.seq);
  assert.equal(duplicate.details.data.duplicate, true);
  const read = await other.invoke("praiseassistant_message", { action: "read" });
  assert.deepEqual(read.details.data.messages, []);
  assert.equal(other.pi.messages.length, 1);
  await fixture.pi.handlers.session_shutdown[0]();
  const stillResident = await other.invoke("praiseassistant_message", { action: "peers" });
  assert.equal(stillResident.details.ok, true);
  assert.equal(fixture.processes.length, 1);
});

test("separate engagements never deliver private messages or share subprocesses", { timeout: 15_000 }, async (t) => {
  const first = await localFixture(t);
  const second = await localFixture(t);
  const address = JSON.parse(first.startup.message.content).agent;
  const selfDelivery = nextMessages(first.pi, 1);
  const sent = await first.invoke("praiseassistant_message", { action: "send", to: address, kind: "close", data: { result: "owned" } });
  assert.equal(sent.details.ok, true);
  await selfDelivery;
  const otherInbox = await second.invoke("praiseassistant_message", { action: "read" });
  assert.deepEqual(otherInbox.details.data.messages, []);
  assert.equal(second.pi.messages.length, 0);
  assert.equal(first.processes.length, 1);
  assert.equal(second.processes.length, 1);
  assert.notEqual(first.processes[0].pid, second.processes[0].pid);
  const cross = await first.invoke("praiseassistant_message", { action: "peers", engagement_dir: second.directory });
  assert.equal(cross.details.ok, false);
});

test("offline durable inbox recovery consumes every page without latest-window loss", { timeout: 20_000 }, async (t) => {
  const fixture = await localFixture(t);
  const recipient = await anotherFactory(t, fixture);
  const address = JSON.parse(recipient.startup.message.content).agent;
  await recipient.pi.handlers.session_shutdown[0]();
  for (let index = 0; index < 40; index++) {
    const result = await fixture.invoke("praiseassistant_message", { action: "send", to: address, kind: "ask", data: { index } });
    assert.equal(result.details.ok, true, result.content[0].text);
  }
  const pi = makePi();
  pi.entries.push(...recipient.pi.entries);
  const recoveredDelivery = nextMessages(pi, 39);
  const restored = await anotherFactory(t, fixture, { pi, ctx: { ...recipient.ctx, sessionManager: { ...recipient.ctx.sessionManager, getEntries: () => pi.entries } } });
  const snapshot = JSON.parse(restored.startup.message.content);
  assert.equal(snapshot.agent, address);
  const messages = [...snapshot.messages, ...await recoveredDelivery];
  assert.deepEqual(messages.map((message) => message.data.index), Array.from({ length: 40 }, (_, index) => index));
  const drained = await restored.invoke("praiseassistant_message", { action: "read" });
  assert.deepEqual(drained.details.data.messages, []);
  assert.ok(pi.entries.at(-1).data.cursor >= messages.at(-1).seq);
});

test("failed push delivery is recovered by the serialized explicit inbox read", { timeout: 15_000 }, async (t) => {
  const fixture = await localFixture(t);
  const recipient = await anotherFactory(t, fixture);
  const address = JSON.parse(recipient.startup.message.content).agent;
  recipient.pi.deliveryError = true;
  const sent = await fixture.invoke("praiseassistant_message", { action: "send", to: address, kind: "ask", data: { recovery: true } });
  assert.equal(sent.details.ok, true);
  const read = await recipient.invoke("praiseassistant_message", { action: "read" });
  assert.equal(read.details.ok, true);
  assert.equal(read.details.data.messages.length, 1);
  assert.equal(read.details.data.messages[0].seq, sent.details.data.seq);
  assert.deepEqual((await recipient.invoke("praiseassistant_message", { action: "read" })).details.data.messages, []);
});

test("startup context is complete bounded JSON and coding outside engagements is untouched", { timeout: 15_000 }, async (t) => {
  const fixture = await localFixture(t);
  assert.equal(fixture.startup.message.attribution, undefined);
  const content = fixture.startup.message.content;
  assert.ok(Buffer.byteLength(content) <= 16_000);
  const startup = JSON.parse(content);
  assert.match(startup.agent, /^a[0-9a-f]+$/);
  assert.equal(startup.role, "lead");
  assert.ok(startup.state && typeof startup.state === "object");
  assert.ok(Array.isArray(startup.messages));
  assert.ok(Array.isArray(startup.lessons));
  const pi = makePi();
  createCrewRouter(pi, { ...emptyFs, requestRunner: () => { throw new Error("must not call backend"); } });
  const ctx = contextFor(pi, "/tmp");
  assert.equal(await pi.handlers.before_agent_start[0]({ prompt: "write local code" }, ctx), undefined);
  assert.equal(await pi.handlers.tool_call[0]({ toolName: "bash", input: { command: "true" } }, ctx), undefined);
  assert.equal(await pi.handlers.tool_call[0]({ toolName: "task", input: { task: "ordinary task" } }, ctx), undefined);
});

test("workflow commit notifications reach an addressed lane and the lead", { timeout: 15_000 }, async (t) => {
  const fixture = await localFixture(t);
  const selector = fixture.catalog.roles[fixture.catalog.stages.gate].models[0].replace(/:(low|medium|high|max)$/, "");
  const [provider, id] = selector.split("/");
  const gatePi = makePi();
  const gate = await anotherFactory(t, fixture, {
    pi: gatePi,
    ctx: { ...contextFor(gatePi, fixture.directory, { kind: "sub", id: "Gate", name: "pentest-verifier" }), model: { provider, id } },
    prompt: header({ stage: "gate", candidate_id: undefined, engagement_dir: fixture.directory }),
  });
  const leadEvent = nextMessages(fixture.pi, 1);
  const gateEvent = nextMessages(gate.pi, 1);
  const candidate = await fixture.create();
  const [lead] = await leadEvent;
  const [event] = await gateEvent;
  assert.equal(event.kind, "event");
  assert.equal(event.data.event, "candidate.created");
  assert.equal(event.case, candidate.id);
  assert.equal(event.to, "@gate");
  assert.equal(lead.seq, event.seq);
});

test("resident timeout rejects uncertain writes without replay or exec fallback and permits explicit restart", { timeout: 10_000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "praiseassistant-client-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const record = path.join(root, "requests.jsonl");
  const script = `
    const fs=require('node:fs'),readline=require('node:readline');
    const file=${JSON.stringify(record)};
    const blocked=!fs.existsSync(file);
    readline.createInterface({input:process.stdin}).on('line',line=>{
      const request=JSON.parse(line);
      fs.appendFileSync(file,line+'\\n');
      if(!blocked)process.stdout.write(JSON.stringify({id:request.id,ok:true,data:{mode:'source'}})+'\\n');
    });
  `;
  const processes = [];
  const client = acquireJsonClient(root, {
    command: process.execPath, prefix: ["-e", script, "--"], timeoutMs: 250,
    spawn(command, args, options) { const child = spawnProcess(command, args, options); processes.push(child); return child; },
  });
  t.after(() => client.release());
  await assert.rejects(client.request(["message", "--data", "{}"]), /not replayed/);
  assert.equal(processes.length, 1);
  assert.equal(fs.readFileSync(record, "utf8").trim().split("\n").length, 1);
  assert.deepEqual(await client.request(["scope"]), { mode: "source" });
  assert.equal(processes.length, 2);
  const requests = fs.readFileSync(record, "utf8").trim().split("\n").map(JSON.parse);
  assert.deepEqual(requests.map((request) => request.args[0]), ["message", "scope"]);
});

test("resident response errors and process death are surfaced and cannot poison a fresh request", { timeout: 15_000 }, async (t) => {
  const fixture = await localFixture(t);
  const lease = acquireJsonClient(fixture.directory);
  t.after(() => lease.release());
  await assert.rejects(lease.request(["inbox", "--agent", "missing"]), /agent|registered|unknown/i);
  assert.equal((await lease.request(["scope"])).mode, "source");
  const child = fixture.processes[0];
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGKILL");
  await exited;
  assert.equal((await lease.request(["scope"])).mode, "source");
  assert.equal(fixture.processes.length, 2);
  await assert.rejects(lease.request(["serve"]), /invalid bound/);
  await assert.rejects(lease.request(["show", "--engagement", "/other"]), /invalid bound/);
});

test("a failed batch leaves no partial authorized spawn record", async () => {
  const exec = dispatchExec({ proof: { agent: "pentest-exploiter", model: "opencode-go/deepseek-v4.1-flash:high" } });
  const pi = routedPi(exec);
  const failed = await pi.handlers.tool_call[0]({
    toolName: "task", input: { tasks: [
      { task: header({ stage: "proof" }) }, { task: header({ stage: "verdict" }) },
    ] },
  });
  assert.equal(failed.block, true);
  assert.equal(failed.input, undefined);
  const spawn = await pi.handlers.before_subagent_spawn[0]({
    agent: "pentest-exploiter", invocationKind: "task", patterns: [],
  });
  assert.equal(spawn.block, true);
});

test("learning promotion, changed evidence and rollback refresh compact lesson context", { timeout: 20_000 }, async (t) => {
  const fixture = await localFixture(t);
  const candidate = await fixture.create();
  const reviewer = { ...fixture.ctx, model: { provider: "opencode-go", id: "mimo-v2.6-flash" } };
  const closed = await fixture.invoke("praiseassistant_transition", {
    action: "verdict", candidate_id: candidate.id, decision: "rejected", reason: "synthetic closed control",
  }, reviewer);
  assert.equal(closed.details.ok, true, closed.content[0].text);
  const observed = await fixture.invoke("praiseassistant_learning", {
    command: "observe", candidate_id: candidate.id, summary: "Require owned evidence for this synthetic boundary", evidence: "trace.json",
  });
  assert.equal(observed.details.ok, true, observed.content[0].text);
  const lesson = observed.details.data.lesson_id;
  const evaluated = await fixture.invoke("praiseassistant_learning", {
    command: "evaluate", lesson_id: lesson, cases: [
      { id: "positive", expected: true, baseline: false, learned: true, evidence: "trace.json" },
      { id: "negative", expected: false, baseline: false, learned: false, evidence: "trace.json" },
    ],
  });
  assert.equal(evaluated.details.ok, true, evaluated.content[0].text);
  assert.equal(evaluated.details.data.passed, true);
  const promoted = await fixture.invoke("praiseassistant_learning", {
    command: "promote", lesson_id: lesson, reason: "matched controls improved without regression",
  }, reviewer);
  assert.equal(promoted.details.ok, true, promoted.content[0].text);
  const refreshed = await fixture.pi.handlers.before_agent_start[0]({ prompt: "next controlled turn" }, fixture.ctx);
  assert.ok(JSON.parse(refreshed.message.content).lessons.some((entry) => entry.id === lesson));
  // No event/revision change: retrieval must still revalidate anchored evidence.
  const artifact = path.join(fixture.directory, "evidence", "trace.json");
  const original = fs.readFileSync(artifact, "utf8");
  fs.writeFileSync(artifact, '{"fixture":"mutated evidence"}');
  const stale = await fixture.pi.handlers.before_agent_start[0]({ prompt: "fresh validation" }, fixture.ctx);
  assert.deepEqual(JSON.parse(stale.message.content).lessons, []);
  fs.writeFileSync(artifact, original);
  const restored = await fixture.pi.handlers.before_agent_start[0]({ prompt: "restored evidence" }, fixture.ctx);
  assert.ok(JSON.parse(restored.message.content).lessons.some((entry) => entry.id === lesson));
  const rolledBack = await fixture.invoke("praiseassistant_learning", {
    command: "rollback", lesson_id: lesson, reason: "explicit controlled deactivation",
  });
  assert.equal(rolledBack.details.ok, true, rolledBack.content[0].text);
  const retired = await fixture.pi.handlers.before_agent_start[0]({ prompt: "after deactivation" }, fixture.ctx);
  assert.deepEqual(JSON.parse(retired.message.content).lessons, []);
});

test("bounded frames fail closed and pending requests reject on resident process death", { timeout: 15_000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "praiseassistant-frames-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [mode, script, error] of [
    ["malformed", "process.stdin.once('data',()=>process.stdout.write('not-json\\n'));", /invalid JSON/],
    ["oversized", "process.stdin.once('data',()=>process.stdout.write('x'.repeat(1024*1024+1)));", /frame limit/],
    ["death", "process.stdin.once('data',()=>process.exit(7));", /exited.*not replayed/],
  ]) {
    const directory = path.join(root, mode);
    fs.mkdirSync(directory);
    const client = acquireJsonClient(directory, { command: process.execPath, prefix: ["-e", script, "--"] });
    t.after(() => client.release());
    await assert.rejects(client.request(["scope"]), error);
    await assert.rejects(client.request(["message", "--data", "x".repeat(1024 * 1024)]), /frame limit/);
  }
});

test("queued aside checkpoints cannot skip undelivered messages after restart", { timeout: 15_000 }, async (t) => {
  const fixture = await localFixture(t);
  const recipient = await anotherFactory(t, fixture);
  const address = JSON.parse(recipient.startup.message.content).agent;
  recipient.pi.deliveryDeferred = true;
  const queued = nextMessages(recipient.pi, 1);
  const sent = await fixture.invoke("praiseassistant_message", {
    action: "send", to: address, kind: "ask", data: { queued: "not durable yet" },
  });
  assert.equal(sent.details.ok, true);
  await queued;
  // Wait for the serialized drain/checkpoint, not a timer or poll.
  await recipient.invoke("praiseassistant_message", { action: "read" });
  await recipient.pi.handlers.session_shutdown[0]();
  const pi = makePi();
  pi.entries.push(...recipient.pi.entries);
  const restored = await anotherFactory(t, fixture, {
    pi, ctx: { ...recipient.ctx, sessionManager: { ...recipient.ctx.sessionManager, getEntries: () => pi.entries } },
  });
  const snapshot = JSON.parse(restored.startup.message.content);
  assert.equal(snapshot.messages.length, 1);
  assert.equal(snapshot.messages[0].seq, sent.details.data.seq);
});

test("durably delivered checkpoints suppress replay on a resumed factory", { timeout: 15_000 }, async (t) => {
  const fixture = await localFixture(t);
  const recipient = await anotherFactory(t, fixture);
  const address = JSON.parse(recipient.startup.message.content).agent;
  const delivered = nextMessages(recipient.pi, 1);
  await fixture.invoke("praiseassistant_message", { action: "send", to: address, kind: "close", data: { delivered: true } });
  await delivered;
  await recipient.invoke("praiseassistant_message", { action: "read" });
  await recipient.pi.handlers.session_shutdown[0]();
  const pi = makePi();
  pi.entries.push(...recipient.pi.entries);
  const restored = await anotherFactory(t, fixture, {
    pi, ctx: { ...recipient.ctx, sessionManager: { ...recipient.ctx.sessionManager, getEntries: () => pi.entries } },
  });
  assert.deepEqual(JSON.parse(restored.startup.message.content).messages, []);
  assert.equal(pi.messages.length, 0);
});

function minimalPacket(finding_id = "C-1") {
  return { hypothesis: "synthetic control", question: "Resolve the named gap",
    relevant_sources: ["fixture:1"], observations: ["owned synthetic observation"],
    evidence: ["trace.json"], proof_status: "unresolved", finding_id };
}

function narrowDispatchExec() {
  return makeExec((args) => {
    const stage = args[args.indexOf("--stage") + 1];
    const tier = args[args.indexOf("--tier") + 1];
    if (args.includes("register")) return { stdout: JSON.stringify({ agent: "aFixture", role: stage || "proof" }) };
    if (args.includes("message")) return { stdout: '{"seq":1}' };
    const agent = tier === "normal" ? CATALOG.stages[stage]
      : tier === "deep" ? CATALOG.escalations[stage] : CATALOG.experts[stage];
    const definition = CATALOG.roles[agent];
    return { stdout: JSON.stringify({
      stage, tier, agent, model: tier === "expert-max" ? definition.max_model : definition.models[0],
      ...(args.includes("--packet") ? { packet: { ref: args[args.indexOf("--packet") + 1],
        sha256: "a".repeat(64), data: minimalPacket() } } : {}),
    }) };
  });
}

test("tier metadata builds real fixed dispatch flags and rejects conflicts or skips", () => {
  const metadata = { stage: "proof", engagement_dir: "/tmp/eng", tier: "expert",
    packet: "packet.json", attempt: 17, reason: "named unresolved gap" };
  assert.equal(validateHeader(metadata), null);
  assert.deepEqual(buildDispatchArgs(metadata), ["--engagement", "/tmp/eng", "dispatch", "--stage", "proof",
    "--tier", "expert", "--reason", "named unresolved gap", "--packet", "packet.json", "--attempt", "17"]);
  for (const invalid of [
    { escalated: false }, { attempt: 0 }, { attempt: "17" }, { attempt: undefined }, { packet: undefined },
    { packet: "../packet.json" }, { packet: "/tmp/packet.json" }, { tier: "max" },
    { reason: "é".repeat(257) }, { confidence: 1 }, { stage: "review" },
  ]) assert.ok(validateHeader({ ...metadata, ...invalid }), JSON.stringify(invalid));
  assert.ok(validateHeader({ stage: "review", engagement_dir: "/tmp/eng" }));
});

test("concurrent Pro HIGH and MAX routes bind exact effort without upgrade or substitution", async () => {
  const exec = narrowDispatchExec();
  const pi = routedPi(exec);
  const items = ["expert", "expert-max"].map((tier) => ({
    task: header({ tier, escalated: true, packet: "packet.json", attempt: tier === "expert" ? 1 : 2,
      reason: "bounded substantive gap" }),
    outputSchema: { type: "object", properties: { own: { type: "string" } } },
  }));
  const result = await pi.handlers.tool_call[0]({ toolName: "task", input: { tasks: items } });
  assert.deepEqual(result.input.tasks.map((item) => item.model),
    ["opencode-go/deepseek-v4-pro:high", "opencode-go/deepseek-v4-pro:max"]);
  assert.deepEqual(result.input.tasks.map((item) => item.outputSchema), items.map((item) => item.outputSchema));
  for (const item of result.input.tasks) {
    const selected = await pi.handlers.before_subagent_spawn[0]({ agent: item.agent, patterns: [item.model] });
    assert.equal(selected.model, item.model);
  }
  for (const patterns of [[], ["opencode-go/deepseek-v4-pro"], ["opencode-go/deepseek-v4-pro:low"],
    ["opencode-go/deepseek-v4.1-flash:high"]]) {
    assert.equal((await pi.handlers.before_subagent_spawn[0]({ agent: "pentest-exploiter-expert", patterns })).block, true);
  }
  assert.ok(exec.calls.every((args) => args.includes("--tier") && args.includes("--packet") && args.includes("--attempt")));
});

test("narrow task transcripts, oversized bodies and absent observed identity cannot authorize a spawn", async () => {
  for (const body of ["x".repeat(4097), "Conversation:\nuser: old prompt\nassistant: old reply", "<|im_start|>assistant"]) {
    const exec = narrowDispatchExec();
    const pi = routedPi(exec);
    const result = await pi.handlers.tool_call[0]({ toolName: "task", input: { task:
      header({ tier: "deep", escalated: true, packet: "packet.json", attempt: 1, reason: "gap" }) + "\n" + body } });
    assert.equal(result.block, true);
    assert.equal(exec.calls.length, 0);
    assert.equal((await pi.handlers.before_subagent_spawn[0]({ agent: "pentest-exploiter-deep", patterns: [] })), undefined);
  }
  const pi = routedPi(narrowDispatchExec());
  const missing = await pi.handlers.tool_call[0]({ toolName: "task", input: { task: header() } }, {});
  assert.equal(missing.block, true);
  const inherited = await pi.handlers.tool_call[0]({ toolName: "task", input: {
    context: "Conversation:\nuser: previous finding\nassistant: previous analysis", task: header({ tier: "deep", escalated: true,
      packet: "packet.json", attempt: 1, reason: "gap" }),
  } });
  assert.equal(inherited.block, true);
  const bounded = await pi.handlers.tool_call[0]({ toolName: "task", input: {
    context: "Scope: isolated fixture. No external targets. Preserve the request budget.",
    task: header({ tier: "deep", escalated: true, packet: "packet.json", attempt: 1, reason: "gap" }),
  } });
  assert.equal(bounded.input.agent, CATALOG.escalations.proof);
  const oversizedShared = await pi.handlers.tool_call[0]({ toolName: "task", input: {
    context: "x".repeat(4097),
    task: header({ tier: "deep", escalated: true, packet: "packet.json", attempt: 1, reason: "gap" }),
  } });
  assert.equal(oversizedShared.block, true);
});

test("a dispatch cannot substitute a cheaper or expensive model for a configured tier", async () => {
  for (const model of ["opencode-go/deepseek-v4-pro:max", "opencode-go/deepseek-v4.1-flash:high"]) {
    const exec = makeExec(() => ({ stdout: JSON.stringify({ agent: "pentest-exploiter-expert", model }) }));
    const pi = routedPi(exec);
    const result = await pi.handlers.tool_call[0]({ toolName: "task", input: { task:
      header({ tier: "expert", escalated: true, packet: "packet.json", attempt: 1, reason: "gap" }) } });
    assert.equal(result.block, true);
    assert.equal((await pi.handlers.before_subagent_spawn[0]({ agent: "pentest-exploiter-expert", patterns: [model] })).block, true);
  }
});

test("expert startup uses whole bounded packet only and host stamps route reports/refusals", async (t) => {
  const exec = narrowDispatchExec();
  const pi = routedPi(exec);
  t.after(() => pi.handlers.session_shutdown[0]());
  const ctx = { ...contextFor(pi, "/tmp/eng", { kind: "sub", name: "pentest-exploiter-expert" }),
    model: { provider: "opencode-go", id: "deepseek-v4-pro" } };
  const result = await pi.handlers.before_agent_start[0]({ prompt:
    header({ tier: "expert", escalated: true, packet: "packet.json", attempt: 1, reason: "gap" }) }, ctx);
  const content = JSON.parse(result.message.content);
  assert.equal(content.worker, "pentest-exploiter-expert");
  assert.equal(content.tier, "expert");
  assert.deepEqual(content.case, { id: "C-1", stage: "proof", tier: "expert" });
  assert.deepEqual(content.packet.data, minimalPacket());
  assert.equal("state" in content, false);
  assert.equal("messages" in content, false);
  assert.ok(Buffer.byteLength(result.message.content) <= 16000);
  assert.equal(exec.calls.some((args) => args.includes("show") || args.includes("inbox")), false);
  const invoke = toolInvoker(pi, ctx);
  const invalid = await invoke("praiseassistant_message", {
    action: "send", to: "@lead", kind: "close", data: { status: "rejected", execution_failure: "refusal" },
  });
  assert.equal(invalid.details.ok, false);
  const sent = await invoke("praiseassistant_message", {
    action: "send", to: "@lead", kind: "close",
    data: { status: "unresolved", execution_failure: "refusal", worker: "lead", tier: "expert-max" },
  });
  assert.equal(sent.details.ok, true);
  const command = exec.calls.find((args) => args.includes("message"));
  assert.deepEqual(JSON.parse(command[command.indexOf("--data") + 1]), {
    status: "unresolved", execution_failure: "refusal", worker: "pentest-exploiter-expert", tier: "expert",
  });
});

test("scoped packet tool writes bounded whole JSON without applying the message data cap", async (t) => {
  const fixture = await localFixture(t);
  const candidate = await fixture.create();
  const data = { ...minimalPacket(candidate.id), observations: Array.from({ length: 6 }, (_, i) => `${i}:` + "x".repeat(450)) };
  assert.ok(Buffer.byteLength(JSON.stringify(data)) > 2048);
  const created = await fixture.invoke("praiseassistant_message", { action: "packet", candidate_id: candidate.id, data });
  assert.equal(created.details.ok, true, created.content[0].text);
  assert.match(created.details.data.ref, /^packet-[a-f0-9]{64}\.json$/);
  const file = path.join(fixture.directory, "evidence", created.details.data.ref);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), data);
  assert.equal(created.details.data.bytes, Buffer.byteLength(fs.readFileSync(file, "utf8")));
  const mismatch = await fixture.invoke("praiseassistant_message", {
    action: "packet", candidate_id: candidate.id, data: { ...data, finding_id: "different-case" },
  });
  assert.equal(mismatch.details.ok, false);
  const oversized = await fixture.invoke("praiseassistant_message", {
    action: "packet", data: { ...data, observations: ["x".repeat(8193)] },
  });
  assert.equal(oversized.details.ok, false);
  const unknown = await fixture.invoke("praiseassistant_message", { action: "packet", data: { ...data, transcript: "history" } });
  assert.equal(unknown.details.ok, false);
});

test("real CLI expert predecessors select HIGH then MAX and stale anchors cannot authorize another spawn", { timeout: 20_000 }, async (t) => {
  const fixture = await localFixture(t);
  const candidate = await fixture.create();
  await fixture.invoke("praiseassistant_transition", { action: "gate", candidate_id: candidate.id, decision: "pass", reason: "synthetic source path" });
  const packet = await fixture.invoke("praiseassistant_message", { action: "packet", candidate_id: candidate.id, data: minimalPacket(candidate.id) });
  assert.equal(packet.details.ok, true, packet.content[0].text);
  const ref = packet.details.data.ref;
  let attempt;
  let highAttempt;
  const routes = [];
  for (const tier of ["normal", "deep", "expert", "expert-max"]) {
    const metadata = { stage: "proof", candidate_id: candidate.id, engagement_dir: fixture.directory, tier,
      escalated: tier !== "normal", ...(tier === "normal" ? {} : { packet: ref, attempt, reason: "substantive cross-request gap" }) };
    const dispatched = await fixture.pi.handlers.tool_call[0]({ toolName: "task", input: { task: header(metadata) } }, fixture.ctx);
    assert.ok(dispatched.input, dispatched.reason);
    routes.push(dispatched.input);
    const workerPi = makePi();
    const model = dispatched.input.model.replace(/:(high|max)$/, "");
    const slash = model.indexOf("/");
    const worker = await anotherFactory(t, fixture, {
      pi: workerPi, prompt: dispatched.input.task,
      ctx: { ...contextFor(workerPi, fixture.directory, { kind: "sub", name: dispatched.input.agent }),
        model: { provider: model.slice(0, slash), id: model.slice(slash + 1) } },
    });
    assert.equal(worker.startup.message.customType, "praiseassistant-scope", worker.startup.message.content);
    if (tier === "expert-max") {
      assert.equal(JSON.parse(worker.startup.message.content).tier, tier);
      continue;
    }
    const closed = await worker.invoke("praiseassistant_message", {
      action: "send", to: "@lead", kind: "close", candidate_id: candidate.id,
      data: { status: "unresolved", finding_id: candidate.id, hypothesis: "synthetic control",
        evidence: ["trace.json", ref], contradictions: [], unresolved_questions: ["substantive cross-request gap"],
        packet: ref, recommended_next_agent: null, execution_failure: "refusal", worker: "spoofed", tier: "normal" },
      evidence: ["trace.json", ref],
    });
    assert.equal(closed.details.ok, true, closed.content[0].text);
    attempt = closed.details.data.seq;
    if (tier === "expert") highAttempt = attempt;
    if (tier !== "normal") {
      const projection = JSON.parse(worker.startup.message.content);
      assert.equal(projection.tier, tier);
      assert.equal("state" in projection, false);
      assert.equal("messages" in projection, false);
    }
  }
  assert.deepEqual(routes.map((route) => route.model), [
    "opencode-go/deepseek-v4.1-flash:high", "opencode-go/deepseek-v4.1-flash:high",
    "opencode-go/deepseek-v4-pro:high", "opencode-go/deepseek-v4-pro:max",
  ]);
  for (const route of routes.slice(2)) {
    assert.equal((await fixture.pi.handlers.before_subagent_spawn[0]({ agent: route.agent, patterns: [route.model] })).model, route.model);
  }
  fs.writeFileSync(path.join(fixture.directory, "evidence", "trace.json"), '{"fixture":"changed current evidence"}');
  const stale = await fixture.pi.handlers.tool_call[0]({ toolName: "task", input: { task: header({
    stage: "proof", tier: "expert-max", escalated: true, candidate_id: candidate.id, engagement_dir: fixture.directory,
    packet: ref, attempt: highAttempt, reason: "remaining concrete gap",
  }) } }, fixture.ctx);
  assert.equal(stale.block, true);
  assert.match(stale.reason, /changed|current|stale|hash/i);
});

test("review lane requires confirmed current proofs and sends observed Blue judgment to the real CLI", { timeout: 20_000 }, async (t) => {
  const fixture = await localFixture(t);
  const candidate = await fixture.create();
  const packet = await fixture.invoke("praiseassistant_message", { action: "packet", data: minimalPacket(candidate.id) });
  assert.equal(packet.details.ok, true, packet.content[0].text);
  let task = header({ stage: "review", candidate_id: candidate.id, engagement_dir: fixture.directory, packet: packet.details.data.ref });
  const route = () => fixture.pi.handlers.tool_call[0]({ toolName: "task", input: { task } }, fixture.ctx);
  assert.equal((await route()).block, true);
  await fixture.invoke("praiseassistant_transition", { action: "gate", candidate_id: candidate.id, decision: "pass", reason: "synthetic gated path" });
  for (const state of ["first", "second"]) {
    const ref = `proof-${state}.json`;
    fs.writeFileSync(path.join(fixture.directory, "evidence", ref), JSON.stringify({ state, owned: true }));
    const proof = await fixture.invoke("praiseassistant_transition", { action: "reproduce", candidate_id: candidate.id,
      run_id: state, clean_state_id: state, evidence: [ref] });
    assert.equal(proof.details.ok, true, proof.content[0].text);
  }
  const verdict = await fixture.invoke("praiseassistant_transition", { action: "verdict", candidate_id: candidate.id,
    decision: "confirmed", reason: "two synthetic clean states", evidence: ["trace.json"] },
  { ...fixture.ctx, model: { provider: "opencode-go", id: "deepseek-v4.1-flash" } });
  assert.equal(verdict.details.ok, true, verdict.content[0].text);
  const reviewPacket = await fixture.invoke("praiseassistant_message", { action: "packet", data: {
    ...minimalPacket(candidate.id), proof_status: "confirmed", evidence: ["proof-first.json", "proof-second.json", "trace.json"],
  } });
  assert.equal(reviewPacket.details.ok, true, reviewPacket.content[0].text);
  task = header({ stage: "review", candidate_id: candidate.id, engagement_dir: fixture.directory, packet: reviewPacket.details.data.ref });
  const before = await fixture.invoke("praiseassistant_state", { candidate_id: candidate.id });
  assert.equal(before.details.data.candidate.report_ready, false);
  const dispatched = await route();
  assert.equal(dispatched.input.agent, "security-reviewer");
  assert.equal(dispatched.input.model, "openai-codex/gpt-daybreak-blue-latest:high");
  const workerPi = makePi();
  const reviewer = await anotherFactory(t, fixture, {
    pi: workerPi, prompt: task,
    ctx: { ...contextFor(workerPi, fixture.directory, { kind: "sub", name: "security-reviewer" }),
      model: { provider: "openai-codex", id: "gpt-daybreak-blue-latest" } },
  });
  const startup = JSON.parse(reviewer.startup.message.content);
  assert.equal(startup.role, "review");
  assert.equal("state" in startup, false);
  fs.writeFileSync(path.join(fixture.directory, "evidence", "review.json"), '{"review":"owned independent synthetic assessment"}');
  const approved = await reviewer.invoke("praiseassistant_transition", { action: "review", candidate_id: candidate.id,
    decision: "approved", reason: "current minimal evidence independently reviewed", evidence: ["review.json"],
    model: "spoofed/model" });
  assert.equal(approved.details.ok, true, approved.content[0].text);
  const state = await fixture.invoke("praiseassistant_state", { candidate_id: candidate.id });
  assert.equal(state.details.data.candidate.review_status, "approved");
  assert.equal(state.details.data.candidate.report_ready, true);
  fs.writeFileSync(path.join(fixture.directory, "evidence", "proof-first.json"), '{"state":"changed"}');
  const stale = await route();
  assert.equal(stale.block, true);
  const current = await fixture.invoke("praiseassistant_state", { candidate_id: candidate.id });
  assert.equal(current.details.data.candidate.report_ready, false);
});

test("installed catalog authorizes a native scoped spawn without catalog injection", { timeout: 15_000 }, async (t) => {
  const fixture = await localFixture(t);
  const agentRoot = path.join(fixture.root, ".omp", "agent");
  const extensions = path.join(agentRoot, "extensions");
  fs.mkdirSync(extensions, { recursive: true });
  for (const name of ["crew-router.js", "json-client.mjs"]) {
    fs.copyFileSync(fileURLToPath(new URL(`../home/.omp/agent/extensions/${name}`, import.meta.url)), path.join(extensions, name));
  }
  fs.writeFileSync(path.join(agentRoot, "crew.json"), JSON.stringify(fixture.catalog));
  const { createCrewRouter: installedRouter } = await import(pathToFileURL(path.join(extensions, "crew-router.js")).href);
  const pi = makePi();
  installedRouter(pi, { clientOptions: fixture.clientOptions });
  t.after(() => pi.handlers.session_shutdown[0]());
  const ctx = contextFor(pi, fixture.directory);
  const routed = await pi.handlers.tool_call[0]({ toolName: "task", input: {
    task: header({ stage: "plan", candidate_id: undefined, engagement_dir: fixture.directory }),
  } }, ctx);
  assert.equal(routed.block, undefined, routed.reason);
  const spawned = await pi.handlers.before_subagent_spawn[0]({
    agent: routed.input.agent, invocationKind: "task", patterns: [],
  }, ctx);
  assert.match(spawned.model, /\/[^/]+-flash:high$/);
  const denied = await pi.handlers.before_subagent_spawn[0]({
    agent: "pentest-finder-expert", invocationKind: "task", patterns: [],
  }, ctx);
  assert.equal(denied.block, true);
});

test("caller-selected unexpected effort fails without authorizing a replacement model", async () => {
  const pi = routedPi(narrowDispatchExec());
  const result = await pi.handlers.tool_call[0]({ toolName: "task", input: {
    model: "opencode-go/deepseek-v4-pro:max",
    task: header({ tier: "expert", escalated: true, packet: "packet.json", attempt: 1, reason: "gap" }),
  } });
  assert.equal(result.block, true);
  assert.match(result.reason, /no substitution/);
  const spawn = await pi.handlers.before_subagent_spawn[0]({
    agent: "pentest-exploiter-expert", patterns: ["opencode-go/deepseek-v4-pro:high"],
  });
  assert.equal(spawn.block, true);
});

test("narrow worker cannot register or report using an unexpected observed model", async (t) => {
  const exec = narrowDispatchExec();
  const pi = routedPi(exec);
  t.after(() => pi.handlers.session_shutdown[0]());
  const ctx = contextFor(pi, "/tmp/eng", { kind: "sub", name: "pentest-exploiter-expert" });
  const startup = await pi.handlers.before_agent_start[0]({ prompt: header({
    tier: "expert", escalated: true, packet: "packet.json", attempt: 1, reason: "gap",
  }) }, ctx);
  assert.equal(startup.message.customType, "praiseassistant-error");
  assert.equal(exec.calls.some((args) => args.includes("register")), false);
  const send = await toolInvoker(pi, ctx)("praiseassistant_message", { action: "send", to: "@lead",
    kind: "close", data: { status: "unresolved", execution_failure: "model" } });
  assert.equal(send.details.ok, false);
});
