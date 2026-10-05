import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import http from "node:http";

import {
  parseTaskHeader,
  validateHeader,
  computeAuthorizedRoots,
  isPathWithinScope,
  guardToolCall,
  createCrewRouter,
} from "../home/.omp/agent/extensions/crew-router.js";

const STAGES = new Set(["plan", "recon", "discover", "gate", "proof", "verdict", "patch"]);

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
  const optional = { optional: () => optional };
  const prim = { ...optional };
  return {
    string: () => prim,
    boolean: () => prim,
    array: () => ({ ...optional }),
    object: () => ({ ...optional }),
  };
}

function makePi() {
  const tools = [];
  const handlers = {};
  return {
    zod: makeZod(),
    tools,
    handlers,
    logger: { info() {} },
    registerTool(def) {
      tools.push(def);
    },
    on(event, handler) {
      (handlers[event] ||= []).push(handler);
    },
  };
}

// Fake execFile: records calls, delegates to a per-call handler.
function makeExec(handler) {
  const fn = async (_cmd, args) => {
    const result = handler(args, fn.calls.length);
    fn.calls.push(args);
    if (result && result.reject) {
      const err = new Error(result.reject.message || "cli failed");
      err.code = result.reject.code != null ? result.reject.code : 1;
      err.stderr = result.reject.stderr || "";
      throw err;
    }
    return { stdout: result && result.stdout != null ? result.stdout : "", stderr: "" };
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
  if (url) init.push("--mode", "audit", "--asset", url, "--max-requests", "1", "--interval", "0");
  await exec("", init);
  fs.writeFileSync(path.join(directory, "evidence", "trace.json"), '{"fixture":"controlled evidence"}');
  const pi = makePi();
  const catalog = JSON.parse(fs.readFileSync(new URL("../praiseassistant/roles.json", import.meta.url), "utf8"));
  createCrewRouter(pi, { execFile: exec, catalog });
  const ctx = { cwd: directory, model: { provider: "opencode-go", id: "glm-5.3-flash" } };
  await pi.handlers.before_agent_start[0]({ prompt: "local regression" }, ctx);
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
  return { root, directory, pi, ctx, invoke, create };
}
const tmpdir = () => "/tmp";

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
// Path scoping.
// ---------------------------------------------------------------------------

test("path scoping authorizes the engagement dir and declared local asset dirs", () => {
  const roots = computeAuthorizedRoots("/tmp/eng", {
    mode: "source",
    assets: ["/srv/target", "https://target.example"],
  });
  assert.deepEqual(roots, ["/tmp/eng", "/srv/target"]);
});

test("path scoping rejects non-local protocols (URLs and internal URIs)", () => {
  const roots = ["/tmp/eng"];
  assert.equal(isPathWithinScope("https://example.com/x", roots, "/tmp/eng"), false);
  assert.equal(isPathWithinScope("ssh://host/etc/passwd", roots, "/tmp/eng"), false);
  assert.equal(isPathWithinScope("skill://agents-chat", roots, "/tmp/eng"), false);
  assert.equal(isPathWithinScope("file:///etc/passwd", roots, "/tmp/eng"), false);
});

test("path scoping rejects traversal outside the authorized root", () => {
  const roots = ["/tmp/eng"];
  assert.equal(isPathWithinScope("/etc/passwd", roots, "/tmp/eng"), false);
  assert.equal(isPathWithinScope("../outside", roots, "/tmp/eng"), false);
  assert.equal(isPathWithinScope("/tmp/eng/evidence/x.json", roots, "/tmp/eng"), true);
});

test("path scoping treats glob prefixes against the authorized root", () => {
  const roots = ["/tmp/eng"];
  assert.equal(isPathWithinScope("/tmp/eng/**/*.js", roots, "/tmp/eng"), true);
  assert.equal(isPathWithinScope("/home/**", roots, "/tmp/eng"), false);
});

// ---------------------------------------------------------------------------
// Guard invariants (pure).
// ---------------------------------------------------------------------------

const ACTIVE = {
  engagementDir: "/tmp/eng",
  mode: "blackbox",
  enforce: true,
  authorizedRoots: ["/tmp/eng"],
};

test("guard blocks shell, eval, browser, remote reads, and write tools", () => {
  for (const name of ["bash", "eval", "python", "browser", "computer", "web_search", "web_fetch", "write", "edit", "mcp_something"]) {
    const r = guardToolCall(name, {}, "/tmp/eng", ACTIVE);
    assert.ok(r && r.block, `expected ${name} to be blocked`);
  }
});

test("guard allows constrained inspection and the trusted tools", () => {
  assert.equal(guardToolCall("read", { path: "/tmp/eng/evidence/x.json" }, "/tmp/eng", ACTIVE), null);
  assert.equal(guardToolCall("grep", { path: "/tmp/eng" }, "/tmp/eng", ACTIVE), null);
  assert.equal(guardToolCall("glob", { path: "/tmp/eng/**" }, "/tmp/eng", ACTIVE), null);
  for (const name of ["task", "yield", "wait", "praiseassistant_state", "praiseassistant_chat", "praiseassistant_request", "praiseassistant_transition", "praiseassistant_learning"]) {
    assert.equal(guardToolCall(name, {}, "/tmp/eng", ACTIVE), null, `expected ${name} to be allowed`);
  }
});

test("guard blocks URL reads even through the read tool", () => {
  const r = guardToolCall("read", { path: "https://example.com/x" }, "/tmp/eng", ACTIVE);
  assert.ok(r && r.block);
});

test("guard does nothing outside an active scope (generic coding preserved)", () => {
  assert.equal(guardToolCall("bash", {}, "/tmp/eng", null), null);
  assert.equal(guardToolCall("bash", {}, "/tmp/eng", { enforce: false }), null);
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
  },
  escalations: { discover: "pentest-finder-deep", proof: "pentest-exploiter-deep", verdict: "pentest-skeptic-deep" },
  roles: {
    "pentest-exploiter": { models: ["opencode-go/deepseek-v4-pro:high"] },
    "pentest-skeptic": { models: ["opencode-go/glm-5.3-flash:high"], independent: true },
  },
};

function routedPi(exec) {
  const pi = makePi();
  const deps = { execFile: exec, ...emptyFs, tmpdir, catalog: CATALOG, cliCmd: "praiseassistant" };
  createCrewRouter(pi, deps);
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
    proof: { stage: "proof", agent: "pentest-exploiter", model: "opencode-go/deepseek-v4-pro:high" },
    verdict: { stage: "verdict", agent: "pentest-skeptic", model: "opencode-go/glm-5.3-flash:high" },
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
    ["opencode-go/deepseek-v4-pro:high", "opencode-go/glm-5.3-flash:high"],
  );
});

test("a failed dispatch returns block, never a fallback agent", async () => {
  const exec = makeExec(() => ({ reject: { stderr: '{"error":"candidate not gated"}', code: 2 } }));
  const pi = routedPi(exec);
  const handler = pi.handlers.tool_call[0];

  const result = await handler({ toolName: "task", input: { task: header({ stage: "proof" }) } });
  assert.ok(result && result.block, "expected a block");
  assert.match(result.reason, /dispatch failed/);
  assert.equal(result.input, undefined, "must not fall back to a default agent/model");
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

test("a header-less task inside an active scope is blocked", async () => {
  const exec = dispatchExec({
    proof: { stage: "proof", agent: "pentest-exploiter", model: "opencode-go/deepseek-v4-pro:high" },
  });
  const pi = routedPi(exec);
  const handler = pi.handlers.tool_call[0];

  await handler({ toolName: "task", input: { task: header({ stage: "proof" }) } });
  const result = await handler({ toolName: "task", input: { task: "do some generic thing" } });
  assert.ok(result && result.block);
  assert.match(result.reason, /without PraiseAssistant-Task metadata/);
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
  const deep = await route({ escalated: true, reason: "cross-request chain remains unresolved" });
  assert.equal(deep.input.agent, "pentest-exploiter-deep");
  const missingReason = await route({ escalated: true });
  assert.equal(missingReason.block, true);
});

// ---------------------------------------------------------------------------
// Per-session state isolation and the spawn re-check.
// ---------------------------------------------------------------------------

test("active scope is isolated per factory invocation (session)", async () => {
  const execA = dispatchExec({ proof: { stage: "proof", agent: "pentest-exploiter", model: "opencode-go/deepseek-v4-pro:high" } });
  const piA = routedPi(execA);
  const piB = routedPi(makeExec(() => ({ stdout: "{}" })));

  await piA.handlers.tool_call[0]({ toolName: "task", input: { task: header({ stage: "proof" }) } });

  const blockedA = await piA.handlers.tool_call[0]({ toolName: "bash", input: { command: "id" } });
  assert.ok(blockedA && blockedA.block, "session A should guard bash");

  const freeB = await piB.handlers.tool_call[0]({ toolName: "bash", input: { command: "id" } });
  assert.equal(freeB, undefined, "session B must remain unguarded");
});

test("before_subagent_spawn respects the dispatch model and blocks undispatch crew spawns", async () => {
  const exec = dispatchExec({ proof: { stage: "proof", agent: "pentest-exploiter", model: "opencode-go/deepseek-v4-pro:high" } });
  const pi = routedPi(exec);
  const toolCall = pi.handlers.tool_call[0];
  const spawn = pi.handlers.before_subagent_spawn[0];

  await toolCall({ toolName: "task", input: { task: header({ stage: "proof" }) } });

  const allowed = await spawn({ agent: "pentest-exploiter", invocationKind: "task", patterns: [] });
  assert.equal(allowed.model, "opencode-go/deepseek-v4-pro:high");

  const blocked = await spawn({ agent: "pentest-skeptic", invocationKind: "task", patterns: [] });
  assert.ok(blocked && blocked.block);
  assert.match(blocked.reason, /without a PraiseAssistant-Task dispatch record/);
});

// ---------------------------------------------------------------------------
// Tool write guards (observed model required).
// ---------------------------------------------------------------------------

test("praiseassistant_chat refuses a write without an observed model", async () => {
  const exec = makeExec(() => ({ stdout: "{}" }));
  const pi = routedPi(exec);
  const tool = pi.tools.find((t) => t.name === "praiseassistant_chat");
  const result = await tool.execute("id", { role: "scout", summary: "x", ask: "y", engagement_dir: "/tmp/eng" }, undefined, undefined, {});
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

test("inspection refuses symlink escapes including reader selectors", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "praiseassistant-path-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, "eng");
  fs.mkdirSync(directory);
  const outside = path.join(root, "outside.txt");
  fs.writeFileSync(outside, "synthetic out-of-scope record");
  fs.symlinkSync(outside, path.join(directory, "link.txt"));
  assert.equal(isPathWithinScope(path.join(directory, "link.txt"), [directory], directory), false);
  assert.equal(isPathWithinScope(path.join(directory, "link.txt:1-5"), [directory], directory), false);
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

test("one batch can bind different checker families for the same role", async (t) => {
  const fixture = await localFixture(t);
  const first = await fixture.create();
  const second = await fixture.create({
    ...fixture.ctx, model: { provider: "opencode-go", id: "mimo-v2.6-flash" },
  });
  const routed = await fixture.pi.handlers.tool_call[0]({
    toolName: "task",
    input: { tasks: [first, second].map((candidate) => ({
      task: header({ stage: "verdict", candidate_id: candidate.id, engagement_dir: fixture.directory }),
    })) },
  }, fixture.ctx);
  const models = [];
  for (const item of routed.input.tasks) {
    const selected = await fixture.pi.handlers.before_subagent_spawn[0]({
      agent: item.agent, invocationKind: "task", patterns: [item.model],
    });
    models.push(selected.model);
  }
  assert.match(models[0], /mimo-v2\.6-flash/);
  assert.match(models[1], /glm-5\.3-flash/);
  const ambiguous = await fixture.pi.handlers.before_subagent_spawn[0]({
    agent: "pentest-skeptic", invocationKind: "task", patterns: [],
  });
  assert.equal(ambiguous.block, true);
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

test("trusted workflow instructions are readable without opening other skill paths", () => {
  assert.equal(guardToolCall("read", { path: "skill://agents-chat" }, "/tmp/eng", ACTIVE), null);
  assert.equal(guardToolCall("read", { path: "skill://agents-chat/../../other-engagement" }, "/tmp/eng", ACTIVE).block, true);
});

test("header references are scoped and relative names resolve against the engagement", async (t) => {
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
  const alias = path.join(fixture.directory, "evidence", "headers:alias.json");
  fs.symlinkSync(outside, alias);
  for (const headers_file of [outside, alias]) {
    const denied = await fixture.invoke("praiseassistant_request", { url, role: "fixture", headers_file });
    assert.equal(denied.details.ok, false);
    assert.match(denied.content[0].text, /header file is outside/);
  }
  assert.deepEqual(hits, []);
  fs.writeFileSync(path.join(fixture.directory, "evidence", "provided.json"), '{"Authorization":"fixture-account-a"}');
  const allowed = await fixture.invoke("praiseassistant_request", {
    url, role: "fixture", headers_file: "evidence/provided.json",
  });
  assert.equal(allowed.details.data?.response_body?.authorized, true, allowed.content[0].text);
  assert.equal(allowed.details.data.response_body.witness, "one synthetic record");
});
