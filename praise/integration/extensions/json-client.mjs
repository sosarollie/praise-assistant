import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const pool = new Map();
const MAX_FRAME = 1024 * 1024;
const COMMANDS = new Set(["scope", "register", "message", "inbox", "peers", "project", "show", "dispatch"]);

export function engagementPath(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw new Error("engagement must be absolute");
  return fs.realpathSync(directory);
}

class ResidentClient {
  constructor(directory, options) {
    this.directory = directory;
    this.options = options;
    this.refs = 0;
    this.nextId = 0;
    this.pending = new Map();
    this.subscribers = new Set();
    this.process = null;
    this.failure = null;
  }

  fail(error) {
    if (this.failure) return;
    this.failure = error;
    const child = this.process;
    this.process = null;
    child?.stdin.destroy();
    child?.kill("SIGKILL");
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  start() {
    if (this.failure) throw this.failure;
    if (this.process) return;
    const child = (this.options.spawn || spawn)(this.options.command || process.env.PRAISE_CLI || "praise",
      [...(this.options.prefix || []), "--engagement", this.directory, "serve"],
      { cwd: this.options.cwd, env: this.options.env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true, shell: false });
    this.process = child;
    let buffer = Buffer.alloc(0);
    const fail = (reason) => this.fail(new Error(`${reason}; outcome may be committed; requests are not replayed`));
    child.on("error", () => fail("resident service failed"));
    child.on("exit", () => fail("resident service exited"));
    child.stdin.on("error", () => fail("resident input failed"));
    child.stdout.on("error", () => fail("resident output failed"));
    child.stderr.on("error", () => fail("resident diagnostics failed"));
    child.stderr.on("data", () => {}); // Diagnostics may contain private engagement data.
    child.stdout.on("data", (chunk) => {
      if (this.process !== child) return;
      buffer = Buffer.concat([buffer, chunk]);
      while (!this.failure) {
        const end = buffer.indexOf(10);
        if (end < 0) {
          if (buffer.length > MAX_FRAME) fail("resident frame exceeds limit");
          return;
        }
        if (end > MAX_FRAME) { fail("resident frame exceeds limit"); return; }
        let reply;
        try { reply = JSON.parse(buffer.subarray(0, end).toString("utf8")); }
        catch { fail("resident returned invalid JSON"); return; }
        buffer = buffer.subarray(end + 1);
        const pending = this.pending.get(reply?.id);
        if (!pending || typeof reply.ok !== "boolean" ||
            (reply.ok && (!reply.data || typeof reply.data !== "object" || Array.isArray(reply.data))) ||
            (!reply.ok && typeof reply.error !== "string")) {
          fail("resident returned invalid response"); return;
        }
        if (!reply.ok) {
          this.pending.delete(reply.id);
          clearTimeout(pending.timer);
          pending.reject(new Error(reply.error));
          continue;
        }
        const { _messages = [], ...data } = reply.data;
        if (!Array.isArray(_messages) || _messages.length > 64 || _messages.some((m) =>
          !m || !Number.isSafeInteger(m.seq) || m.seq < 1 || typeof m.from !== "string" || typeof m.to !== "string" ||
          !["ask", "reply", "close", "event"].includes(m.kind) || !m.data || typeof m.data !== "object" ||
          Array.isArray(m.data) || Buffer.byteLength(JSON.stringify(m)) > 8192)) {
          fail("resident returned invalid notifications"); return;
        }
        this.pending.delete(reply.id);
        clearTimeout(pending.timer);
        for (const message of _messages) {
          for (const { identity, notify } of this.subscribers) {
            if (message.to === identity.agent || message.to === `@${identity.role}`) {
              try { Promise.resolve(notify(message)).catch(() => {}); }
              catch { /* The durable inbox retains failed deliveries. */ }
            }
          }
        }
        pending.resolve(data);
      }
    });
  }

  request(args) {
    if (!Array.isArray(args) || !COMMANDS.has(args[0]) || args.some((arg) =>
      typeof arg !== "string" || arg === "--engagement" || arg.startsWith("--engagement="))) {
      return Promise.reject(new Error("invalid bound resident command"));
    }
    if (this.pending.size >= 128) return Promise.reject(new Error("resident pending request limit reached"));
    const id = ++this.nextId;
    const frame = JSON.stringify({ id, args }) + "\n";
    if (Buffer.byteLength(frame) > MAX_FRAME) return Promise.reject(new Error("resident request exceeds limit"));
    return new Promise((resolve, reject) => {
      try { this.start(); } catch (error) { reject(error); return; }
      const timer = setTimeout(() => this.fail(new Error("resident timed out; outcome may be committed; requests are not replayed")),
        this.options.timeoutMs ?? 30_000);
      this.pending.set(id, { resolve, reject, timer });
      this.process.stdin.write(frame, (error) => { if (error) this.fail(new Error("resident write failed; requests are not replayed")); });
    });
  }

  close() {
    this.fail(new Error("resident lease released; requests are not replayed"));
    this.subscribers.clear();
  }
}

export function acquireJsonClient(directory, options = {}) {
  const key = engagementPath(directory);
  let client = pool.get(key);
  if (!client) { client = new ResidentClient(key, options); pool.set(key, client); }
  client.refs++;
  let released = false;
  const subscriptions = new Set();
  return {
    request: (args) => released ? Promise.reject(new Error("resident lease released")) : client.request(args),
    subscribe(identity, notify) {
      if (released) throw new Error("resident lease released");
      const subscriber = { identity, notify };
      client.subscribers.add(subscriber);
      subscriptions.add(subscriber);
      return () => { client.subscribers.delete(subscriber); subscriptions.delete(subscriber); };
    },
    release() {
      if (released) return;
      released = true;
      for (const subscriber of subscriptions) client.subscribers.delete(subscriber);
      subscriptions.clear();
      if (--client.refs === 0) { client.close(); pool.delete(key); }
    },
  };
}
