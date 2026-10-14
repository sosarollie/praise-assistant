import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const pool = new Map();
const MAX_FRAME = 1024 * 1024;
const COMMANDS = new Set(["scope", "register", "message", "packet", "inbox", "peers", "show", "dispatch", "request", "candidate", "gate", "reproduce", "verdict", "review", "validate-fix", "learn", "project"]);

function engagementKey(directory) {
  if (!path.isAbsolute(directory)) throw new Error("engagement must be absolute");
  try { return fs.realpathSync(directory); } catch { return path.resolve(directory); }
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
    this.lessons = null;
    this.lessonEpoch = 0;
  }

  start() {
    if (this.process) return;
    const child = (this.options.spawn || spawn)(this.options.command || process.env.PRAISEASSISTANT_CLI || "praiseassistant", [...(this.options.prefix || []), "--engagement", this.directory, "serve"], {
      cwd: this.options.cwd,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      shell: false,
    });
    this.process = child;
    let buffer = Buffer.alloc(0);
    const fail = (error) => {
      if (this.process !== child) return;
      this.process = null;
      child.stdin.destroy();
      child.kill("SIGKILL");
      for (const request of this.pending.values()) {
        clearTimeout(request.timer);
        request.reject(error);
      }
      this.pending.clear();
    };
    child.on("error", (error) => fail(new Error(`resident service failed: ${error.message}`)));
    child.on("exit", (code, signal) => fail(new Error(`resident service exited (${signal || code}); outcome may be committed; writes are not replayed`)));
    child.stdin.on("error", (error) => fail(new Error(`resident input failed: ${error.message}; writes are not replayed`)));
    child.stdout.on("error", () => fail(new Error("resident output failed; writes are not replayed")));
    child.stderr.on("error", () => fail(new Error("resident diagnostic stream failed; writes are not replayed")));
    // Never retain or disclose raw diagnostic output, which may contain evidence.
    child.stderr.on("data", () => {});
    child.stdout.on("data", (chunk) => {
      if (this.process !== child) return;
      buffer = Buffer.concat([buffer, chunk]);
      while (true) {
        const end = buffer.indexOf(10);
        if (end < 0) {
          if (buffer.length > MAX_FRAME) fail(new Error("resident response exceeds frame limit"));
          return;
        }
        if (end > MAX_FRAME) { fail(new Error("resident response exceeds frame limit")); return; }
        const frame = buffer.subarray(0, end);
        buffer = buffer.subarray(end + 1);
        let reply;
        try { reply = JSON.parse(frame.toString("utf8")); } catch {
          fail(new Error("resident service returned invalid JSON")); return;
        }
        const request = this.pending.get(reply?.id);
        if (!request || typeof reply.ok !== "boolean" || (reply.ok && (!reply.data || typeof reply.data !== "object" || Array.isArray(reply.data))) || (!reply.ok && typeof reply.error !== "string")) {
          fail(new Error("resident service returned an invalid response")); return;
        }
        this.pending.delete(reply.id);
        clearTimeout(request.timer);
        if (!reply.ok) { request.reject(new Error(reply.error)); continue; }
        const { _messages = [], ...data } = reply.data;
        if (!Array.isArray(_messages)) { fail(new Error("resident service returned invalid notifications")); request.reject(new Error("invalid notifications")); return; }
        for (const message of _messages) {
          if (!message || !Number.isSafeInteger(message.seq) || message.seq < 1 ||
              typeof message.from !== "string" || typeof message.to !== "string" ||
              !["ask", "reply", "close", "event"].includes(message.kind) ||
              !message.data || typeof message.data !== "object" || Array.isArray(message.data) ||
              Buffer.byteLength(JSON.stringify(message)) > 4096) {
            fail(new Error("resident service returned an invalid message envelope"));
            request.reject(new Error("invalid message envelope"));
            return;
          }
          if (message.kind === "event" && ["learning.evaluated", "learning.promoted", "learning.rolled_back"].includes(message.data?.event)) {
            this.lessonEpoch++;
            this.lessons = null;
          }
          for (const subscriber of this.subscribers) {
            if (matches(message, subscriber.identity)) {
              try { Promise.resolve(subscriber.notify(message)).catch(() => {}); } catch { /* durable inbox recovers failed delivery */ }
            }
          }
        }
        request.resolve(data);
      }
    });
  }

  request(args) {
    if (!Array.isArray(args) || !COMMANDS.has(args[0]) || args.some((arg) => typeof arg !== "string" || arg === "--engagement" || arg.startsWith("--engagement="))) {
      return Promise.reject(new Error("invalid bound resident command"));
    }
    const id = ++this.nextId;
    const frame = JSON.stringify({ id, args }) + "\n";
    if (Buffer.byteLength(frame) > MAX_FRAME) return Promise.reject(new Error("resident request exceeds frame limit"));
    return new Promise((resolve, reject) => {
      try { this.start(); } catch (error) { reject(error); return; }
      const child = this.process;
      const timer = setTimeout(() => {
        if (!this.pending.has(id)) return;
        this.process = null;
        child.stdin.destroy();
        child.kill("SIGKILL");
        for (const request of this.pending.values()) {
          clearTimeout(request.timer);
          request.reject(new Error("resident service timed out; outcome may be committed; writes are not replayed"));
        }
        this.pending.clear();
      }, this.options.timeoutMs || 30_000);
      this.pending.set(id, { resolve, reject, timer });
      child.stdin.write(frame, (error) => {
        if (error && this.pending.has(id)) {
          // The process error handler rejects every in-flight request. Do not resend.
          child.emit("error", error);
        }
      });
    });
  }

  subscribe(identity, notify) {
    const subscriber = { identity, notify };
    this.subscribers.add(subscriber);
    return () => this.subscribers.delete(subscriber);
  }

  async approvedLessons() {
    if (!this.lessons) {
      const epoch = this.lessonEpoch;
      const pending = this.request(["learn", "list", "--approved", "--compact", "--limit", "4"])
        .then((data) => epoch === this.lessonEpoch ? data : this.approvedLessons());
      this.lessons = pending;
      pending.finally(() => {
        // Evidence files can change without changing the revision. Only share
        // in-flight validation; never serve a settled payload without rechecking.
        if (this.lessons === pending) this.lessons = null;
      }).catch(() => {});
    }
    return this.lessons;
  }

  close() {
    const child = this.process;
    this.process = null;
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error("resident service released; writes are not replayed"));
    }
    this.pending.clear();
    this.subscribers.clear();
    if (child) { child.stdin.end(); child.kill("SIGKILL"); }
  }
}

function matches(message, identity) {
  if (identity.role === "lead" && message.kind === "event") return true;
  if (message.to === identity.agent) return true;
  if (message.to !== `@${identity.role}` && !(identity.role === "lead" && message.to === "@learning")) return false;
  return !identity.candidate_id || message.case == null || message.case === identity.candidate_id;
}

export function acquireJsonClient(directory, options = {}) {
  const key = engagementKey(directory);
  let client = pool.get(key);
  if (!client) { client = new ResidentClient(key, options); pool.set(key, client); }
  client.refs++;
  let released = false;
  return {
    request: (args) => released ? Promise.reject(new Error("resident lease released")) : client.request(args),
    subscribe: (identity, notify) => {
      if (released) throw new Error("resident lease released");
      return client.subscribe(identity, notify);
    },
    approvedLessons: () => released ? Promise.reject(new Error("resident lease released")) : client.approvedLessons(),
    release() {
      if (released) return;
      released = true;
      if (--client.refs === 0) { client.close(); pool.delete(key); }
    },
  };
}
