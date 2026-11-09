// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The OpenCode plugin file Omnodex installs.
 *
 * OpenCode has no command hooks; it loads JavaScript plugins from
 * `~/.config/opencode/plugins/` (every project) or `<project>/.opencode/plugins/`
 * (one). The plugin below does no work of its own: for each event it sends a
 * small JSON envelope to the shared launcher (the same one the other agents'
 * hooks run) and, for a tool call about to run, reads the answer. A deny
 * becomes a thrown error, which is how OpenCode stops a call.
 *
 * Every other failure is swallowed, because a throw from a before-hook blocks
 * the user's call: a missing launcher, a crash, a timeout and an answer that
 * is not JSON all mean "no decision". Events are sent one after another, so a
 * session start and a prompt are recorded before the first tool call is judged.
 * Only the before-hook waits for the launcher; everything else is queued.
 *
 * Envelope fields: event (session.start, session.end, prompt, tool.before,
 * tool.after, tool.error, subagent.start, subagent.stop), session_id (the
 * root session; a subagent's own id is agent_id), cwd, model, prompt, tool,
 * call_id, args, output, duration_ms, error.
 *
 * The file starts with a marker line so uninstall removes only a file Omnodex
 * wrote.
 */

export const PLUGIN_MARKER = "omnodex-managed";

export interface PluginSourceOptions {
  /** Node binary the launcher runs under. */
  nodePath: string;
  /** Absolute path of the launcher (or the shim for a legacy install). */
  launcherPath: string;
  omnodexHome: string;
  /** Marks the file as the every-project one (the launcher then lets project copies step aside). */
  userScope?: boolean;
  debug?: boolean;
  /** Longest wait for the launcher on a tool call, in milliseconds. */
  timeoutMs?: number;
}

/** The text of the plugin file. */
export function buildPluginSource(opts: PluginSourceOptions): string {
  const config = {
    node: opts.nodePath,
    launcher: opts.launcherPath,
    home: opts.omnodexHome,
    userScope: opts.userScope === true,
    debug: opts.debug === true,
    timeoutMs: opts.timeoutMs ?? 20_000,
  };
  return PLUGIN_TEMPLATE.replace("__CONFIG__", JSON.stringify(config, null, 2));
}

// The body avoids template literals so this string needs no escaping.
const PLUGIN_TEMPLATE = String.raw`// ${PLUGIN_MARKER}: written by omnodex install opencode. Remove it with omnodex uninstall opencode.
import { spawn } from "node:child_process";

const CONFIG = __CONFIG__;

function send(payload, wait) {
  return new Promise(function (resolve) {
    var settled = false;
    var out = "";
    var child;
    var timer;
    function done(value) {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(value);
    }
    try {
      var env = Object.assign({}, process.env, { OMNODEX_HOME: CONFIG.home });
      if (CONFIG.debug) env.OMNODEX_DEBUG = "1";
      child = spawn(CONFIG.node, [CONFIG.launcher].concat(CONFIG.userScope ? ["--user-scope"] : []), {
        env: env,
        stdio: ["pipe", "pipe", "ignore"],
        windowsHide: true,
      });
      child.on("error", function () { done(undefined); });
      child.stdout.on("data", function (d) { out += d; });
      child.stdout.on("error", function () {});
      child.stdin.on("error", function () {});
      child.on("close", function () {
        if (!wait) return done(undefined);
        try {
          var parsed = JSON.parse(out);
          done(parsed && typeof parsed === "object" ? parsed : undefined);
        } catch (e) {
          done(undefined);
        }
      });
      timer = setTimeout(function () {
        try { child.kill(); } catch (e) {}
        done(undefined);
      }, CONFIG.timeoutMs);
      child.stdin.end(JSON.stringify(payload));
    } catch (e) {
      done(undefined);
    }
  });
}

export const OmnodexPlugin = async function (input) {
  var directory = (input && (input.directory || input.worktree)) || process.cwd();
  var parents = new Map();
  var started = new Set();
  var starts = new Map();
  var finished = new Set();
  var chain = Promise.resolve();

  function enqueue(payload, wait) {
    var next = chain.then(function () { return send(payload, wait); });
    chain = next.then(function () {}, function () {});
    return next;
  }
  function rootOf(id) {
    var seen = 0;
    while (parents.has(id) && seen++ < 20) id = parents.get(id);
    return id;
  }
  function envelope(event, sessionId, extra) {
    var root = rootOf(sessionId);
    var body = { event: event, session_id: root, cwd: directory, ts: new Date().toISOString() };
    if (root !== sessionId) body.agent_id = sessionId;
    return Object.assign(body, extra || {});
  }
  function ensureStarted(sessionId) {
    var root = rootOf(sessionId);
    if (started.has(root)) return;
    started.add(root);
    enqueue(envelope("session.start", root));
  }

  return {
    event: async function (arg) {
      try {
        var ev = arg && arg.event;
        if (!ev || !ev.properties) return;
        var p = ev.properties;
        if (ev.type === "session.created" && p.info && p.info.id) {
          if (p.info.directory) directory = p.info.directory;
          if (p.info.parentID) {
            parents.set(p.info.id, p.info.parentID);
            ensureStarted(p.info.parentID);
            enqueue(envelope("subagent.start", p.info.id, { agent_type: p.info.title }));
          } else if (!started.has(p.info.id)) {
            started.add(p.info.id);
            enqueue(envelope("session.start", p.info.id));
          }
        } else if (ev.type === "session.idle" && p.sessionID && parents.has(p.sessionID)) {
          enqueue(envelope("subagent.stop", p.sessionID));
        } else if (ev.type === "session.deleted" && p.info && p.info.id && !p.info.parentID) {
          enqueue(envelope("session.end", p.info.id, { reason: "completed" }));
        } else if (ev.type === "message.part.updated" && p.part && p.part.type === "tool" && p.part.state && p.part.state.status === "error") {
          if (finished.has(p.part.callID)) return;
          finished.add(p.part.callID);
          ensureStarted(p.part.sessionID);
          enqueue(envelope("tool.error", p.part.sessionID, {
            tool: p.part.tool,
            call_id: p.part.callID,
            args: p.part.state.input,
            error: p.part.state.error,
            duration_ms: starts.has(p.part.callID) ? Date.now() - starts.get(p.part.callID) : undefined,
          }));
        }
      } catch (e) {}
    },

    "chat.message": async function (inp, out) {
      try {
        if (!inp || !inp.sessionID) return;
        ensureStarted(inp.sessionID);
        var text = ((out && out.parts) || [])
          .filter(function (part) { return part && part.type === "text" && !part.synthetic && typeof part.text === "string"; })
          .map(function (part) { return part.text; })
          .join("\n");
        enqueue(envelope("prompt", inp.sessionID, { prompt: text, model: inp.model && inp.model.modelID }));
      } catch (e) {}
    },

    "tool.execute.before": async function (inp, out) {
      var reply;
      try {
        if (!inp || !inp.sessionID) return;
        ensureStarted(inp.sessionID);
        starts.set(inp.callID, Date.now());
        reply = await enqueue(envelope("tool.before", inp.sessionID, { tool: inp.tool, call_id: inp.callID, args: out && out.args }), true);
      } catch (e) {
        return;
      }
      if (reply && reply.decision === "deny") {
        throw new Error(typeof reply.reason === "string" && reply.reason ? reply.reason : "Omnodex blocked this tool call.");
      }
    },

    "tool.execute.after": async function (inp, out) {
      try {
        if (!inp || !inp.sessionID || finished.has(inp.callID)) return;
        finished.add(inp.callID);
        enqueue(envelope("tool.after", inp.sessionID, {
          tool: inp.tool,
          call_id: inp.callID,
          args: inp.args,
          output: out && out.output,
          duration_ms: starts.has(inp.callID) ? Date.now() - starts.get(inp.callID) : undefined,
        }));
      } catch (e) {}
    },
  };
};
`;
