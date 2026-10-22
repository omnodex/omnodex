// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * What a tool call does, worked out once per event.
 *
 * Conditions used to parse a call's parameters each in their own way: one
 * serialized everything and ran a regex, another pulled the command out of
 * a shell tool, a third looked for write targets. This module does that
 * parsing once and hands every condition the same answer:
 *
 *   kinds         read, write, exec, network
 *   paths         every file path the call names (read or write)
 *   writes        the files it writes to
 *   command       the command a shell tool runs, as given
 *   exec          the same command without heredoc bodies saved to files
 *   destinations  the hosts it reaches: from URLs, and from the arguments
 *                 of network programs (curl, wget, nc, ssh, scp, rsync,
 *                 git remotes, DNS lookups), each with an IP class
 *   outbound      whether the call reaches an external host over HTTP, the
 *                 outbound_call condition's answer
 *   staging       archive, encode, encrypt and clipboard steps, with their
 *                 output file where one can be read from the command
 *
 * Shell parsing is best effort. A program we do not know yields no
 * destination rather than a guess, and only what runs counts: a URL in
 * content written to a file is a string in a file, not a destination.
 *
 * The result is cached per event object, so a sequence rule re-reading a
 * window of earlier events does not parse them again.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { extractPaths } from "./conditions/path-match.js";
import { extractExecText, isWriteTool, stripFileHeredocs } from "./conditions/scope.js";
import { commandTargets, extractWriteTargets } from "./conditions/write-targets.js";

export type ActionKind = "read" | "write" | "exec" | "network";

export type IpClass = "loopback" | "private" | "link-local" | "metadata" | "public";

export interface Destination {
  /** Lowercased host name or IP literal, without brackets, user or port. */
  host: string;
  port?: number;
  /** URL scheme, when the destination came from a URL. */
  scheme?: string;
  /** 4 or 6 when the host is an IP literal. */
  ip?: 4 | 6;
  /** Set for IP literals, and for names that are known to be local or a metadata service. */
  ipClass?: IpClass;
  /** Where it was read from: a URL, a network program's arguments, or a DNS lookup. */
  source: "url" | "shell-arg" | "dns-query";
}

export type StagingOp = "archive" | "encode" | "encrypt" | "clipboard";

export interface StagingStep {
  op: StagingOp;
  program: string;
  /** The file the step writes, when the command names one. */
  output?: string;
}

export interface NormalizedAction {
  kinds: ReadonlySet<ActionKind>;
  paths: readonly string[];
  writes: readonly string[];
  command: string | null;
  exec: string | null;
  destinations: readonly Destination[];
  outbound: boolean;
  staging: readonly StagingStep[];
}

const cache = new WeakMap<ToolInvokedEvent, NormalizedAction>();

/** What a tool.invoked event does. Cached per event object. */
export function normalizeAction(event: ToolInvokedEvent): NormalizedAction {
  const hit = cache.get(event);
  if (hit) return hit;
  const action = computeAction(event);
  cache.set(event, action);
  return action;
}

function computeAction(event: ToolInvokedEvent): NormalizedAction {
  const command = extractExecText(event);
  const exec = command === null ? null : stripFileHeredocs(command);
  const writes = extractWriteTargets(event);
  const paths = extractPaths(event);

  const name = event.tool_name.toLowerCase();
  const fetchLike = name.includes("fetch") || name.includes("http") || name.includes("request");
  const writeTool = isWriteTool(event);

  // The text whose URLs count as places the call goes: the command a shell
  // runs, or a non-writing tool's parameters. A file being written is not a
  // call being made, unless the tool itself is a fetch.
  let urlText: string | null;
  if (exec !== null) urlText = exec;
  else if (writeTool && !fetchLike) urlText = null;
  else urlText = JSON.stringify(event.parameters ?? {});

  const destinations: Destination[] = [];
  const add = (d: Destination): void => {
    if (!destinations.some((x) => x.host === d.host && x.port === d.port && x.source === d.source)) {
      destinations.push(d);
    }
  };
  if (urlText !== null) {
    for (const d of urlDestinations(urlText)) add(d);
  }
  const httpHosts = urlText === null ? [] : legacyHttpHosts(urlText);
  if (exec !== null) {
    for (const d of shellDestinations(exec)) add(d);
  }

  const outbound = isOutbound({ writeTool, fetchLike, exec, httpHosts });
  const staging = exec === null ? [] : stagingSteps(exec);

  const kinds = new Set<ActionKind>();
  if (exec !== null) kinds.add("exec");
  if (writes.length > 0 || writeTool) kinds.add("write");
  if (paths.some((p) => !writes.includes(p))) kinds.add("read");
  if (outbound || destinations.some((d) => d.ipClass !== "loopback")) kinds.add("network");

  return { kinds, paths, writes, command, exec, destinations, outbound, staging };
}

// ---------------------------------------------------------------------------
// Outbound: unchanged semantics of the outbound_call condition
// ---------------------------------------------------------------------------

const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const LEGACY_URL_RE = /https?:\/\/([^/\s"'\\]+)/g;

/**
 * Hosts of http(s) URLs exactly as outbound_call has always read them,
 * including ones that do not parse as a host (a variable, a template). Kept
 * separate from destinations so the condition's answer does not change.
 */
function legacyHttpHosts(text: string): string[] {
  const hosts: string[] = [];
  LEGACY_URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = LEGACY_URL_RE.exec(text)) !== null) {
    hosts.push(m[1]?.toLowerCase().split(":")[0] ?? "");
  }
  return hosts;
}

function isOutbound(opts: {
  writeTool: boolean;
  fetchLike: boolean;
  exec: string | null;
  httpHosts: string[];
}): boolean {
  if (opts.writeTool && !opts.fetchLike) return false;
  // If URLs are present, they decide: outbound when one leaves the machine.
  if (opts.httpHosts.length > 0) return opts.httpHosts.some((h) => !LOCALHOST_HOSTS.has(h));
  if (opts.fetchLike) return true;
  return opts.exec !== null && /\b(curl|wget|httpie?)\b/.test(opts.exec);
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

const URL_RE = /\b(https?|wss?|ftps?|sftp|ssh|git|s3|gs):\/\/([^\s"'\\/?#<>()]+)/gi;

/**
 * Every destination named by a URL in the text, including a URL nested
 * percent-encoded inside another one's query, as redirect and proxy
 * parameters carry it (?url=https%3A%2F%2Fhost%2F).
 */
export function urlDestinations(text: string): Destination[] {
  const out: Destination[] = [];
  const scan = (t: string): void => {
    URL_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = URL_RE.exec(t)) !== null) {
      const scheme = m[1]!.toLowerCase();
      const parsed = parseAuthority(m[2]!);
      if (!parsed) continue;
      if (out.some((d) => d.host === parsed.host && d.port === parsed.port && d.scheme === scheme)) continue;
      out.push({ ...parsed, scheme, source: "url" });
    }
  };
  scan(text);
  if (/%3a%2f%2f/i.test(text)) scan(text.replace(/%3a/gi, ":").replace(/%2f/gi, "/").replace(/%5b/gi, "[").replace(/%5d/gi, "]"));
  return out;
}

/** host[:port], [v6][:port] or user@host[:port], to a destination without its source. */
function parseAuthority(authority: string): Omit<Destination, "source"> | null {
  const at = authority.lastIndexOf("@");
  let rest = at === -1 ? authority : authority.slice(at + 1);
  let port: number | undefined;
  let host: string;
  if (rest.startsWith("[")) {
    const close = rest.indexOf("]");
    if (close === -1) return null;
    host = rest.slice(1, close);
    const after = rest.slice(close + 1);
    if (after.startsWith(":") && /^\d+$/.test(after.slice(1))) port = Number(after.slice(1));
  } else if (/^[0-9a-f:.]+$/i.test(rest) && (rest.includes("::") || rest.split(":").length === 8)) {
    // An unbracketed IPv6 literal, as network programs take it: every colon
    // is part of the address, so none of it is a port. A full address has
    // eight groups and a shortened one has "::", which a time such as
    // 12:30:45 does not.
    host = rest;
  } else {
    const colon = rest.lastIndexOf(":");
    if (colon !== -1 && /^\d+$/.test(rest.slice(colon + 1))) {
      port = Number(rest.slice(colon + 1));
      rest = rest.slice(0, colon);
    } else if (colon !== -1 && rest.indexOf(":") === colon) {
      // host:path (scp style) or a stray colon: keep the host part.
      rest = rest.slice(0, colon);
    }
    host = rest;
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (!isHostLike(host)) return null;
  return withClass({ host, ...(port !== undefined ? { port } : {}) });
}

function isHostLike(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  if (ipVersion(host) !== undefined) return true;
  if (host === "localhost") return true;
  // A name with at least one dot, made of label characters. Excludes
  // template and variable references such as ${HOST} or $API.
  return /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$/.test(host);
}

// ---------------------------------------------------------------------------
// IP classes
// ---------------------------------------------------------------------------

const IPV4_LITERAL = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ipVersion(host: string): 4 | 6 | undefined {
  const m = IPV4_LITERAL.exec(host);
  if (m && m.slice(1).every((o) => Number(o) <= 255)) return 4;
  if (host.includes(":") && /^[0-9a-f:.]+$/.test(host)) return 6;
  return undefined;
}

const METADATA_NAMES = new Set(["metadata.google.internal", "metadata", "metadata.azure.com"]);

/** The class of an IP literal, or of a name known to be local or a metadata service. */
export function classifyHost(host: string): IpClass | undefined {
  const version = ipVersion(host);
  if (version === 4) {
    const [a, b, c, d] = host.split(".").map(Number) as [number, number, number, number];
    if (a === 169 && b === 254 && c === 169 && d === 254) return "metadata";
    if (a === 100 && b === 100 && c === 100 && d === 200) return "metadata";
    if (a === 127 || (a === 0 && b === 0 && c === 0 && d === 0)) return "loopback";
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
    if (a === 169 && b === 254) return "link-local";
    return "public";
  }
  if (version === 6) {
    if (host === "::1" || host === "::") return "loopback";
    if (host === "fd00:ec2::254") return "metadata";
    if (/^f[cd][0-9a-f]{2}:/.test(host)) return "private";
    if (/^fe[89ab][0-9a-f]:/.test(host)) return "link-local";
    return "public";
  }
  if (host === "localhost" || host.endsWith(".localhost")) return "loopback";
  if (METADATA_NAMES.has(host)) return "metadata";
  return undefined;
}

function withClass(d: Omit<Destination, "source">): Omit<Destination, "source"> {
  const ip = ipVersion(d.host);
  const ipClass = classifyHost(d.host);
  return { ...d, ...(ip ? { ip } : {}), ...(ipClass ? { ipClass } : {}) };
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

/** Words of a shell segment, with quotes removed. Best effort, no expansion. */
export function shellWords(segment: string): string[] {
  const words: string[] = [];
  const re = /'([^']*)'|"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(segment)) !== null) words.push(m[1] ?? m[2] ?? m[3] ?? "");
  return words;
}

/** Command segments: split on ;, &&, ||, | and newlines, outside quotes. */
export function shellSegments(command: string): string[] {
  const out: string[] = [];
  let current = "";
  let quote: string | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    if (quote) {
      current += ch;
      if (ch === quote && command[i - 1] !== "\\") quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === ";" || ch === "\n" || ch === "|" || (ch === "&" && command[i + 1] === "&")) {
      if (current.trim()) out.push(current.trim());
      current = "";
      if ((ch === "|" || ch === "&") && command[i + 1] === ch) i++;
      continue;
    }
    current += ch;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

/** The program a segment runs and its arguments, past sudo, env assignments and wrappers. */
function programOf(segment: string): { program: string; args: string[] } | null {
  const words = shellWords(segment);
  while (words.length > 0) {
    const w = words[0]!;
    if (w === "sudo" || w === "command" || w === "exec" || w === "nohup" || w === "time") words.shift();
    else if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) words.shift();
    else break;
  }
  const first = words.shift();
  if (!first) return null;
  const program = first.replace(/^.*[/\\]/, "").replace(/\.exe$/i, "").toLowerCase();
  return { program, args: words };
}

/** Flags that take the next word as their value, per program. */
const VALUE_FLAGS: Record<string, ReadonlySet<string>> = {
  curl: new Set([
    "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json",
    "-F", "--form", "-o", "--output", "-X", "--request", "-u", "--user", "-A", "--user-agent",
    "-e", "--referer", "-T", "--upload-file", "-w", "--write-out", "-b", "--cookie", "-c",
    "--cookie-jar", "--resolve", "--connect-to", "-m", "--max-time", "--retry", "-K", "--config",
    "--cacert", "--cert", "--key", "-x", "--proxy", "--oauth2-bearer",
  ]),
  wget: new Set(["-O", "--output-document", "-o", "--output-file", "--header", "--post-data", "--post-file", "-U", "--user-agent", "-P", "--directory-prefix", "-e", "--execute", "--user", "--password", "-T", "--timeout", "-t", "--tries"]),
  ssh: new Set(["-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-c", "-m", "-b", "-E", "-S", "-W", "-w", "-Q", "-O", "-B", "-e", "-I"]),
  nc: new Set(["-p", "-s", "-w", "-i", "-x", "-X", "-q", "-e", "-c", "-I", "-O", "-T", "-V"]),
};
VALUE_FLAGS.ncat = VALUE_FLAGS.nc!;
VALUE_FLAGS.netcat = VALUE_FLAGS.nc!;
VALUE_FLAGS.telnet = new Set(["-l", "-n", "-b", "-e"]);

/** The non-flag arguments of a program, skipping the values of flags that take one. */
function positionals(program: string, args: string[]): string[] {
  const valueFlags = VALUE_FLAGS[program] ?? new Set<string>();
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") {
      out.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("-")) {
      if (valueFlags.has(a)) i++;
      continue;
    }
    if (/^\d?[<>]/.test(a)) {
      // A redirection: skip it and, when it stands alone, its target.
      if (/^\d?[<>]{1,2}$/.test(a)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

/**
 * File extensions that make a bare word a file name, not a host. Only used
 * for scheme-less arguments; a URL is always a destination. (".sh" is also a
 * TLD, so a scheme-less "transfer.sh" is missed; its URL form is not.)
 */
const FILE_EXTENSIONS = /\.(?:json|txt|md|sh|py|js|mjs|cjs|ts|tsx|yaml|yml|toml|csv|log|tar|gz|tgz|zip|html?|xml|lock|env|cfg|conf|ini|pem|key|crt|png|jpe?g|gif|svg|pdf)$/i;

function hostArg(word: string, source: Destination["source"]): Destination | null {
  if (word.includes("://")) return null; // URLs are read separately
  const bare = word.replace(/\/.*$/, "");
  if (FILE_EXTENSIONS.test(bare)) return null;
  const parsed = parseAuthority(bare);
  return parsed ? { ...parsed, source } : null;
}

const HTTP_CLIENTS = new Set(["curl", "wget", "http", "https", "xh", "httpie"]);
const RAW_SOCKETS = new Set(["nc", "ncat", "netcat", "telnet", "socat"]);
const DNS_TOOLS = new Set(["dig", "nslookup", "host", "drill", "resolvectl"]);

/** Destinations named by the arguments of network programs in a command. */
export function shellDestinations(command: string): Destination[] {
  const out: Destination[] = [];
  for (const segment of shellSegments(command)) {
    const run = programOf(segment);
    if (!run) continue;
    const { program, args } = run;
    const pos = positionals(program, args);

    if (HTTP_CLIENTS.has(program)) {
      for (const p of pos) {
        // httpie takes a method first, and request items (key=value, Header:value) after the URL.
        if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/i.test(p) || /[=:]/.test(p.replace(/^[^/]*:\d+/, ""))) continue;
        const d = hostArg(p, "shell-arg");
        if (d) out.push(d);
      }
    } else if (RAW_SOCKETS.has(program)) {
      const target = program === "socat" ? pos.map((p) => /^(?:tcp|udp|openssl)[46]?:([^:,]+)/i.exec(p)?.[1]).find(Boolean) : pos[0];
      if (target) {
        const d = hostArg(target, "shell-arg");
        if (d) out.push(d);
      }
    } else if (program === "ssh" || program === "mosh") {
      const target = pos[0];
      if (target) {
        const d = hostArg(target, "shell-arg");
        if (d) out.push(d);
      }
      const jump = args.indexOf("-J");
      if (jump !== -1 && args[jump + 1]) {
        for (const hop of args[jump + 1]!.split(",")) {
          const d = hostArg(hop, "shell-arg");
          if (d) out.push(d);
        }
      }
    } else if (program === "scp" || program === "rsync" || program === "sftp" || program === "git") {
      // Remote paths look like [user@]host:path. git also takes them as remotes.
      for (const p of pos) {
        const m = /^(?:[^@\s/]+@)?(\[[0-9a-f:]+\]|[a-z0-9_.-]+):(?!\/\/)/i.exec(p);
        if (m && !/^[a-z]$/i.test(m[1]!)) {
          const d = hostArg(m[1]!, "shell-arg");
          if (d) out.push(d);
        } else if (program === "sftp") {
          const d = hostArg(p, "shell-arg");
          if (d) out.push(d);
        }
      }
    } else if (DNS_TOOLS.has(program)) {
      for (const p of pos) {
        if (p.startsWith("@") || /^(A|AAAA|TXT|MX|NS|CNAME|ANY|SOA|PTR|SRV)$/i.test(p)) continue;
        const d = hostArg(p, "dns-query");
        if (d) {
          out.push(d);
          break;
        }
      }
    } else if (program === "ping" || program === "ping6" || program === "traceroute" || program === "tracert") {
      const target = pos[pos.length - 1];
      const d = target ? hostArg(target, "shell-arg") : null;
      if (d) out.push(d);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------

const CLIPBOARD = new Set(["pbcopy", "xclip", "xsel", "wl-copy", "clip", "set-clipboard"]);
const COMPRESSORS = new Set(["gzip", "bzip2", "xz", "zstd", "lz4", "compress"]);

/** Archive, encode, encrypt and clipboard steps in a command. */
export function stagingSteps(command: string): StagingStep[] {
  const out: StagingStep[] = [];
  for (const segment of shellSegments(command)) {
    const run = programOf(segment);
    if (!run) continue;
    const { program, args } = run;
    const redirect = commandTargets(segment)[0];
    const step = (op: StagingOp, output?: string): void => {
      const file = output ?? redirect;
      out.push({ op, program, ...(file ? { output: file } : {}) });
    };

    if (program === "tar") {
      // Short options are bundled ("-czf", or "czf" as the first word).
      const bundles = args.filter((a, i) => /^-[A-Za-z]+$/.test(a) || (i === 0 && /^[A-Za-z]{1,8}$/.test(a)));
      const create = args.includes("--create") || bundles.some((b) => b.includes("c"));
      if (!create) continue;
      let file: string | undefined;
      for (let i = 0; i < args.length; i++) {
        const a = args[i]!;
        if (a === "--file") file = args[i + 1];
        else if (a.startsWith("--file=")) file = a.slice(7);
        else if (bundles.includes(a) && a.endsWith("f")) file = args[i + 1];
      }
      step("archive", file && file !== "-" ? file : undefined);
    } else if (program === "zip" || program === "7z" || program === "7za" || program === "rar") {
      const pos = positionals(program, args).filter((a) => !(program !== "zip" && a === "a"));
      if (program !== "zip" && !args.includes("a")) continue;
      step("archive", pos[0]);
    } else if (COMPRESSORS.has(program)) {
      if (args.some((a) => a === "-d" || a === "--decompress")) continue;
      step("archive");
    } else if (program === "base64" || program === "base32" || program === "xxd" || program === "uuencode") {
      if (args.some((a) => a === "-d" || a === "--decode" || a === "-D" || (program === "xxd" && a === "-r"))) continue;
      step("encode");
    } else if (program === "openssl") {
      const sub = args[0];
      if (sub === "base64") {
        if (!args.includes("-d")) step("encode");
      } else if (sub === "enc") {
        if (!args.includes("-d")) {
          const o = args.indexOf("-out");
          step(args.includes("-base64") || args.includes("-a") ? "encode" : "encrypt", o !== -1 ? args[o + 1] : undefined);
        }
      }
    } else if (program === "gpg" || program === "gpg2") {
      if (args.some((a) => ["-c", "--symmetric", "-e", "--encrypt", "-se", "-es"].includes(a))) {
        const o = args.findIndex((a) => a === "-o" || a === "--output");
        step("encrypt", o !== -1 ? args[o + 1] : undefined);
      }
    } else if (program === "age") {
      if (!args.some((a) => a === "-d" || a === "--decrypt")) {
        const o = args.findIndex((a) => a === "-o" || a === "--output");
        step("encrypt", o !== -1 ? args[o + 1] : undefined);
      }
    } else if (CLIPBOARD.has(program)) {
      if (program === "xclip" && args.includes("-o")) continue;
      if (program === "xsel" && (args.includes("-o") || args.includes("--output"))) continue;
      step("clipboard");
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Credential role
// ---------------------------------------------------------------------------

export type CredentialRole = "auth-header" | "body" | "url" | "env" | "argument" | "content";

const HEADER_FLAGS = new Set(["-H", "--header", "-u", "--user", "--oauth2-bearer", "-b", "--cookie"]);
const BODY_FLAGS = new Set(["-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "-F", "--form", "--post-data", "-T", "--upload-file"]);

/**
 * How a credential value is used in a call: sent as authentication, in a
 * request body or a URL, set in the environment, passed as an argument, or
 * written as file content. Undefined when the value is not in the call.
 *
 * Authentication to the credential's own service is routine. The same value
 * in a request body to an unrelated host is how data leaves, so rules about
 * movement need to tell the two apart.
 */
export function credentialRole(event: ToolInvokedEvent, value: string): CredentialRole | undefined {
  if (!value) return undefined;
  const action = normalizeAction(event);
  if (action.command !== null) {
    if (!action.command.includes(value)) return undefined;
    for (const segment of shellSegments(action.command)) {
      if (!segment.includes(value)) continue;
      const words = shellWords(segment);
      const i = words.findIndex((w) => w.includes(value));
      if (i === -1) continue;
      const word = words[i]!;
      const flag = words[i - 1];
      const inline = /^(--?[A-Za-z][\w-]*)=/.exec(word)?.[1];
      if ((flag && HEADER_FLAGS.has(flag)) || (inline && HEADER_FLAGS.has(inline))) return "auth-header";
      if ((flag && BODY_FLAGS.has(flag)) || (inline && BODY_FLAGS.has(inline))) return "body";
      if (/:\/\//.test(word) && word.indexOf(value) > word.indexOf("://")) return "url";
      if (/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=/.test(word) && words.slice(0, i).every((w) => w === "export" || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w))) return "env";
      return "argument";
    }
    return "argument";
  }
  const key = keyPathOf(event.parameters ?? {}, value);
  if (key === undefined) return undefined;
  const k = key.toLowerCase();
  if (isWriteTool(event) && /(?:^|\.)(?:content|new_string|new_source|text|edits|command|input|patch)(?:\.|$)/.test(k)) return "content";
  if (/(?:^|\.)(?:headers?|authorization|auth|cookie|x-api-key|api[_-]?key|token|bearer)(?:\.|$)/.test(k)) return "auth-header";
  if (/(?:^|\.)(?:url|uri|endpoint|href|link)(?:\.|$)/.test(k)) return "url";
  if (/(?:^|\.)(?:body|data|json|payload|content|text|message|form)(?:\.|$)/.test(k)) return "body";
  return "argument";
}

/** The dotted key path of the first string field containing the value. */
function keyPathOf(value: unknown, needle: string, prefix = ""): string | undefined {
  if (typeof value === "string") return value.includes(needle) ? prefix : undefined;
  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = keyPathOf(item, needle, prefix);
      if (hit !== undefined) return hit;
    }
    return undefined;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const hit = keyPathOf(v, needle, prefix ? `${prefix}.${k}` : k);
      if (hit !== undefined) return hit;
    }
  }
  return undefined;
}

/**
 * The services a credential type authenticates to, by host suffix. A
 * credential sent to one of these as authentication is that service being
 * used, not the credential leaving.
 */
export const CREDENTIAL_PROVIDERS: Readonly<Record<string, readonly string[]>> = {
  "github-pat": ["github.com", "githubusercontent.com", "ghcr.io"],
  "github-oauth": ["github.com", "githubusercontent.com", "ghcr.io"],
  "github-app": ["github.com", "githubusercontent.com", "ghcr.io"],
  "github-refresh": ["github.com"],
  "aws-key": ["amazonaws.com", "aws.amazon.com"],
  "anthropic": ["anthropic.com"],
  "anthropic-admin": ["anthropic.com"],
  "openai": ["openai.com"],
  "openrouter": ["openrouter.ai"],
  "xai": ["x.ai"],
  "groq": ["groq.com"],
  "perplexity": ["perplexity.ai"],
  "huggingface": ["huggingface.co", "hf.co"],
  "google-api-key": ["googleapis.com"],
  "slack-bot": ["slack.com"],
  "stripe-live": ["stripe.com"],
  "stripe-test": ["stripe.com"],
};

/** True when the host belongs to a service the credential type authenticates to. */
export function isCredentialProvider(credentialType: string, host: string): boolean {
  const suffixes = CREDENTIAL_PROVIDERS[credentialType];
  if (!suffixes) return false;
  const h = host.toLowerCase();
  return suffixes.some((s) => h === s || h.endsWith(`.${s}`));
}
