// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The contract every agent hook shim keeps, whatever the agent.
 *
 * Some agents punish a misbehaving hook: Copilot denies the tool call when a
 * hook exits non-zero or crashes, and Cursor blocks it when a permission
 * hook prints invalid JSON. A bug in Omnodex must never stop a user's agent,
 * so a shim runs its work through `runShim`, which:
 *
 *   - always resolves to exit code 0;
 *   - always prints one valid JSON document, the agent's decision when the
 *     work produced one and the "no decision" document otherwise;
 *   - turns a throw, a rejection, a timeout, `undefined`, a value that is
 *     not a JSON object, or a value that cannot be serialized into "no
 *     decision";
 *   - reports the failure to `onError` without letting `onError` fail.
 *
 * "No decision" is the document that makes the agent carry on as if no hook
 * had run. It is agent-specific (often `{}`), so each shim passes its own.
 */

export interface ShimContractOptions {
  /** The shim's work. Resolves to the agent's decision, or nothing for none. */
  run: () => Promise<unknown> | unknown;
  /** The document that means "no decision" for this agent. Defaults to `{}`. */
  noDecision?: Record<string, unknown>;
  /** Writes the shim's output. Defaults to process.stdout. */
  write?: (text: string) => void;
  /** Told about a failure so the shim can log it. Its own errors are ignored. */
  onError?: (err: unknown) => void;
  /** Give up on `run` after this long and answer "no decision". No limit by default. */
  timeoutMs?: number;
}

export interface ShimContractResult {
  /** Always 0. */
  exitCode: 0;
  /** The JSON text written to the agent. */
  output: string;
  /** True when the output is the "no decision" document because something went wrong. */
  failed: boolean;
}

const isJsonObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** The serialized decision, or null when the value is not a serializable JSON object. */
function serialize(value: unknown): string | null {
  if (!isJsonObject(value)) return null;
  try {
    const text = JSON.stringify(value);
    return typeof text === "string" ? text : null;
  } catch {
    return null;
  }
}

const TIMED_OUT = Symbol("shim-timeout");

/** Run a shim's work under the contract. Never rejects. */
export async function runShim(options: ShimContractOptions): Promise<ShimContractResult> {
  const noDecision = serialize(options.noDecision ?? {}) ?? "{}";
  const write = options.write ?? ((text: string) => void process.stdout.write(text));
  const report = (err: unknown): void => {
    try {
      options.onError?.(err);
    } catch {
      // a failing logger must not break the contract
    }
  };

  let output = noDecision;
  let failed = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const work = Promise.resolve().then(() => options.run());
    const result = options.timeoutMs && options.timeoutMs > 0
      ? await Promise.race([
          work,
          new Promise<typeof TIMED_OUT>((resolve) => {
            timer = setTimeout(() => resolve(TIMED_OUT), options.timeoutMs);
          }),
        ])
      : await work;
    if (result === TIMED_OUT) {
      failed = true;
      report(new Error(`shim work exceeded ${options.timeoutMs} ms`));
    } else if (result !== undefined && result !== null) {
      const text = serialize(result);
      if (text === null) {
        failed = true;
        report(new Error("shim work produced a value that is not a JSON object"));
      } else {
        output = text;
      }
    }
  } catch (err) {
    failed = true;
    report(err);
  } finally {
    if (timer) clearTimeout(timer);
  }

  try {
    write(output);
  } catch (err) {
    report(err);
  }
  return { exitCode: 0, output, failed };
}
