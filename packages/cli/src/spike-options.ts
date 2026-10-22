// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { randomInt } from "node:crypto";
import { buildHistoryScenarios, buildScenarios, HISTORY_MACHINES, MOVEMENT_SCENARIOS, type HistoryMachine, type ScenarioOptions } from "@omnodex/hooks-provider";

/** Scenario options, or, with `history`, which machine of the history set to build. */
export type SpikeOptions = ScenarioOptions & { history?: HistoryMachine };

export function parseSpikeOptions(args: readonly string[], freshSeed = () => randomInt(0, 0x100000000)): SpikeOptions {
  const options: SpikeOptions = {};
  let history = false;
  const seen = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("-")) {
      if (!["--seed", "--random", "--now", "--sessions", "--scenario-set", "--machine"].includes(arg)) throw new Error(`unknown spike option: ${arg}`);
      if (seen.has(arg)) throw new Error(`duplicate spike option: ${arg}`);
      seen.add(arg);
      if (arg === "--random") continue;
      const value = args[++i];
      if (value === undefined || value.startsWith("--")) throw new Error(`${arg} requires a value`);
      if (arg === "--scenario-set") {
        if (value === "movement") options.additionalScenarios = MOVEMENT_SCENARIOS;
        else if (value === "history") history = true;
        else throw new Error("--scenario-set supports movement and history");
      } else if (arg === "--machine") {
        if (!(HISTORY_MACHINES as readonly string[]).includes(value)) throw new Error(`--machine must be one of ${HISTORY_MACHINES.join(", ")}`);
        options.history = value as HistoryMachine;
      } else if (arg === "--now") options.now = value;
      else {
        if (!/^-?\d+$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error(`${arg} requires a safe integer`);
        if (arg === "--seed") options.seed = Number(value);
        else options.sessions = Number(value);
      }
    } else {
      if (options.name !== undefined) throw new Error("spike accepts only one name");
      options.name = arg;
    }
  }
  if (seen.has("--random") && seen.has("--seed")) throw new Error("--random and --seed cannot be combined");
  if (seen.has("--random")) options.seed = freshSeed();
  // The history set is one machine at a time, each into its own home, and
  // its session count is fixed.
  if (history && !options.history) throw new Error("--scenario-set history requires --machine");
  if (!history && options.history) throw new Error("--machine applies to --scenario-set history");
  if (history && seen.has("--sessions")) throw new Error("--sessions does not apply to --scenario-set history");
  // Validate before the command opens or writes any data.
  if (options.history) buildHistoryScenarios({ ...options, machine: options.history });
  else buildScenarios(options);
  return options;
}
