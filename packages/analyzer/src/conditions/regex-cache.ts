// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Compiled-pattern cache shared by the condition evaluators.
 *
 * Rule patterns are strings in declarative rule definitions. Compiling them
 * on every evaluation cost a RegExp construction per pattern per event; this
 * compiles each (source, flags) pair once per process. Global regexes carry
 * lastIndex state, so callers get the expression with lastIndex reset.
 */

const cache = new Map<string, RegExp>();

/** The compiled expression for a pattern, reset and ready to use. */
export function compiled(source: string, flags = ""): RegExp {
  const key = `${flags}/${source}`;
  let re = cache.get(key);
  if (!re) {
    re = new RegExp(source, flags);
    cache.set(key, re);
  }
  re.lastIndex = 0;
  return re;
}
