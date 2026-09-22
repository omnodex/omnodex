// Test-only module hooks for the hook shims' capture evaluation.
//
// Load with `node --import <this file> <shim>`. Environment switches:
//
//   OMNODEX_TEST_CAPTURE=throw   the evaluator throws when created
//   OMNODEX_TEST_CAPTURE=hang    the evaluator module never finishes loading
//   OMNODEX_TEST_PUSH_LOG=<file> pushEventsToCloud appends what it was given
//                                to <file>, one JSON event per line, instead
//                                of pushing

import { register } from "node:module";

register("./capture-hooks-impl.mjs", import.meta.url);
