import { test } from "node:test";
import assert from "node:assert/strict";
import { fitToolName, isShortenedToolName } from "../dist/index.js";

test("isShortenedToolName recognizes a name shortened under any limit", () => {
  const full = "filesystem__list_directory_with_sizes";
  for (const limit of [16, 24, 32, 36]) {
    const short = fitToolName("filesystem", "list_directory_with_sizes", limit);
    assert.ok(short.length <= limit);
    assert.equal(isShortenedToolName(short, full), true, `limit ${limit}`);
  }
});

test("isShortenedToolName rejects a name that fits or names another tool", () => {
  const full = "filesystem__read_text_file";
  assert.equal(isShortenedToolName(full, full), false, "an unshortened name is an exact match");
  const short = fitToolName("filesystem", "list_directory_with_sizes", 32);
  assert.equal(isShortenedToolName(short, "filesystem__list_directory_with_types"), false);
  assert.equal(isShortenedToolName("filesystem__list_dir_000000", "filesystem__list_directory"), false);
});
