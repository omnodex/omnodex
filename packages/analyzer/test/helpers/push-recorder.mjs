// Stands in for @omnodex/sync-encryptor: everything is the real module
// except pushEventsToCloud, which records what it was given.
import { appendFileSync } from "node:fs";

export * from "@omnodex/sync-encryptor";

export async function pushEventsToCloud(events) {
  const lines = events.map((e) => JSON.stringify(e)).join("\n");
  appendFileSync(process.env.OMNODEX_TEST_PUSH_LOG, `${lines}\n`);
  return true;
}
