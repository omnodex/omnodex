import { setTimeout as delay } from "node:timers/promises";

/** Wait for observable progress; a slow runner fails with a bounded error. */
export async function waitFor(predicate, timeoutMs = 10000, label = "test condition") {
  const deadline = Date.now() + timeoutMs;
  do {
    if (await predicate()) return;
    await delay(20);
  } while (Date.now() < deadline);
  throw new Error(`timed out waiting for ${label}`);
}
