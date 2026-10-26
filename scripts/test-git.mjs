// Keep Git discovery inside a test's scratch tree, even when TEMP is
// inside a developer's checkout. Fixture repositories below it still work.
import { dirname, resolve } from "node:path";

export function gitTestEnv(scratchRoot, env = process.env) {
  return { ...env, GIT_CEILING_DIRECTORIES: dirname(resolve(scratchRoot)) };
}
