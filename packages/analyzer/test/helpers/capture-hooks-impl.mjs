// Resolve hooks registered by capture-hooks.mjs. Runs on the loader thread.

const here = new URL("./", import.meta.url);

export async function resolve(specifier, context, next) {
  const parent = context.parentURL ?? "";
  const mode = process.env.OMNODEX_TEST_CAPTURE;
  if (mode && specifier === "./evaluator.js" && parent.endsWith("/analyzer/dist/capture.js")) {
    return { url: new URL(`fault-${mode}.mjs`, here).href, shortCircuit: true };
  }
  if (
    process.env.OMNODEX_TEST_PUSH_LOG &&
    specifier === "@omnodex/sync-encryptor" &&
    !parent.endsWith("/push-recorder.mjs")
  ) {
    return { url: new URL("push-recorder.mjs", here).href, shortCircuit: true };
  }
  return next(specifier, context);
}
