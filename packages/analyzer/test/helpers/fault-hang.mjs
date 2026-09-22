// Stands in for the evaluator module: it never finishes loading.
await new Promise(() => {});
export function createEvaluator() {
  throw new Error("unreachable");
}
