// conventional.mjs
//
// The commit subject convention for this repository, shared by the PR
// title check (check-pr-title.mjs) and the release notes (release.mjs).
//
//   type(scope): summary      scope is optional
//   type(scope)!: summary     ! marks a breaking change
//
// PRs are squash-merged with the PR title as the commit subject, so the
// title is what lands on main and what the release notes are built from.

/** Allowed types, and the release-notes section each one lands in (null: left out). */
export const TYPES = {
  feat: "Features",
  fix: "Fixes",
  perf: "Performance",
  refactor: "Other changes",
  revert: "Other changes",
  docs: null,
  test: null,
  build: null,
  ci: null,
  chore: null,
};

export const MAX_TITLE_LENGTH = 100;

const SUBJECT = /^(?<type>[a-z]+)(?:\((?<scope>[a-z0-9][a-z0-9-]*)\))?(?<breaking>!)?: (?<summary>\S.*)$/;
const PR_SUFFIX = / \(#\d+\)$/;
const WORK_ITEM = /\b(?:ENG|BUG|VAL|PRD|BUS)-\d+\b|\bFS-\d{3}\b/;

/** Parses a subject line; null when it does not follow the convention. */
export function parseSubject(subject) {
  const m = SUBJECT.exec(String(subject).trim());
  if (!m || !(m.groups.type in TYPES)) return null;
  const { type, scope, breaking, summary } = m.groups;
  return { type, scope: scope ?? null, breaking: Boolean(breaking), summary };
}

/** Problems with a PR title; empty when it is fine to merge. */
export function checkTitle(title) {
  const text = String(title ?? "").trim();
  const problems = [];
  if (!parseSubject(text)) {
    problems.push(
      `does not match "type(scope): summary", with type one of ${Object.keys(TYPES).join(", ")} ` +
        `and an optional lowercase scope (for example "fix(dashboard): keep the session list sorted")`,
    );
  }
  const length = text.replace(PR_SUFFIX, "").length;
  if (length > MAX_TITLE_LENGTH) problems.push(`is ${length} characters; keep it to ${MAX_TITLE_LENGTH}`);
  const ref = WORK_ITEM.exec(text);
  if (ref) problems.push(`contains the internal reference "${ref[0]}"; describe the change instead`);
  return problems;
}

/**
 * Markdown release notes from commit subjects, newest first, grouped by
 * type. Subjects that do not follow the convention (older history) are
 * listed under "Other changes" as written.
 */
export function releaseNotes(subjects) {
  const order = ["Features", "Fixes", "Performance", "Other changes"];
  const sections = new Map(order.map((name) => [name, []]));
  for (const subject of subjects) {
    const line = String(subject).trim();
    if (!line) continue;
    const parsed = parseSubject(line);
    if (!parsed) {
      sections.get("Other changes").push(line);
      continue;
    }
    const section = TYPES[parsed.type];
    if (!section) continue;
    const scope = parsed.scope ? `**${parsed.scope}:** ` : "";
    const breaking = parsed.breaking ? "**Breaking:** " : "";
    sections.get(section).push(`${breaking}${scope}${parsed.summary}`);
  }
  const parts = [];
  for (const [name, lines] of sections) {
    if (lines.length === 0) continue;
    parts.push(`## ${name}\n\n${lines.map((l) => `- ${l}`).join("\n")}`);
  }
  return parts.length > 0 ? parts.join("\n\n") + "\n" : "Maintenance release; no user-facing changes.\n";
}
