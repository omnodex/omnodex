/**
 * Made-up credentials for rule tests.
 *
 * Each is shaped like a live secret (the vendor prefix, letters mixed with
 * digits, a realistic length) so the credential rules must fire on it. They
 * are assembled from parts so the repository holds no complete key-shaped
 * literal for secret scanners to flag, and none is a real credential.
 */

const join = (...parts) => parts.join("");

export const FAKE = {
  aws: join("AKIA", "Z7Q3LXKD5N2PWM4R"),
  github: join("ghp_", "Zx9Lm2Qr7Tv4Wb8Nc1Hd5Kf3Jg6Ps0Ya2Ue4"),
  slack: join("xoxb-", "2048-5190-kQ7rT2vX9pL4"),
  stripeLive: join("sk_", "live_", "51Hq8vT2kP9xR4mW7nL3"),
  stripeTest: join("sk_", "test_", "51Hq8vT2kP9xR4mW7nL3"),
  jwt: join("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiI0MiJ9", ".", "Qm9keQ7xR2pL5vN8"),
  apiKey: "q8Zr4Lm2Vx7Tn1Pk",
  token: "Hj5Wq2Ez9Rb4Yc7N",
  // AI model providers, at each format's real length.
  anthropic: join("sk-ant-api03-", "XbWZOD9ZZaCcghp70lnNHwstphogGvTbUJntnM7kmBYmX2AbuQIdjHEPGOwfIGkViAKDBha7Bxtq8SwN3C9V5htXFJLtUAA"),
  anthropicAdmin: join("sk-ant-admin01-", "5lJ6PvCPgBVGasApJfiEon0OWQHPQoeGfWy-KEbQWijpqpatvpI09wgJ2Ecv63Ct49DRot3Pk6EXT3jtJ2RCoLptfXHKlAA"),
  openaiProject: join("sk-proj-", "nJ3HoRYHG5K5J7b3YhOBirbZzxhLD6TZrLvGRLhoBpUsZreIFnuC2QY8MRRVOrG4z6lrLAef2Y", "T3BlbkFJ", "rgkQuLWdIwkuz9CbyvqFUKjqZbPpj0MZKaIP8lhJX6fc99u8LDJQt7ywF8hgivvTlBL8F8PElW"),
  openaiLegacy: join("sk-", "n8w5qzjQSMMzrI12VDLV", "T3BlbkFJ", "nj9HweOX2Ef7eOeUBkbR"),
  openrouter: join("sk-or-v1-", "c5c3f3523980c711f4e880175f597ebee88f21a742a714501cfd89358d46ef25"),
  xai: join("xai-", "qGtMcnmHK5xcMBszFif1hgfEfeDvcKbc6r5utDVXF4rz6nm97iCxbHWL4SAi0GuQlIR3a8w6VC5EewlU"),
  groq: join("gsk_", "MKbrjHFn6uYCT22Q5DVB5Ugf9e7uC7lwk048hUYHE5AnG73rNijo"),
  perplexity: join("pplx-", "0yaHoAaTy4kRXs1LUbMyEXIND7bbK8UKiOspC6aYhLpyKrMn"),
  huggingface: join("hf_", "fLtyffpdIfRZNCrKqKGVFURlGiqfIBuxRg"),
  huggingfaceOrg: join("api_org_", "UhxorKWjgtlwAVbQHAdQUHsZyOyReiKqTd"),
  google: join("AIza", "2jmIcsEJZNBkihgyraHHqGb_f1CoAtm-cue"),
  // GitHub token forms beyond the classic personal access token.
  githubFineGrained: join("github_pat_", "pTC6rNV43UrxyMOuC5tU41EPNIvuJMGM7JQRn8A7le9KkK7MSlu2Ukbvwr_HHM2a04GHqb9fnwnT8_LMTj"),
  githubOauth: join("gho_", "upr2naOROd9itrQ8dlWosOcSNQAhBqAN9HV8"),
  githubApp: join("ghs_", "Vf9QMjgjp56Jn5tgV6uAFMtgWoMEGiq30XPT"),
  githubRefresh: join("ghr_", "PNB8wqwXtGItfSd0nTlXZ5zdvQG529F3iVEQ"),
};

/**
 * Vendor documentation keys: published examples that are never live. The
 * rules must ignore them, as they turn up in docs, tutorials and tests.
 */
export const DOCUMENTATION = {
  aws: join("AKIA", "IOSFODNN7", "EXAMPLE"),
  stripe: join("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc"),
  github: join("ghp_", "16C7e42F292c6912E7710c838347Ae178B4a"),
};
