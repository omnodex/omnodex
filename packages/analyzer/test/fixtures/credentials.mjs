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
