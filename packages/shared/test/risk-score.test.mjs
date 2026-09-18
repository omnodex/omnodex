import { test } from "node:test";
import * as assert from "node:assert/strict";
import {
  RISK_SEVERITY_WEIGHT,
  RISK_BAND_THRESHOLD,
  riskScoreFor,
  riskBandFor,
  roundRiskScore,
} from "../dist/index.js";

/**
 * The weights are the single source of truth for turning a severity into a
 * number. Four scales had grown up independently before this, so the same
 * session scored differently depending on which path its data took.
 *
 * The hosted dashboard mirrors these values by hand across a repo boundary
 * (dashboard/hosted/src/riskScore.ts in omnodex-cloud). If these numbers
 * change, that file changes with them.
 */

test("the weights are the scale everything else is derived from", () => {
  assert.deepEqual(RISK_SEVERITY_WEIGHT, {
    LOW: 0.1,
    MEDIUM: 0.4,
    HIGH: 0.7,
    CRITICAL: 1.0,
  });
});

test("severities score in ascending order", () => {
  const { LOW, MEDIUM, HIGH, CRITICAL } = RISK_SEVERITY_WEIGHT;
  assert.ok(LOW < MEDIUM && MEDIUM < HIGH && HIGH < CRITICAL);
});

test("an unknown severity contributes nothing", () => {
  assert.equal(riskScoreFor("NOPE"), 0);
  assert.equal(riskScoreFor(""), 0);
});

test("one finding lands in its own band", () => {
  // The property the thresholds exist to hold: a session with a single
  // finding reads as that finding's severity, not as something milder.
  for (const severity of ["LOW", "MEDIUM", "HIGH", "CRITICAL"]) {
    assert.equal(
      riskBandFor(riskScoreFor(severity)),
      severity,
      `a lone ${severity} finding should band as ${severity}`,
    );
  }
});

test("no findings is not a band", () => {
  assert.equal(riskBandFor(0), null);
});

test("findings accumulate into higher bands", () => {
  const { LOW, MEDIUM } = RISK_SEVERITY_WEIGHT;
  assert.equal(riskBandFor(LOW * 4), "MEDIUM", "four lows reach medium");
  assert.equal(riskBandFor(MEDIUM * 3), "CRITICAL", "three mediums reach critical");
});

test("the scale stays small as findings pile up", () => {
  // The reason for choosing tenths: a busy session should still show a score
  // a person can read, not four digits.
  const busy = RISK_SEVERITY_WEIGHT.CRITICAL * 20 + RISK_SEVERITY_WEIGHT.LOW * 100;
  assert.ok(busy < 100, `expected a two-digit score, got ${busy}`);
});

test("accumulated scores are rounded away from binary drift", () => {
  // Three LOW findings sum to 0.30000000000000004 in binary floating point,
  // which has no business reaching a dashboard.
  const { LOW } = RISK_SEVERITY_WEIGHT;
  const raw = LOW + LOW + LOW;
  assert.notEqual(raw, 0.3, "precondition: the drift is real");
  assert.equal(roundRiskScore(raw), 0.3);
});

test("band thresholds match the weights they describe", () => {
  assert.equal(RISK_BAND_THRESHOLD.CRITICAL, RISK_SEVERITY_WEIGHT.CRITICAL);
  assert.equal(RISK_BAND_THRESHOLD.HIGH, RISK_SEVERITY_WEIGHT.HIGH);
  assert.equal(RISK_BAND_THRESHOLD.MEDIUM, RISK_SEVERITY_WEIGHT.MEDIUM);
  assert.equal(RISK_BAND_THRESHOLD.LOW, 0);
});
