#!/usr/bin/env node
/**
 * Mock enrichment API server for the Omnodex demo.
 *
 * Listens on localhost:3456 and returns fake enrichment data for any
 * customer email. Accepts a Bearer token in the Authorization header
 * (does not validate it, but the token appears in the hook payload,
 * which is the point: Omnodex should detect it).
 *
 * Usage:
 *   node demo/api-server.js
 *   # => Enrichment API listening on http://localhost:3456
 *
 * Endpoints:
 *   GET /v1/customer/:email   returns enrichment data for the email
 *   GET /health               returns 200 OK
 */

const http = require("node:http");

const PORT = parseInt(process.env.PORT ?? "3456", 10);

/** Fake enrichment data keyed by email prefix. */
function enrichCustomer(email) {
  const domain = email.split("@")[1] ?? "unknown.com";
  const now = new Date().toISOString();
  return {
    email,
    enriched_at: now,
    company_domain: domain,
    company_size: Math.floor(Math.random() * 5000) + 50,
    industry: pickRandom([
      "Technology",
      "Financial Services",
      "Healthcare",
      "Manufacturing",
      "Retail",
    ]),
    annual_revenue_usd: Math.floor(Math.random() * 50_000_000) + 1_000_000,
    headquarters: pickRandom([
      "San Francisco, CA",
      "New York, NY",
      "London, UK",
      "Tokyo, JP",
      "Berlin, DE",
    ]),
    linkedin_employees: Math.floor(Math.random() * 3000) + 20,
    risk_score: Math.floor(Math.random() * 100),
    data_sources: ["clearbit", "zoominfo", "linkedin"],
  };
}

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

const server = http.createServer((req, res) => {
  // Simple router.
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  const match = req.url?.match(/^\/v1\/customer\/([^/?]+)/);
  if (match) {
    const email = decodeURIComponent(match[1]);
    const auth = req.headers.authorization ?? "(none)";
    console.log(`[enrich] ${email}  auth=${auth.slice(0, 30)}...`);

    const data = enrichCustomer(email);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data, null, 2));
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Enrichment API listening on http://localhost:${PORT}`);
  console.log("Endpoints:");
  console.log("  GET /v1/customer/:email");
  console.log("  GET /health");
  console.log("Press Ctrl+C to stop.\n");
});
