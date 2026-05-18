"use strict";

const test = require("node:test");
const assert = require("node:assert");
const helpers = require("./helpers");

helpers.install();
const ContrastAPI = require("..");

function newClient() {
  return ContrastAPI({});
}

test.beforeEach(() => helpers.reset());

// --- Constructor / transport guards ---

test("constructor rejects http base URL by default", () => {
  assert.throws(() => ContrastAPI({ baseUrl: "http://localhost:8000" }), /HTTPS/);
});

test("constructor allows http base URL with allowInsecure flag", () => {
  const c = ContrastAPI({ baseUrl: "http://localhost:8000", allowInsecure: true });
  assert.equal(typeof c.cve.lookup, "function");
});

test("default base URL is https://api.contrastcyber.com", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/status", {
    body: { status: "ok", version: "1.4.0" },
  });
  const c = newClient();
  const r = await c.status();
  assert.equal(r.status, "ok");
});

// --- CVE namespace ---

test("cve.lookup hits /v1/cve/{id}", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/cve/CVE-2021-44228", {
    body: { cve_id: "CVE-2021-44228", cwe_id: "CWE-502" },
  });
  const c = newClient();
  const r = await c.cve.lookup("CVE-2021-44228");
  assert.equal(r.cve_id, "CVE-2021-44228");
  assert.equal(r.cwe_id, "CWE-502");
});

test("cve.search builds query string", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/cves?product=apache&severity=critical", {
    body: { results: [], total: 0 },
  });
  const c = newClient();
  await c.cve.search({ product: "apache", severity: "critical" });
  const last = helpers.calls()[0];
  assert.match(last.path, /product=apache/);
  assert.match(last.path, /severity=critical/);
});

test("cve.bulk POSTs cve_ids body", async () => {
  helpers.mock("POST", "https://api.contrastcyber.com/v1/cves/bulk", {
    body: { successful: 2, results: [] },
  });
  const c = newClient();
  await c.cve.bulk(["CVE-2021-44228", "CVE-2024-3094"]);
  const last = helpers.calls()[0];
  const body = JSON.parse(last.body);
  assert.deepEqual(body.cve_ids, ["CVE-2021-44228", "CVE-2024-3094"]);
});

test("cve.bulk rejects non-array input", () => {
  const c = newClient();
  assert.throws(() => c.cve.bulk("CVE-2021-44228"), /array of strings/);
});

// --- v1.29.1: composite risk score + CVSS v3.x parser ---

test("cve.riskScore hits /v1/cve/{id}/risk_score", async () => {
  helpers.mock(
    "GET",
    "https://api.contrastcyber.com/v1/cve/CVE-2021-44228/risk_score",
    { body: { cve_id: "CVE-2021-44228", score: 100, label: "CRITICAL" } }
  );
  const c = newClient();
  const r = await c.cve.riskScore("CVE-2021-44228");
  assert.equal(r.score, 100);
  assert.equal(r.label, "CRITICAL");
});

test("cve.cvssDetails percent-encodes vector and parses response", async () => {
  const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
  helpers.mock(
    "GET",
    `https://api.contrastcyber.com/v1/cvss/details?vector=${encodeURIComponent(vector)}`,
    { body: { version: "3.1", base_score: 9.8, base_severity: "CRITICAL" } }
  );
  const c = newClient();
  const r = await c.cve.cvssDetails(vector);
  assert.equal(r.version, "3.1");
  assert.equal(r.base_score, 9.8);
});

test("cve.cvssDetails rejects empty vector", () => {
  const c = newClient();
  assert.throws(() => c.cve.cvssDetails(""), /non-empty CVSS/);
});

// --- ATLAS namespace + new bulkTechniqueLookup ---

test("atlas.bulkTechniqueLookup hits /v1/atlas/techniques/bulk", async () => {
  helpers.mock("POST", "https://api.contrastcyber.com/v1/atlas/techniques/bulk", {
    body: { successful: 2, results: [] },
  });
  const c = newClient();
  await c.atlas.bulkTechniqueLookup(["AML.T0051", "AML.T0043"]);
  const last = helpers.calls()[0];
  const body = JSON.parse(last.body);
  assert.deepEqual(body.technique_ids, ["AML.T0051", "AML.T0043"]);
});

test("atlas.bulkTechniqueLookup validates input array", () => {
  const c = newClient();
  assert.throws(() => c.atlas.bulkTechniqueLookup("AML.T0051"), /array of strings/);
});

test("atlas.techniqueSearch sends keyword (not q) to server", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/atlas/techniques?keyword=prompt", {
    body: { results: [], total: 0 },
  });
  const c = newClient();
  await c.atlas.techniqueSearch({ keyword: "prompt" });
  assert.match(helpers.calls()[0].path, /keyword=prompt/);
});

test("atlas.techniqueSearch accepts q as back-compat alias", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/atlas/techniques?keyword=prompt", {
    body: { results: [], total: 0 },
  });
  const c = newClient();
  await c.atlas.techniqueSearch({ q: "prompt" });
  assert.match(helpers.calls()[0].path, /keyword=prompt/);
});

test("atlas.techniqueSearch throws when both q and keyword passed", () => {
  const c = newClient();
  assert.throws(() => c.atlas.techniqueSearch({ q: "x", keyword: "y" }), /back-compat/);
});

// --- D3FEND namespace ---

test("d3fend.defenseSearch sends keyword, no kind param", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/d3fend/defenses?keyword=encryption", {
    body: { results: [], total: 0 },
  });
  const c = newClient();
  await c.d3fend.defenseSearch({ keyword: "encryption" });
  const last = helpers.calls()[0];
  assert.match(last.path, /keyword=encryption/);
  assert.doesNotMatch(last.path, /kind=/);
});

test("d3fend.defenseForAttack accepts include + exclude_id params", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/d3fend/attack/T1059?include=full&exclude_id=ProcessAllowlist", {
    body: { defenses: [] },
  });
  const c = newClient();
  await c.d3fend.defenseForAttack("T1059", { include: "full", exclude_id: "ProcessAllowlist" });
  assert.match(helpers.calls()[0].path, /include=full/);
});

test("d3fend.coverage POSTs attack_technique_ids body", async () => {
  helpers.mock("POST", "https://api.contrastcyber.com/v1/d3fend/coverage", {
    body: { defended_techniques: [], undefended_techniques: [] },
  });
  const c = newClient();
  await c.d3fend.coverage(["T1059", "T1190"]);
  const body = JSON.parse(helpers.calls()[0].body);
  assert.deepEqual(body.attack_technique_ids, ["T1059", "T1190"]);
});

// --- New username + wayback (parity with Python SDK) ---

test("username.lookup hits /v1/username/{username}", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/username/octocat", {
    body: { username: "octocat", platforms: [] },
  });
  const c = newClient();
  const r = await c.username.lookup("octocat");
  assert.equal(r.username, "octocat");
});

test("domain.wayback hits /v1/archive/{domain}", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/archive/example.com", {
    body: { domain: "example.com", snapshots: [] },
  });
  const c = newClient();
  const r = await c.domain.wayback("example.com");
  assert.equal(r.domain, "example.com");
});

// --- IOC namespace ---

test("ioc.bulk POSTs indicators body", async () => {
  helpers.mock("POST", "https://api.contrastcyber.com/v1/iocs/bulk", {
    body: { successful: 1, results: [] },
  });
  const c = newClient();
  await c.ioc.bulk(["8.8.8.8", "evil.com"]);
  const body = JSON.parse(helpers.calls()[0].body);
  assert.deepEqual(body.indicators, ["8.8.8.8", "evil.com"]);
});

test("ioc.phishing preserves path separators in URL indicator", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/phishing/evil.example.com/login", {
    body: { verdict: "phishing" },
  });
  const c = newClient();
  await c.ioc.phishing("evil.example.com/login");
  assert.match(helpers.calls()[0].path, /evil\.example\.com\/login/);
});

// --- Domain namespace ---

test("domain.report attaches lite=true when opts.lite", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/domain/example.com?lite=true", {
    body: { domain: "example.com" },
  });
  const c = newClient();
  await c.domain.report("example.com", { lite: true });
  assert.match(helpers.calls()[0].path, /lite=true/);
});

// --- API key handling ---

test("X-API-Key header sent when apiKey provided", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/usage", {
    body: { requests_remaining: 999 },
  });
  const c = ContrastAPI({ apiKey: "cc_test_key" });
  await c.usage();
  assert.equal(helpers.calls()[0].headers["X-API-Key"], "cc_test_key");
});

test("no X-API-Key header when keyless", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/usage", {
    body: { requests_remaining: 100 },
  });
  const c = newClient();
  await c.usage();
  assert.equal(helpers.calls()[0].headers["X-API-Key"], undefined);
});

// --- Error handling ---

test("4xx response rejects with status code attached", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/cve/CVE-9999-99999", {
    statusCode: 404,
    body: { error: { code: "not_found", message: "CVE not found" } },
  });
  const c = newClient();
  await assert.rejects(c.cve.lookup("CVE-9999-99999"), (err) => {
    assert.equal(err.status, 404);
    return true;
  });
});

// --- User agent ---

test("User-Agent header is contrastapi-node/<version>", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/status", {
    body: { status: "ok" },
  });
  const c = newClient();
  await c.status();
  assert.match(helpers.calls()[0].headers["User-Agent"], /^contrastapi-node\/\d+\.\d+\.\d+/);
});

// --- v1.5.0: API-surface parity (8 endpoints) ---

const RULE_ID = "11111111-2222-3333-4444-555555555555";

test("domain.robots hits /v1/robots/{domain}", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/robots/example.com", { body: {} });
  const c = newClient();
  await c.domain.robots("example.com");
  assert.equal(helpers.calls()[0].path, "/v1/robots/example.com");
});

test("domain.redirect preserves path separators in URL", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/redirect/https%3A//bit.ly/3xyz", {
    body: { hops: [] },
  });
  const c = newClient();
  await c.domain.redirect("https://bit.ly/3xyz");
  assert.match(helpers.calls()[0].path, /bit\.ly\/3xyz/);
});

test("domain.brand hits /v1/brand/{domain}", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/brand/example.com", { body: {} });
  const c = newClient();
  await c.domain.brand("example.com");
  assert.equal(helpers.calls()[0].path, "/v1/brand/example.com");
});

test("domain.seo hits /v1/seo/{domain}", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/seo/example.com", { body: {} });
  const c = newClient();
  await c.domain.seo("example.com");
  assert.equal(helpers.calls()[0].path, "/v1/seo/example.com");
});

test("email.securityPosture hits /v1/email/security-posture/{domain} with no query by default", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/email/security-posture/example.com", {
    body: {},
  });
  const c = newClient();
  await c.email.securityPosture("example.com");
  assert.equal(helpers.calls()[0].path, "/v1/email/security-posture/example.com");
});

test("email.securityPosture appends selectors query when provided", async () => {
  helpers.mock(
    "GET",
    "https://api.contrastcyber.com/v1/email/security-posture/example.com?selectors=s1%2Cs2",
    { body: {} },
  );
  const c = newClient();
  await c.email.securityPosture("example.com", { selectors: "s1,s2" });
  assert.match(helpers.calls()[0].path, /selectors=s1%2Cs2/);
});

test("email.verify hits /v1/email/verify/{email}", async () => {
  helpers.mock("GET", "https://api.contrastcyber.com/v1/email/verify/user%40example.com", {
    body: {},
  });
  const c = newClient();
  await c.email.verify("user@example.com");
  assert.match(helpers.calls()[0].path, /\/v1\/email\/verify\/user%40example\.com/);
});

test("sigma.lookup hits /v1/sigma/{rule_id}", async () => {
  helpers.mock("GET", `https://api.contrastcyber.com/v1/sigma/${RULE_ID}`, { body: { rule: {} } });
  const c = newClient();
  await c.sigma.lookup(RULE_ID);
  assert.equal(helpers.calls()[0].path, `/v1/sigma/${RULE_ID}`);
});

test("sigma.bulk POSTs rule_ids body", async () => {
  helpers.mock("POST", "https://api.contrastcyber.com/v1/sigma/bulk", { body: { items: [] } });
  const c = newClient();
  await c.sigma.bulk([RULE_ID, "bad-id"]);
  const body = JSON.parse(helpers.calls()[0].body);
  assert.deepEqual(body.rule_ids, [RULE_ID, "bad-id"]);
});

test("sigma.bulk rejects non-array input", () => {
  const c = newClient();
  assert.throws(() => c.sigma.bulk(RULE_ID), /array of strings/);
});
