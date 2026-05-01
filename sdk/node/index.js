/**
 * ContrastAPI — Security Intelligence SDK
 * https://api.contrastcyber.com
 */

const https = require("https");
const http = require("http");

const DEFAULT_BASE = "https://api.contrastcyber.com";
const MAX_BODY = 10 * 1024 * 1024; // 10 MB
const VERSION = require("./package.json").version;

function enc(v) {
  if (!v && v !== 0) throw new Error("Missing required parameter");
  return encodeURIComponent(String(v));
}

function encPath(v) {
  if (!v) throw new Error("Missing required parameter");
  return String(v).split("/").map(encodeURIComponent).join("/");
}

function ContrastAPI(options = {}) {
  const baseUrl = (options.baseUrl || DEFAULT_BASE).replace(/\/$/, "");
  const apiKey = options.apiKey || null;
  const timeout = Math.max(1000, Math.min(options.timeout || 30000, 120000));

  if (!baseUrl.startsWith("https://") && !options.allowInsecure) {
    throw new Error("Only HTTPS is allowed. Pass { allowInsecure: true } to override.");
  }

  function request(method, path, body) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, baseUrl);
      if (url.origin !== new URL(baseUrl).origin) {
        return reject(new Error("URL origin mismatch"));
      }

      const headers = {
        "Accept": "application/json",
        "User-Agent": `contrastapi-node/${VERSION}`,
      };
      if (apiKey) {
        if (url.protocol !== "https:") {
          return reject(new Error("Refusing to send API key over insecure connection"));
        }
        headers["X-API-Key"] = apiKey;
      }

      let payload;
      if (body) {
        payload = JSON.stringify(body);
        headers["Content-Type"] = "application/json";
        headers["Content-Length"] = Buffer.byteLength(payload);
      }

      const mod = url.protocol === "https:" ? https : http;
      const req = mod.request(url, { method, headers, timeout }, (res) => {
        let data = "";
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size > MAX_BODY) {
            req.destroy();
            return reject(new Error("Response too large"));
          }
          data += chunk;
        });
        res.on("end", () => {
          try {
            const json = JSON.parse(data);
            if (res.statusCode >= 400) {
              const err = new Error(json.detail || json.message || `HTTP ${res.statusCode}`);
              err.status = res.statusCode;
              reject(err);
            } else {
              resolve(json);
            }
          } catch {
            reject(new Error(`Invalid JSON response (HTTP ${res.statusCode})`));
          }
        });
      });

      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out")); });
      if (payload) req.write(payload);
      req.end();
    });
  }

  function get(path) { return request("GET", path); }
  function post(path, body) { return request("POST", path, body); }

  return {
    // --- Domain Intelligence ---
    domain: {
      report: (domain, opts = {}) => get(`/v1/domain/${enc(domain)}${opts.lite ? "?lite=true" : ""}`),
      dns: (domain) => get(`/v1/dns/${enc(domain)}`),
      whois: (domain) => get(`/v1/whois/${enc(domain)}`),
      subdomains: (domain) => get(`/v1/subdomains/${enc(domain)}`),
      certs: (domain) => get(`/v1/certs/${enc(domain)}`),
      ssl: (domain) => get(`/v1/ssl/${enc(domain)}`),
      tech: (domain) => get(`/v1/tech/${enc(domain)}`),
      threat: (domain) => get(`/v1/threat/${enc(domain)}`),
      monitor: (domain) => get(`/v1/monitor/${enc(domain)}`),
      vulns: (domain) => get(`/v1/domain/${enc(domain)}/vulns`),
      bulk: (domains) => {
        if (!Array.isArray(domains) || !domains.every(d => typeof d === "string")) {
          throw new Error("domains must be an array of strings");
        }
        return post("/v1/domains/bulk", { domains });
      },
      audit: (domain) => get(`/v1/audit/${enc(domain)}`),
      // v1.4.0: Wayback Machine archive lookup (parity with Python SDK).
      wayback: (domain) => get(`/v1/archive/${enc(domain)}`),
    },

    // --- IP Intelligence ---
    ip: {
      lookup: (ip) => get(`/v1/ip/${enc(ip)}`),
      threatReport: (ip) => get(`/v1/threat-report/${enc(ip)}`),
    },

    // --- ASN ---
    asn: {
      lookup: (target) => get(`/v1/asn/${enc(target)}`),
    },

    // --- CVE Intelligence ---
    cve: {
      lookup: (cveId) => get(`/v1/cve/${enc(cveId)}`),
      search: (params = {}) => {
        const q = new URLSearchParams();
        if (params.product) q.set("product", params.product);
        if (params.severity) q.set("severity", params.severity);
        if (params.days) q.set("days", params.days);
        if (params.limit) q.set("limit", params.limit);
        return get(`/v1/cves?${q}`);
      },
      leading: (params = {}) => {
        const q = new URLSearchParams();
        if (params.limit) q.set("limit", params.limit);
        if (params.offset) q.set("offset", params.offset);
        if (params.include) q.set("include", params.include);
        const qs = q.toString();
        return get(`/v1/cve/leading${qs ? "?" + qs : ""}`);
      },
      kev: (cveId) => get(`/v1/kev/${enc(cveId)}`),
      exploit: (cveId) => get(`/v1/exploit/${enc(cveId)}`),
      bulk: (cveIds) => {
        if (!Array.isArray(cveIds) || !cveIds.every(c => typeof c === "string")) {
          throw new Error("cveIds must be an array of strings");
        }
        return post("/v1/cves/bulk", { cve_ids: cveIds });
      },
    },

    // --- CWE (MITRE Common Weakness Enumeration) ---
    cwe: {
      lookup: (cweId) => get(`/v1/cwe/${enc(cweId)}`),
    },

    // --- MITRE ATLAS (AI/ML attack catalog) ---
    atlas: {
      technique: (techniqueId) => get(`/v1/atlas/${enc(techniqueId)}`),
      techniqueSearch: (params = {}) => {
        // v1.4.0: server param is `keyword`; SDK accepts `keyword=` or back-compat `q=`.
        // Passing both raises (matches Python SDK behaviour).
        if (params.keyword !== undefined && params.q !== undefined) {
          throw new Error("Pass only one of `keyword` or `q` (q is a back-compat alias)");
        }
        const kw = params.keyword !== undefined ? params.keyword : params.q;
        const qs = new URLSearchParams();
        if (kw) qs.set("keyword", kw);
        if (params.tactic) qs.set("tactic", params.tactic);
        if (params.maturity) qs.set("maturity", params.maturity);
        if (params.limit) qs.set("limit", params.limit);
        if (params.offset) qs.set("offset", params.offset);
        if (params.include) qs.set("include", params.include);
        if (params.exclude_id) qs.set("exclude_id", params.exclude_id);
        const out = qs.toString();
        return get(`/v1/atlas/techniques${out ? "?" + out : ""}`);
      },
      // v1.4.0: bulk technique drill — parity with Python SDK and v1.20.0 server endpoint.
      bulkTechniqueLookup: (techniqueIds) => {
        if (!Array.isArray(techniqueIds) || !techniqueIds.every(t => typeof t === "string")) {
          throw new Error("techniqueIds must be an array of strings");
        }
        return post("/v1/atlas/techniques/bulk", { technique_ids: techniqueIds });
      },
      caseStudy: (caseStudyId) => get(`/v1/atlas/case-studies/${enc(caseStudyId)}`),
      caseStudySearch: (params = {}) => {
        if (params.keyword !== undefined && params.q !== undefined) {
          throw new Error("Pass only one of `keyword` or `q` (q is a back-compat alias)");
        }
        const kw = params.keyword !== undefined ? params.keyword : params.q;
        const qs = new URLSearchParams();
        if (kw) qs.set("keyword", kw);
        if (params.target_type) qs.set("target_type", params.target_type);
        if (params.limit) qs.set("limit", params.limit);
        if (params.offset) qs.set("offset", params.offset);
        if (params.include) qs.set("include", params.include);
        const out = qs.toString();
        return get(`/v1/atlas/case-studies${out ? "?" + out : ""}`);
      },
    },

    // --- MITRE D3FEND (defense technique catalog) ---
    d3fend: {
      defense: (defenseId) => get(`/v1/d3fend/${enc(defenseId)}`),
      defenseSearch: (params = {}) => {
        // v1.4.0: server param is `keyword`; `kind` removed (server doesn't accept it).
        if (params.keyword !== undefined && params.q !== undefined) {
          throw new Error("Pass only one of `keyword` or `q` (q is a back-compat alias)");
        }
        const kw = params.keyword !== undefined ? params.keyword : params.q;
        const qs = new URLSearchParams();
        if (kw) qs.set("keyword", kw);
        if (params.tactic) qs.set("tactic", params.tactic);
        if (params.artifact) qs.set("artifact", params.artifact);
        if (params.limit) qs.set("limit", params.limit);
        if (params.offset) qs.set("offset", params.offset);
        if (params.include) qs.set("include", params.include);
        if (params.exclude_id) qs.set("exclude_id", params.exclude_id);
        const out = qs.toString();
        return get(`/v1/d3fend/defenses${out ? "?" + out : ""}`);
      },
      defenseForAttack: (attackTechniqueId, params = {}) => {
        // v1.4.0: server accepts include + exclude_id query params.
        const qs = new URLSearchParams();
        if (params.include) qs.set("include", params.include);
        if (params.exclude_id) qs.set("exclude_id", params.exclude_id);
        const out = qs.toString();
        return get(`/v1/d3fend/attack/${enc(attackTechniqueId)}${out ? "?" + out : ""}`);
      },
      coverage: (attackTechniqueIds) => {
        if (!Array.isArray(attackTechniqueIds) || !attackTechniqueIds.every(c => typeof c === "string")) {
          throw new Error("attackTechniqueIds must be an array of strings");
        }
        return post("/v1/d3fend/coverage", { attack_technique_ids: attackTechniqueIds });
      },
    },

    // --- Threat Intelligence / IOC ---
    ioc: {
      lookup: (indicator) => get(`/v1/ioc/${encPath(indicator)}`),
      hash: (fileHash) => get(`/v1/hash/${enc(fileHash)}`),
      phishing: (url) => get(`/v1/phishing/${encPath(url)}`),
      bulk: (indicators) => {
        if (!Array.isArray(indicators) || !indicators.every(i => typeof i === "string")) {
          throw new Error("indicators must be an array of strings");
        }
        return post("/v1/iocs/bulk", { indicators });
      },
    },

    // --- Email ---
    email: {
      mx: (domain) => get(`/v1/email/mx/${enc(domain)}`),
      disposable: (email) => get(`/v1/email/disposable/${enc(email)}`),
    },

    // --- Phone ---
    phone: {
      lookup: (number) => get(`/v1/phone/${enc(number)}`),
    },

    // --- Password ---
    password: {
      check: (sha1Hash) => get(`/v1/password/${enc(sha1Hash)}`),
    },

    // --- Username (v1.4.0: parity with Python SDK; new endpoint coverage) ---
    username: {
      lookup: (username) => get(`/v1/username/${enc(username)}`),
    },

    // --- Code Security ---
    check: {
      secrets: (code, language) => post("/v1/check/secrets", { code, language }),
      injection: (code, language) => post("/v1/check/injection", { code, language }),
      headers: (headers) => post("/v1/check/headers", { headers }),
      dependencies: (packages) => post("/v1/check/dependencies", { packages }),
    },

    // --- Headers (live scan) ---
    scan: {
      headers: (domain) => get(`/v1/scan/headers/${enc(domain)}`),
    },

    // --- Meta ---
    status: () => get("/v1/status"),
    usage: () => get("/v1/usage"),
  };
}

module.exports = ContrastAPI;
