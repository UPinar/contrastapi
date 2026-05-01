# MCP Resources (v1.23.0)

ContrastAPI exposes the ATLAS / D3FEND / CWE catalogs as MCP `resources/*` so agents can browse without spending a tool slot. Resources are pure local-DB lookups — no rate limit, no upstream API, no auth.

## URI map

| URI | Type | Returns |
|---|---|---|
| `atlas://catalog` | static | All ATLAS techniques + case studies (slim summary) |
| `atlas://technique/{technique_id}` | template | Full ATLAS technique record |
| `atlas://case-study/{case_study_id}` | template | Full ATLAS case study |
| `d3fend://catalog` | static | All D3FEND defenses (slim summary) |
| `d3fend://defense/{defense_id}` | template | Full D3FEND defense + ATT&CK mappings |
| `cwe://catalog` | static | All CWE weaknesses (id+name+abstract_type) |
| `cwe://weakness/{cwe_id}` | template | Full CWE record incl. mitigations + examples |

`{technique_id}` accepts ATLAS format `AML.T####` or `AML.T####.###`. `{cwe_id}` accepts `CWE-79` or just `79` (auto-prefixed). All MIME types are `application/json`.

## Why resources, not tools?

Tools and resources cover different use-cases:

- **Resources** — "I know exactly which catalog row I want." Browse-style. Cheap. No filtering / pivots.
- **Tools** (`atlas_technique_search`, `d3fend_defense_search`, `cwe_lookup`, ...) — "I want to filter / pivot / chain." Carries a rate budget but supports parameters and emits `next_calls` pivot hints.

Reach for resources when an agent already has a CWE id or a D3FEND slug from a prior tool call and you want to drill the full record without re-running the search.

## Discovery

```bash
# List static resources (3 catalogs)
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}'

# List URI templates (4 detail-resource templates)
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"resources/templates/list","params":{}}'
```

## Read

```bash
# Full ATLAS technique
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"atlas://technique/AML.T0051"}}'

# CWE-79 (bare-number form auto-prefixes)
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"cwe://weakness/79"}}'

# Full D3FEND catalog (149 defenses, slim)
curl -X POST https://api.contrastcyber.com/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"d3fend://catalog"}}'
```

## Catalog payload shape (slim by design)

The CWE catalog has 944 rows in production; full descriptions blow past most agent context budgets. Catalog responses therefore carry **only** `id + name + key fields` per row. Use the per-id template URI when you need the full record.

```json
// atlas://catalog
{
  "techniques": [{"technique_id": "AML.T0051", "name": "LLM Prompt Injection", "tactics": ["AML.TA0011"], "subtechnique_of": null}, ...],
  "case_studies": [{"case_study_id": "AML.CS0000", "name": "Evasion of Deep Learning Detector"}, ...],
  "totals": {"techniques": 167, "case_studies": 57},
  "truncated": false
}

// d3fend://catalog
{
  "defenses": [{"defense_id": "TokenBinding", "label": "Token Binding", "tactic": "Harden", "artifact": "Token", "parent_label": "Authentication"}, ...],
  "totals": {"defenses": 149},
  "truncated": false
}

// cwe://catalog
{
  "weaknesses": [{"cwe_id": "CWE-79", "name": "Improper Neutralization of Input ...", "abstract_type": "Base"}, ...],
  "totals": {"weaknesses": 944},
  "truncated": false,
  "note": "Slim view (cwe_id + name + abstract_type only). Read cwe://weakness/{id} for description, mitigations, examples."
}
```

The `truncated` boolean is true when the in-memory listing length is below the table count — surfaced honestly so clients fall back to the search tools (`atlas_technique_search`, `d3fend_defense_search`) instead of trusting an incomplete catalog. Today it is always false in production (catalog sizes well within the listing cap); the flag is forward-compatible.

## Errors

A well-formed but unknown id surfaces as a JSON-RPC error response (not a 200-with-empty-body) so agents can branch on it cleanly:

- `atlas://technique/AML.T9999` (well-formed, not in catalog) → JSON-RPC error
- `atlas://technique/not-an-id` (malformed) → JSON-RPC error (validator rejects before DB lookup)
- `cwe://weakness/0` (well-formed, not in catalog) → JSON-RPC error

## Cache strategy

Catalog data ships with the server (synced from upstream on a schedule — ATLAS ~6 months, D3FEND ~yearly, CWE ~weekly). Resources read directly from SQLite on each call; no MCP-layer cache, no TTL. Upstream sync cadence is the only cache.
