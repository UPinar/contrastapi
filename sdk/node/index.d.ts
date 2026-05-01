// ContrastAPI Node SDK — TypeScript declarations
// v1.4.0: concrete response types mirror the v1.22.3 Python SDK + server schemas.
// Drift from `app/schemas.py` → silent KeyError downstream, so types are kept
// loose at the leaf level (`any`) while top-level keys are enumerated.
// Wire-exact field names; consult `app/schemas.py` for full nested shapes.

// ============================================================================
// Cross-cutting shapes
// ============================================================================

export interface ErrorBody {
  code: string;
  message: string;
  retry_after_seconds?: number | null;
  upgrade_url?: string | null;
  docs_url?: string | null;
}

export interface ErrorEnvelope {
  error?: ErrorBody;
  // Top-level back-compat extensions: hint, tier, limit, upgrade, field, ...
  [key: string]: any;
}

export interface Verdict {
  deterministic?: boolean;
  falsifiable_fields?: string[];
  sources_queried?: string[];
  sources_unavailable?: string[];
  completeness?: string;
}

export interface PivotHint {
  tool?: string;
  value?: string;
  reason?: string;
  params?: Record<string, any>;
}

interface BaseSuccess {
  verdict?: Verdict;
  next_calls?: PivotHint[];
}

// ============================================================================
// CVE / KEV / CWE / Exploit
// ============================================================================

export interface CveResponse extends BaseSuccess {
  cve_id?: string;
  summary?: string;
  description?: string;
  severity?: string;
  cvss_v3?: number;
  cvss_breakdown?: Record<string, any>;
  cwe_id?: string;
  epss?: Record<string, any>;
  kev?: Record<string, any>;
  affected_products?: Array<Record<string, any>>;
  total_products?: number;
  published?: string;
  modified?: string;
  references?: string[];
  total_references?: number;
  patch_available?: boolean;
  patch_url?: string;
  sources?: string[];
}

export interface CveSearchResponse extends BaseSuccess {
  count?: number;
  total?: number;
  truncated?: boolean;
  offset?: number;
  summary?: string;
  results?: Array<Record<string, any>>;
  query_echo?: Record<string, any>;
  next_offset?: number | null;
  hint?: Record<string, any>;
}

export interface KevDetailResponse extends BaseSuccess {
  cve_id?: string;
  in_kev?: boolean;
  date_added?: string;
  due_date?: string;
  required_action?: string;
  known_ransomware_use?: boolean;
  vendor_project?: string;
  product?: string;
  vulnerability_name?: string;
  short_description?: string;
  notes?: string;
  cwes?: string[];
}

export interface CweLookupResponse extends BaseSuccess {
  cwe_id?: string;
  name?: string;
  description?: string;
  extended_description?: string;
  abstract_type?: string;
  status?: string;
  likelihood?: string;
  mitigations?: string[];
  examples?: string[];
  parent_cwe?: string;
  child_cwes?: string[];
  cve_count?: number;
  total_mitigations?: number | null;
  total_examples?: number | null;
  updated_at?: string;
}

export interface ExploitResponse extends BaseSuccess {
  cve_id?: string;
  exploits_found?: number;
  sources?: Record<string, any>;
  has_public_exploit?: boolean;
  exploits?: Array<Record<string, any>>;
  summary?: string;
}

// ============================================================================
// Bulk parity (v1.21.0+ unified status enum)
// ============================================================================

export type BulkStatus = "ok" | "error" | "not_found" | "invalid_format";

export interface BulkCveItem {
  cve_id?: string;
  status?: BulkStatus;
  cve?: CveResponse | null;
  error?: string;
}

export interface BulkCveResponse extends BaseSuccess {
  results?: BulkCveItem[];
  total?: number;
  successful?: number;
  failed?: number;
  timed_out?: number;
  not_found?: number;
  partial?: boolean;
  summary?: string;
}

export interface BulkIocItem {
  indicator?: string;
  status?: BulkStatus;
  ioc?: Record<string, any>;
  error?: string;
}

export interface BulkIocResponse extends BaseSuccess {
  results?: BulkIocItem[];
  total?: number;
  successful?: number;
  failed?: number;
  timed_out?: number;
  not_found?: number;
  invalid?: number;
  partial?: boolean;
  summary?: string;
}

export interface BulkAtlasTechniqueItem {
  technique_id?: string;
  status?: BulkStatus;
  technique?: Record<string, any>;
  error?: string;
}

export interface BulkAtlasTechniqueResponse extends BaseSuccess {
  results?: BulkAtlasTechniqueItem[];
  total?: number;
  successful?: number;
  failed?: number;
  partial?: boolean;
  summary?: string;
}

export interface BulkDomainResponse extends BaseSuccess {
  results?: Array<Record<string, any>>;
  total?: number;
  successful?: number;
  failed?: number;
  timed_out?: number;
  summary?: string;
}

// ============================================================================
// IOC / Hash / Phishing / Password
// ============================================================================

export interface IocResponse extends BaseSuccess {
  indicator?: string;
  type?: string; // ip | domain | url | hash | unknown
  threat_level?: string; // none | low | medium | high
  sources?: Record<string, any>;
  summary?: string;
}

export interface HashResponse extends BaseSuccess {
  hash?: string;
  hash_type?: string;
  found?: boolean;
  malware_family?: string | null;
  file_type?: string | null;
  file_size?: number | null;
  first_seen?: string | null;
  tags?: string[];
}

export interface PhishingResponse extends BaseSuccess {
  url?: string;
  host?: string;
  is_malicious?: boolean;
  is_stale?: boolean;
  sources?: Record<string, any>;
  summary?: string;
}

export interface PasswordResponse extends BaseSuccess {
  hash_prefix?: string;
  found?: boolean;
  pwned_count?: number;
  summary?: string;
}

// ============================================================================
// Domain
// ============================================================================

export interface DomainReportResponse extends BaseSuccess {
  domain?: string;
  dns?: Record<string, any>;
  reverse_dns?: Record<string, any>;
  whois?: Record<string, any>;
  ssl?: Record<string, any>;
  subdomains?: Record<string, any>;
  certificates?: Record<string, any>;
  email_security?: Record<string, any>;
  waf?: Record<string, any>;
  threat?: Record<string, any>;
  risk?: Record<string, any>;
  /** DEPRECATED (Sunset 2026-09-01) — use `risk.score` instead. */
  risk_score?: number | null;
  reputation?: Record<string, any>;
  summary?: string;
}

export interface DnsResponse extends BaseSuccess {
  domain?: string;
  records?: Record<string, any>;
  summary?: string;
}

export interface WhoisResponse extends BaseSuccess {
  domain?: string;
  whois?: Record<string, any>;
  summary?: string;
}

export interface SubdomainsResponse extends BaseSuccess {
  domain?: string;
  count?: number;
  subdomains?: string[];
  summary?: string;
  sources?: string[];
  warnings?: string[];
  found_via_wordlist?: number;
  found_via_crtsh?: number;
}

export interface CertsResponse extends BaseSuccess {
  domain?: string;
  total_certificates?: number;
  certificates?: Array<Record<string, any>>;
  summary?: string;
}

export interface SslResponse extends BaseSuccess {
  domain?: string;
  valid?: boolean;
  cert_valid?: boolean;
  grade?: string;
  validation_errors?: string[];
  issuer?: Record<string, any>;
  subject?: Record<string, any>;
  san?: string[];
  not_before?: string;
  not_after?: string;
  days_until_expiry?: number;
  summary?: string;
}

export interface TechResponse extends BaseSuccess {
  domain?: string;
  technologies?: Array<Record<string, any>>;
  categories?: Record<string, string[]>;
  count?: number;
  summary?: string;
}

export interface ThreatResponse extends BaseSuccess {
  domain?: string;
  urlhaus_status?: string;
  urls_online?: number;
  url_count?: number;
  threat_types?: string[];
  tags?: string[];
  urls?: Array<Record<string, any>>;
  summary?: string;
}

export interface WaybackResponse extends BaseSuccess {
  domain?: string;
  status?: string; // 'ok' | 'unavailable'
  snapshots?: Array<Record<string, any>>;
  total_snapshots?: number;
  earliest?: string;
  latest?: string;
  warnings?: string[];
  summary?: string;
}

export interface AuditResponse extends BaseSuccess {
  domain?: string;
  report?: DomainReportResponse | null;
  headers?: Record<string, any>;
  tech?: TechResponse | null;
  summary?: string;
}

// ============================================================================
// IP / ASN / Threat report
// ============================================================================

export interface IpLookupResponse extends BaseSuccess {
  ip?: string;
  ptr?: string | null;
  asn?: number | null;
  asn_name?: string | null;
  country?: string | null;
  ports?: number[];
  hostnames?: string[];
  vulns?: Array<Record<string, any>>;
  cpes?: string[];
  tags?: string[];
  reputation?: Record<string, any>;
  cloud_provider?: string | null;
  is_datacenter?: boolean;
  tor_exit?: boolean;
  risk_score?: number;
  severity_label?: string; // low | medium | high | critical
  summary?: string;
}

export interface AsnResponse extends BaseSuccess {
  target?: string;
  resolved_ip?: string | null;
  asn?: number;
  asn_name?: string;
  country?: string | null;
  prefixes?: string[];
  prefix_count?: number;
  summary?: string;
}

export interface ThreatReportResponse extends BaseSuccess {
  ip?: string;
  enrichment?: Record<string, any>;
  abuseipdb?: Record<string, any>;
  shodan?: Record<string, any>;
  asn_info?: Record<string, any>;
  risk_score?: number;
  severity_label?: string;
  summary?: string;
}

// ============================================================================
// Email / Phone / Username
// ============================================================================

export interface EmailMxResponse extends BaseSuccess {
  domain?: string;
  mx_records?: Array<Record<string, any>>;
  mail_provider?: string | null;
  email_security?: Record<string, any>;
  summary?: string;
}

export interface DisposableResponse extends BaseSuccess {
  email?: string;
  domain?: string;
  disposable?: boolean;
  provider?: string | null;
  summary?: string;
}

export interface PhoneLookupResponse extends BaseSuccess {
  valid?: boolean;
  number?: string;
  country?: string | null;
  region?: string | null;
  carrier?: string | null;
  line_type?: string | null;
  format?: Record<string, any>;
  summary?: string;
}

export interface UsernameLookupResponse extends BaseSuccess {
  username?: string;
  found_count?: number;
  platforms?: Array<Record<string, any>>;
  summary?: string;
}

// ============================================================================
// ATLAS
// ============================================================================

export interface AtlasTechniqueResponse extends BaseSuccess {
  technique_id?: string;
  name?: string;
  description?: string;
  tactics?: string[];
  inherited_tactics?: boolean;
  maturity?: string;
  attack_reference_id?: string;
  attack_reference_url?: string;
  subtechnique_of?: string;
  created_date?: string;
  modified_date?: string;
}

export interface AtlasTechniqueListItem {
  technique_id?: string;
  name?: string;
  description?: string;
  tactics?: string[];
  inherited_tactics?: boolean;
  maturity?: string;
  attack_reference_id?: string;
  subtechnique_of?: string;
}

export interface AtlasTechniqueSearchResponse extends BaseSuccess {
  query?: Record<string, any>;
  total?: number;
  results?: AtlasTechniqueListItem[];
}

export interface AtlasCaseStudyResponse extends BaseSuccess {
  case_study_id?: string;
  name?: string;
  description?: string;
  techniques_used?: string[];
}

export interface AtlasCaseStudySearchResponse extends BaseSuccess {
  query?: Record<string, any>;
  total?: number;
  results?: AtlasCaseStudyResponse[];
}

// ============================================================================
// D3FEND
// ============================================================================

export interface D3fendDefenseResponse extends BaseSuccess {
  defense_id?: string;
  label?: string;
  uri?: string;
  parent_label?: string;
  description?: string;
  tactic?: string; // singular
  artifact?: string;
  attack_techniques?: string[];
}

export interface D3fendDefenseListItem {
  defense_id?: string;
  label?: string;
  uri?: string;
  parent_label?: string;
  tactic?: string;
  artifact?: string;
}

export interface D3fendDefenseSearchResponse extends BaseSuccess {
  query?: Record<string, any>;
  total?: number;
  results?: D3fendDefenseListItem[];
}

export interface D3fendDefenseForAttackItem {
  defense_id?: string;
  label?: string;
  uri?: string;
  parent_label?: string;
  tactic?: string;
  artifact?: string;
  attack_label?: string;
  attack_tactic?: string;
}

export interface D3fendForAttackResponse extends BaseSuccess {
  attack_technique_id?: string;
  total?: number;
  truncated?: boolean;
  defenses?: D3fendDefenseForAttackItem[];
  coverage_by_tactic?: Record<string, number>;
}

export interface D3fendCoverageResponse extends BaseSuccess {
  queried_techniques?: string[];
  coverage_by_tactic?: Record<string, number>;
  defended_techniques?: string[];
  undefended_techniques?: string[];
}

// ============================================================================
// Code-security checks + scan
// ============================================================================

export interface CodeCheckResponse extends BaseSuccess {
  findings?: Array<Record<string, any>>;
  total?: number;
  by_severity?: Record<string, number>;
  summary?: string;
}

export interface CheckHeadersResponse extends BaseSuccess {
  findings?: Array<Record<string, any>>;
  total?: number;
  by_severity?: Record<string, number>;
  summary?: string;
}

export interface ScanHeadersResponse extends BaseSuccess {
  domain?: string;
  status_code?: number;
  url?: string;
  score?: number;
  grade?: string;
  findings?: Array<Record<string, any>>;
  headers?: Record<string, string>;
  summary?: string;
}

export interface DependenciesResponse extends BaseSuccess {
  findings?: Array<Record<string, any>>;
  total?: number;
  by_severity?: Record<string, number>;
  summary?: string;
}

// ============================================================================
// Meta
// ============================================================================

export interface StatusResponse {
  status?: string;
  version?: string;
  uptime_seconds?: number;
}

export interface UsageResponse {
  requests_remaining?: number;
  window_seconds?: number;
  tier?: string;
}

// ============================================================================
// Search param shapes
// ============================================================================

export interface CveSearchParams {
  product?: string;
  severity?: string;
  days?: number;
  limit?: number;
}

export interface CveLeadingParams {
  limit?: number;
  offset?: number;
  include?: string;
}

export interface AtlasTechniqueSearchParams {
  /** v1.4.0: prefer `keyword`. `q` is back-compat alias; passing both throws. */
  keyword?: string;
  q?: string;
  tactic?: string;
  maturity?: string;
  limit?: number;
  offset?: number;
  include?: string;
  exclude_id?: string;
}

export interface AtlasCaseStudySearchParams {
  keyword?: string;
  q?: string;
  target_type?: string;
  limit?: number;
  offset?: number;
  include?: string;
}

export interface D3fendDefenseSearchParams {
  /** v1.4.0: prefer `keyword`. `q` is back-compat alias; passing both throws. */
  keyword?: string;
  q?: string;
  tactic?: string;
  artifact?: string;
  limit?: number;
  offset?: number;
  include?: string;
  exclude_id?: string;
}

export interface D3fendForAttackParams {
  include?: string;
  exclude_id?: string;
}

// ============================================================================
// Client factory
// ============================================================================

declare function ContrastAPI(options?: {
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
  allowInsecure?: boolean;
}): {
  domain: {
    report(domain: string, opts?: { lite?: boolean }): Promise<DomainReportResponse>;
    dns(domain: string): Promise<DnsResponse>;
    whois(domain: string): Promise<WhoisResponse>;
    subdomains(domain: string): Promise<SubdomainsResponse>;
    certs(domain: string): Promise<CertsResponse>;
    ssl(domain: string): Promise<SslResponse>;
    tech(domain: string): Promise<TechResponse>;
    threat(domain: string): Promise<ThreatResponse>;
    monitor(domain: string): Promise<Record<string, any>>;
    vulns(domain: string): Promise<Record<string, any>>;
    bulk(domains: string[]): Promise<BulkDomainResponse>;
    audit(domain: string): Promise<AuditResponse>;
    /** v1.4.0: Wayback Machine archive lookup. */
    wayback(domain: string): Promise<WaybackResponse>;
  };
  ip: {
    lookup(ip: string): Promise<IpLookupResponse>;
    threatReport(ip: string): Promise<ThreatReportResponse>;
  };
  asn: {
    lookup(target: string): Promise<AsnResponse>;
  };
  cve: {
    lookup(cveId: string): Promise<CveResponse>;
    search(params?: CveSearchParams): Promise<CveSearchResponse>;
    leading(params?: CveLeadingParams): Promise<CveSearchResponse>;
    kev(cveId: string): Promise<KevDetailResponse>;
    exploit(cveId: string): Promise<ExploitResponse>;
    bulk(cveIds: string[]): Promise<BulkCveResponse>;
  };
  cwe: {
    lookup(cweId: string): Promise<CweLookupResponse>;
  };
  atlas: {
    technique(techniqueId: string): Promise<AtlasTechniqueResponse>;
    techniqueSearch(params?: AtlasTechniqueSearchParams): Promise<AtlasTechniqueSearchResponse>;
    /** v1.4.0: bulk technique drill (server v1.20.0+). */
    bulkTechniqueLookup(techniqueIds: string[]): Promise<BulkAtlasTechniqueResponse>;
    caseStudy(caseStudyId: string): Promise<AtlasCaseStudyResponse>;
    caseStudySearch(params?: AtlasCaseStudySearchParams): Promise<AtlasCaseStudySearchResponse>;
  };
  d3fend: {
    defense(defenseId: string): Promise<D3fendDefenseResponse>;
    /** v1.4.0: server param renamed `q` → `keyword`. `kind` removed (server doesn't accept it). */
    defenseSearch(params?: D3fendDefenseSearchParams): Promise<D3fendDefenseSearchResponse>;
    defenseForAttack(attackTechniqueId: string, params?: D3fendForAttackParams): Promise<D3fendForAttackResponse>;
    coverage(attackTechniqueIds: string[]): Promise<D3fendCoverageResponse>;
  };
  ioc: {
    lookup(indicator: string): Promise<IocResponse>;
    hash(fileHash: string): Promise<HashResponse>;
    phishing(url: string): Promise<PhishingResponse>;
    bulk(indicators: string[]): Promise<BulkIocResponse>;
  };
  email: {
    mx(domain: string): Promise<EmailMxResponse>;
    disposable(email: string): Promise<DisposableResponse>;
  };
  phone: {
    lookup(number: string): Promise<PhoneLookupResponse>;
  };
  password: {
    check(sha1Hash: string): Promise<PasswordResponse>;
  };
  /** v1.4.0: parity with Python SDK. */
  username: {
    lookup(username: string): Promise<UsernameLookupResponse>;
  };
  check: {
    secrets(code: string, language?: string): Promise<CodeCheckResponse>;
    injection(code: string, language?: string): Promise<CodeCheckResponse>;
    headers(headers: Record<string, string>): Promise<CheckHeadersResponse>;
    dependencies(packages: string[]): Promise<DependenciesResponse>;
  };
  scan: {
    headers(domain: string): Promise<ScanHeadersResponse>;
  };
  status(): Promise<StatusResponse>;
  usage(): Promise<UsageResponse>;
};

export = ContrastAPI;
