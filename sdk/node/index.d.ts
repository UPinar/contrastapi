declare function ContrastAPI(options?: {
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
  allowInsecure?: boolean;
}): {
  domain: {
    report(domain: string, opts?: { lite?: boolean }): Promise<any>;
    dns(domain: string): Promise<any>;
    whois(domain: string): Promise<any>;
    subdomains(domain: string): Promise<any>;
    certs(domain: string): Promise<any>;
    ssl(domain: string): Promise<any>;
    tech(domain: string): Promise<any>;
    threat(domain: string): Promise<any>;
    monitor(domain: string): Promise<any>;
    vulns(domain: string): Promise<any>;
    bulk(domains: string[]): Promise<any>;
    audit(domain: string): Promise<any>;
  };
  ip: {
    lookup(ip: string): Promise<any>;
    threatReport(ip: string): Promise<any>;
  };
  asn: {
    lookup(target: string): Promise<any>;
  };
  cve: {
    lookup(cveId: string): Promise<any>;
    search(params?: { product?: string; severity?: string; days?: number; limit?: number }): Promise<any>;
    leading(params?: { limit?: number; offset?: number; include?: string }): Promise<any>;
    kev(cveId: string): Promise<any>;
    exploit(cveId: string): Promise<any>;
    bulk(cveIds: string[]): Promise<any>;
  };
  cwe: {
    lookup(cweId: string): Promise<any>;
  };
  atlas: {
    technique(techniqueId: string): Promise<any>;
    techniqueSearch(params?: { q?: string; tactic?: string; maturity?: string; limit?: number; offset?: number; include?: string }): Promise<any>;
    caseStudy(caseStudyId: string): Promise<any>;
    caseStudySearch(params?: { q?: string; target_type?: string; limit?: number; offset?: number; include?: string }): Promise<any>;
  };
  d3fend: {
    defense(defenseId: string): Promise<any>;
    defenseSearch(params?: { q?: string; tactic?: string; kind?: string; limit?: number; offset?: number }): Promise<any>;
    defenseForAttack(attackTechniqueId: string): Promise<any>;
    coverage(attackTechniqueIds: string[]): Promise<any>;
  };
  ioc: {
    lookup(indicator: string): Promise<any>;
    hash(fileHash: string): Promise<any>;
    phishing(url: string): Promise<any>;
    bulk(indicators: string[]): Promise<any>;
  };
  email: {
    mx(domain: string): Promise<any>;
    disposable(email: string): Promise<any>;
  };
  phone: {
    lookup(number: string): Promise<any>;
  };
  password: {
    check(sha1Hash: string): Promise<any>;
  };
  check: {
    secrets(code: string, language: string): Promise<any>;
    injection(code: string, language: string): Promise<any>;
    headers(headers: Record<string, string>): Promise<any>;
    dependencies(packages: Array<{ name: string; version?: string }>): Promise<any>;
  };
  scan: {
    headers(domain: string): Promise<any>;
  };
  status(): Promise<any>;
  usage(): Promise<any>;
};

export = ContrastAPI;
