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
  };
  ip: {
    lookup(ip: string): Promise<any>;
  };
  asn: {
    lookup(target: string): Promise<any>;
  };
  cve: {
    lookup(cveId: string): Promise<any>;
    search(params?: { product?: string; severity?: string; days?: number; limit?: number }): Promise<any>;
    recent(params?: { hours?: number; limit?: number }): Promise<any>;
    kev(params?: { limit?: number }): Promise<any>;
    epss(cveId: string): Promise<any>;
    exploit(cveId: string): Promise<any>;
  };
  ioc: {
    lookup(indicator: string): Promise<any>;
    hash(fileHash: string): Promise<any>;
    phishing(url: string): Promise<any>;
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
