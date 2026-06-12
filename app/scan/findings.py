"""Vulnerability findings and enterprise detection for ContrastScan"""

from collections import Counter

from config import SEVERITY_LEVELS, SEVERITY_ORDER

HEADER_RISKS = {
    "content-security-policy": {
        "risk": "high",
        "attack": "Cross-Site Scripting (XSS), data injection",
        "description": "No CSP allows attackers to inject malicious scripts via XSS vulnerabilities.",
        "fix": "Add Content-Security-Policy header with strict directives.",
        "ref": "https://owasp.org/www-community/attacks/xss/",
    },
    "strict-transport-security": {
        "risk": "high",
        "attack": "SSL stripping, MITM downgrade",
        "description": "Without HSTS, attackers can downgrade HTTPS to HTTP via MITM.",
        "fix": "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        "ref": "https://owasp.org/www-project-secure-headers/",
    },
    "x-content-type-options": {
        "risk": "medium",
        "attack": "MIME sniffing, drive-by downloads",
        "description": "Browser may interpret files as a different MIME type, enabling attacks.",
        "fix": "Add X-Content-Type-Options: nosniff",
        "ref": "https://owasp.org/www-project-secure-headers/",
    },
    "x-frame-options": {
        "risk": "medium",
        "attack": "Clickjacking",
        "description": "Page can be embedded in an iframe, enabling clickjacking attacks.",
        "fix": "Add X-Frame-Options: DENY or SAMEORIGIN",
        "ref": "https://owasp.org/www-community/attacks/Clickjacking",
    },
    "referrer-policy": {
        "risk": "low",
        "attack": "Information leakage via Referer header",
        "description": "Full URL including query parameters may be leaked to third parties.",
        "fix": "Add Referrer-Policy: strict-origin-when-cross-origin",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "permissions-policy": {
        "risk": "low",
        "attack": "Unauthorized API access (camera, microphone, geolocation)",
        "description": "Third-party scripts can access device APIs without restriction.",
        "fix": "Add Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
}

ENTERPRISE_DOMAINS = {
    "google.com",
    "youtube.com",
    "gmail.com",
    "googleapis.com",
    "facebook.com",
    "instagram.com",
    "meta.com",
    "whatsapp.com",
    "microsoft.com",
    "outlook.com",
    "live.com",
    "office.com",
    "bing.com",
    "amazon.com",
    "aws.amazon.com",
    "apple.com",
    "icloud.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "netflix.com",
    "cloudflare.com",
    "github.com",
    "yahoo.com",
    "baidu.com",
    "tiktok.com",
}


def is_enterprise_domain(domain: str) -> str | None:
    """Check if domain belongs to a known enterprise. Returns company name or None."""
    domain = domain.lower()
    for ent in ENTERPRISE_DOMAINS:
        if domain == ent or domain.endswith("." + ent):
            return ent.split(".")[0].capitalize()
    return None


def _header_findings(result: dict) -> list:
    findings = []
    headers = result.get("headers", {})
    for h in headers.get("details", []):
        if not h.get("present"):
            info = HEADER_RISKS.get(h["header"], {})
            findings.append(
                {
                    "category": "headers",
                    "header": h["header"],
                    "severity": info.get("risk", "info"),
                    "attack_vector": info.get("attack", "unknown"),
                    "description": info.get("description", ""),
                    "remediation": info.get("fix", ""),
                    "reference": info.get("ref", ""),
                }
            )
    return findings


def _ssl_findings(result: dict) -> list:
    findings = []
    ssl = result.get("ssl", {})
    ssl_details = ssl.get("details", {})
    ssl_error = ssl.get("error")

    if ssl_error:
        if "TCP connection failed" in ssl_error:
            findings.append(
                {
                    "category": "ssl",
                    "severity": "info",
                    "attack_vector": "Network connectivity",
                    "description": "Could not connect to port 443. The server may block datacenter IPs or port 443 is closed.",
                    "remediation": "Verify the server accepts connections on port 443. This may be a network restriction, not a missing certificate.",
                    "reference": "https://letsencrypt.org/",
                }
            )
        elif "Connection reset during TLS handshake" in ssl_error:
            findings.append(
                {
                    "category": "ssl",
                    "severity": "info",
                    "attack_vector": "Network connectivity",
                    "description": "Connection was reset during TLS handshake. The server may block datacenter IPs or reject the connection.",
                    "remediation": "Verify the server accepts TLS connections. This may be a network restriction, not a missing certificate.",
                    "reference": "https://letsencrypt.org/",
                }
            )
        elif any(kw in ssl_error.lower() for kw in ("timeout", "timed out", "unreachable", "refused")):
            findings.append(
                {
                    "category": "ssl",
                    "severity": "info",
                    "attack_vector": "Network connectivity",
                    "description": f"TLS handshake failed due to network issue: {ssl_error}.",
                    "remediation": "Verify the server is reachable and accepts TLS connections on port 443.",
                    "reference": "https://letsencrypt.org/",
                }
            )
        elif "certificate" in ssl_error.lower() or "verify" in ssl_error.lower():
            findings.append(
                {
                    "category": "ssl",
                    "severity": "critical",
                    "attack_vector": "MITM, eavesdropping",
                    "description": f"TLS handshake failed: {ssl_error}. No encrypted connection possible.",
                    "remediation": "Install a valid SSL certificate from a trusted CA.",
                    "reference": "https://letsencrypt.org/",
                }
            )
        else:
            findings.append(
                {
                    "category": "ssl",
                    "severity": "medium",
                    "attack_vector": "MITM, eavesdropping",
                    "description": f"TLS handshake failed: {ssl_error}. May be a network issue or misconfigured SSL.",
                    "remediation": "Check SSL configuration and ensure a valid certificate is installed.",
                    "reference": "https://letsencrypt.org/",
                }
            )
    else:
        tls_ver = ssl_details.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1"):
            findings.append(
                {
                    "category": "ssl",
                    "severity": "high",
                    "attack_vector": "BEAST, POODLE, protocol downgrade",
                    "description": f"{tls_ver} is deprecated and vulnerable to known attacks.",
                    "remediation": "Disable TLS 1.0/1.1, enable TLS 1.2+ only.",
                    "reference": "https://www.rfc-editor.org/rfc/rfc8996",
                }
            )
        if not ssl_details.get("chain_valid"):
            findings.append(
                {
                    "category": "ssl",
                    "severity": "critical",
                    "attack_vector": "MITM, certificate impersonation",
                    "description": "Certificate chain is not trusted. May be self-signed or hostname mismatch.",
                    "remediation": "Use a certificate signed by a trusted CA matching the domain name.",
                    "reference": "https://letsencrypt.org/",
                }
            )
        if not ssl_details.get("cert_valid"):
            days = ssl_details.get("days_remaining", 0)
            if ssl_details.get("chain_valid", True):
                findings.append(
                    {
                        "category": "ssl",
                        "severity": "high" if days < 0 else "medium",
                        "attack_vector": "Browser warnings, user distrust",
                        "description": f"Certificate {'expired' if days < 0 else 'expiring soon'} ({days} days remaining).",
                        "remediation": "Renew the SSL certificate.",
                        "reference": "https://letsencrypt.org/",
                    }
                )
        cipher = ssl_details.get("cipher", "")
        if cipher and ssl_details.get("cipher_score", 0) <= 3:
            findings.append(
                {
                    "category": "ssl",
                    "severity": "medium",
                    "attack_vector": "Weak encryption, brute-force decryption",
                    "description": f"Weak cipher suite: {cipher}.",
                    "remediation": "Configure server to prefer AES-256-GCM or CHACHA20-POLY1305.",
                    "reference": "https://wiki.mozilla.org/Security/Server_Side_TLS",
                }
            )
    return findings


def _dns_findings(result: dict) -> list:
    findings = []
    dns_details = result.get("dns", {}).get("details", {})

    if not dns_details.get("spf"):
        findings.append(
            {
                "category": "dns",
                "severity": "high",
                "attack_vector": "Email spoofing, phishing",
                "description": "No SPF record. Anyone can send emails pretending to be this domain.",
                "remediation": "Add SPF TXT record: v=spf1 include:_spf.provider.com -all",
                "reference": "https://www.rfc-editor.org/rfc/rfc7208",
            }
        )
    if not dns_details.get("dmarc"):
        findings.append(
            {
                "category": "dns",
                "severity": "high",
                "attack_vector": "Email spoofing, phishing, BEC attacks",
                "description": "No DMARC record. Email receivers cannot verify sender authenticity.",
                "remediation": "Add DMARC TXT record: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com",
                "reference": "https://www.rfc-editor.org/rfc/rfc7489",
            }
        )
    if not dns_details.get("dkim"):
        findings.append(
            {
                "category": "dns",
                "severity": "medium",
                "attack_vector": "Email tampering, spoofing",
                "description": "No DKIM record found (10 common selectors checked). Email content cannot be verified.",
                "remediation": "Configure DKIM signing in your email provider and publish the public key in DNS.",
                "reference": "https://www.rfc-editor.org/rfc/rfc6376",
            }
        )
    return findings


def _redirect_findings(result: dict) -> list:
    redirect_details = result.get("redirect", {}).get("details", {})
    if not redirect_details.get("redirects_to_https"):
        return [
            {
                "category": "redirect",
                "severity": "high",
                "attack_vector": "SSL stripping, MITM",
                "description": "HTTP does not redirect to HTTPS. Users connecting via HTTP remain unencrypted.",
                "remediation": "Configure your web server to 301 redirect all HTTP traffic to HTTPS.",
                "reference": "https://owasp.org/www-project-secure-headers/",
            }
        ]
    return []


def _disclosure_findings(result: dict) -> list:
    findings = []
    disc_details = result.get("disclosure", {}).get("details", {})

    if disc_details.get("powered_by_exposed"):
        findings.append(
            {
                "category": "disclosure",
                "severity": "medium",
                "attack_vector": "Technology fingerprinting, targeted exploits",
                "description": f"X-Powered-By header exposes server technology: {disc_details.get('powered_by_value', 'unknown')}.",
                "remediation": "Remove the X-Powered-By header from server responses.",
                "reference": "https://owasp.org/www-project-secure-headers/",
            }
        )
    elif disc_details.get("server_exposed"):
        findings.append(
            {
                "category": "disclosure",
                "severity": "low",
                "attack_vector": "Server fingerprinting",
                "description": f"Server header exposes software: {disc_details.get('server_value', 'unknown')}.",
                "remediation": "Remove or obfuscate the Server header.",
                "reference": "https://owasp.org/www-project-secure-headers/",
            }
        )
    return findings


def _cookie_findings(result: dict) -> list:
    findings = []
    cookie_details = result.get("cookies", {}).get("details", {})
    cookie_count = cookie_details.get("cookies_found", 0)
    if cookie_count > 0:
        missing = []
        if not cookie_details.get("all_secure"):
            missing.append("Secure")
        if not cookie_details.get("all_httponly"):
            missing.append("HttpOnly")
        if not cookie_details.get("all_samesite"):
            missing.append("SameSite")
        if missing:
            findings.append(
                {
                    "category": "cookies",
                    "severity": "medium",
                    "attack_vector": "Session hijacking, CSRF, XSS",
                    "description": f"Cookies missing flags: {', '.join(missing)}.",
                    "remediation": "Set Secure, HttpOnly, and SameSite flags on all cookies.",
                    "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute",
                }
            )
        if cookie_details.get("samesite_none_without_secure"):
            findings.append(
                {
                    "category": "cookies",
                    "severity": "high",
                    "attack_vector": "Cross-site request forgery, session leakage",
                    "description": "SameSite=None without Secure flag. Cookie will be rejected by modern browsers or sent over insecure connections.",
                    "remediation": "Add the Secure flag to all cookies that use SameSite=None.",
                    "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                }
            )
    return findings


def _dnssec_findings(result: dict) -> list:
    dnssec_details = result.get("dnssec", {}).get("details", {})
    if not dnssec_details.get("dnssec_enabled"):
        return [
            {
                "category": "dnssec",
                "severity": "low",
                "attack_vector": "DNS cache poisoning, DNS spoofing",
                "description": "DNSSEC is not enabled. DNS responses cannot be verified as authentic.",
                "remediation": "Enable DNSSEC at your domain registrar or DNS provider.",
                "reference": "https://www.icann.org/resources/pages/dnssec-what-is-it-why-is-it-important-2019-03-05-en",
            }
        ]
    return []


def _methods_findings(result: dict) -> list:
    findings = []
    methods = result.get("methods", {})
    details = methods.get("details", {})
    if details.get("trace_enabled"):
        findings.append(
            {
                "category": "methods",
                "severity": "high",
                "attack_vector": "Cross-site tracing (XST), credential theft",
                "description": "TRACE method is enabled. Attackers can use XST to steal credentials and session tokens.",
                "remediation": "Disable the TRACE HTTP method on the web server.",
                "reference": "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
            }
        )
    if details.get("delete_enabled") or details.get("put_enabled"):
        enabled = []
        if details.get("delete_enabled"):
            enabled.append("DELETE")
        if details.get("put_enabled"):
            enabled.append("PUT")
        findings.append(
            {
                "category": "methods",
                "severity": "medium",
                "attack_vector": "Unauthorized resource modification or deletion",
                "description": f"Dangerous HTTP methods enabled: {', '.join(enabled)}. Attackers may modify or delete resources.",
                "remediation": "Disable PUT and DELETE methods unless explicitly required by the application.",
                "reference": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            }
        )
    return findings


def _cors_findings(result: dict) -> list:
    findings = []
    cors = result.get("cors", {})
    details = cors.get("details", {})
    if details.get("credentials_with_wildcard"):
        findings.append(
            {
                "category": "cors",
                "severity": "critical",
                "attack_vector": "Cross-origin credential theft, session hijacking",
                "description": "CORS allows credentials with wildcard origin. Any website can make authenticated requests and steal user data.",
                "remediation": "Never combine Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *.",
                "reference": "https://portswigger.net/web-security/cors",
            }
        )
    if details.get("reflects_origin"):
        # reflects_origin + credentials = critical (attacker reads authenticated data)
        if details.get("cors_credentials"):
            findings.append(
                {
                    "category": "cors",
                    "severity": "critical",
                    "attack_vector": "Cross-origin credential theft, session hijacking",
                    "description": "CORS reflects arbitrary Origin header with credentials allowed. Any website can make authenticated requests and steal user data.",
                    "remediation": "Never reflect the Origin header when Access-Control-Allow-Credentials is true. Whitelist specific trusted origins.",
                    "reference": "https://portswigger.net/web-security/cors",
                }
            )
        else:
            findings.append(
                {
                    "category": "cors",
                    "severity": "high",
                    "attack_vector": "Cross-origin data theft, CSRF bypass",
                    "description": "CORS reflects arbitrary Origin header. Attackers can read responses from any origin.",
                    "remediation": "Whitelist specific trusted origins instead of reflecting the Origin header.",
                    "reference": "https://portswigger.net/web-security/cors",
                }
            )
    if details.get("wildcard_origin"):
        findings.append(
            {
                "category": "cors",
                "severity": "medium",
                "attack_vector": "Cross-origin information leakage",
                "description": "CORS allows any origin (Access-Control-Allow-Origin: *). Public APIs may be acceptable, but sensitive endpoints should restrict origins.",
                "remediation": "Restrict Access-Control-Allow-Origin to trusted domains.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            }
        )
    return findings


def _html_findings(result: dict) -> list:
    findings = []
    html = result.get("html", {})
    details = html.get("details", {})
    if details.get("mixed_active", 0) > 0:
        findings.append(
            {
                "category": "html",
                "severity": "high",
                "attack_vector": "MITM, script injection via HTTP resources",
                "description": f"Active mixed content detected ({details['mixed_active']} resources). Scripts or stylesheets loaded over HTTP can be tampered with.",
                "remediation": "Load all scripts, stylesheets, and iframes over HTTPS.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            }
        )
    if details.get("mixed_passive", 0) > 0:
        findings.append(
            {
                "category": "html",
                "severity": "low",
                "attack_vector": "Content spoofing, privacy leakage",
                "description": f"Passive mixed content detected ({details['mixed_passive']} resources). Images or media loaded over HTTP.",
                "remediation": "Load all images, audio, and video over HTTPS.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            }
        )
    if details.get("inline_scripts", 0) > 5 or details.get("inline_handlers", 0) > 0:
        findings.append(
            {
                "category": "html",
                "severity": "medium",
                "attack_vector": "XSS, CSP bypass",
                "description": "Excessive inline JavaScript detected. Inline scripts weaken CSP and increase XSS attack surface.",
                "remediation": "Move inline scripts to external files and use CSP nonces or hashes.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            }
        )
    if details.get("external_scripts_no_sri", 0) > 0:
        findings.append(
            {
                "category": "html",
                "severity": "medium",
                "attack_vector": "Supply chain attack, CDN compromise",
                "description": f"External scripts without SRI ({details['external_scripts_no_sri']} resources). Compromised CDNs can inject malicious code.",
                "remediation": "Add integrity and crossorigin attributes to external script tags.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            }
        )
    if details.get("forms_http_action", 0) > 0:
        findings.append(
            {
                "category": "html",
                "severity": "high",
                "attack_vector": "Credential theft, MITM",
                "description": f"Forms submit to HTTP ({details['forms_http_action']} forms). Form data including passwords can be intercepted.",
                "remediation": "Change all form action URLs to use HTTPS.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            }
        )
    if details.get("meta_set_cookie", 0) > 0:
        findings.append(
            {
                "category": "html",
                "severity": "high",
                "attack_vector": "HttpOnly bypass, cookie theft via XSS",
                "description": 'Cookies set via <meta http-equiv="Set-Cookie">. This bypasses HttpOnly and is accessible to JavaScript.',
                "remediation": "Set cookies via HTTP Set-Cookie headers with HttpOnly flag instead.",
                "reference": "https://owasp.org/www-community/HttpOnly",
            }
        )
    if details.get("meta_refresh_http", 0) > 0:
        findings.append(
            {
                "category": "html",
                "severity": "medium",
                "attack_vector": "HTTPS bypass, session hijacking",
                "description": "Meta refresh redirects to HTTP URL. This downgrades the connection and exposes data.",
                "remediation": "Change meta refresh URLs to use HTTPS or remove meta refresh entirely.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
            }
        )
    return findings


def _csp_deep_findings(result: dict) -> list:
    findings = []
    csp = result.get("csp_analysis", {})
    details = csp.get("details", {})
    if details.get("unsafe_inline"):
        findings.append(
            {
                "category": "csp_analysis",
                "severity": "medium",
                "attack_vector": "XSS via inline script injection",
                "description": "CSP allows 'unsafe-inline'. Inline scripts and styles can execute, reducing XSS protection.",
                "remediation": "Remove 'unsafe-inline' from CSP and use nonces or hashes instead.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            }
        )
    if details.get("unsafe_eval"):
        findings.append(
            {
                "category": "csp_analysis",
                "severity": "high",
                "attack_vector": "Code injection via eval(), Function(), setTimeout(string)",
                "description": "CSP allows 'unsafe-eval'. Attackers can execute arbitrary code through eval-like functions.",
                "remediation": "Remove 'unsafe-eval' from CSP. Refactor code to avoid eval().",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            }
        )
    if details.get("wildcard_source"):
        findings.append(
            {
                "category": "csp_analysis",
                "severity": "high",
                "attack_vector": "Unrestricted resource loading, data exfiltration",
                "description": "CSP has wildcard source (*). Any domain can serve scripts, styles, or other resources.",
                "remediation": "Replace wildcard sources with specific trusted domains.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            }
        )
    if details.get("data_uri"):
        findings.append(
            {
                "category": "csp_analysis",
                "severity": "medium",
                "attack_vector": "XSS via data: URI injection",
                "description": "CSP allows data: URIs. Attackers can inject executable content via data: scheme.",
                "remediation": "Remove data: from CSP source lists where possible.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            }
        )
    return findings


def _recalculate_grade(score: int, max_score: int) -> str:
    """Calculate grade from score/max percentage (matches C scanner logic)."""
    if max_score <= 0:
        return "F"
    pct = (score * 100) // max_score
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    if pct >= 40:
        return "D"
    return "F"


def enrich_with_findings(result: dict) -> dict:
    """Add vulnerability findings and enterprise detection to scan result"""
    # Exclude SSL from scoring when TCP connection failed (not a real SSL issue)
    ssl_data = result.get("ssl", {})
    ssl_error = ssl_data.get("error", "")
    if ssl_error and ("TCP connection failed" in ssl_error or "Connection reset during TLS handshake" in ssl_error):
        ssl_score = ssl_data.get("score", 0)
        ssl_max = ssl_data.get("max", 0)
        ssl_data["score"] = 0
        ssl_data["max"] = 0
        result["ssl"] = ssl_data
        # Recalculate total_score and max_score
        if ssl_max > 0:
            result["max_score"] = result.get("max_score", 100) - ssl_max
            result["total_score"] = result.get("total_score", 0) - ssl_score
            result["grade"] = _recalculate_grade(result["total_score"], result["max_score"])

    findings = []
    findings.extend(_header_findings(result))
    findings.extend(_ssl_findings(result))
    findings.extend(_dns_findings(result))
    findings.extend(_redirect_findings(result))
    findings.extend(_disclosure_findings(result))
    findings.extend(_cookie_findings(result))
    findings.extend(_dnssec_findings(result))
    findings.extend(_methods_findings(result))
    findings.extend(_cors_findings(result))
    findings.extend(_html_findings(result))
    findings.extend(_csp_deep_findings(result))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    result["findings"] = findings
    counts = Counter(f["severity"] for f in findings)
    result["findings_count"] = {level: counts.get(level, 0) for level in SEVERITY_LEVELS}

    domain = result.get("domain", "")
    company = is_enterprise_domain(domain)
    if company:
        result["enterprise"] = {
            "is_enterprise": True,
            "company": company,
            "note": f"{company} uses a non-standard security model. "
            "Large enterprises often omit certain headers or DNS records "
            "due to custom infrastructure, CDN configurations, or scale-specific trade-offs. "
            "A lower score does not necessarily indicate poor security.",
        }

    return result
