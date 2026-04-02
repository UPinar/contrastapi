"""Domain risk scoring — calculate A-F grade from full domain report."""


def score_domain(report: dict) -> dict:
    """Score a domain report and return grade with factors."""
    score = 0
    factors = []

    # SSL (max 20)
    ssl = report.get("ssl", {})
    ssl_grade = ssl.get("grade")
    if ssl_grade == "A":
        score += 20
        factors.append({"name": "SSL/TLS", "score": 20, "max": 20, "detail": "TLS 1.3, valid certificate"})
    elif ssl_grade == "B":
        score += 14
        factors.append({"name": "SSL/TLS", "score": 14, "max": 20, "detail": "TLS 1.2 or short expiry"})
    elif ssl_grade == "C":
        score += 8
        factors.append({"name": "SSL/TLS", "score": 8, "max": 20, "detail": "Weak TLS or expiring soon"})
    elif ssl.get("error"):
        factors.append({"name": "SSL/TLS", "score": 0, "max": 20, "detail": "SSL connection failed"})
    else:
        factors.append({"name": "SSL/TLS", "score": 0, "max": 20, "detail": "Deprecated TLS or expired"})

    # Email security (max 25)
    email = report.get("email_security", {})
    email_score = 0
    if email.get("spf"):
        email_score += 10
    if email.get("dmarc"):
        email_score += 10
    if email.get("dkim_selectors"):
        email_score += 5
    score += email_score
    email_detail = []
    if email.get("spf"):
        email_detail.append("SPF")
    if email.get("dmarc"):
        email_detail.append("DMARC")
    if email.get("dkim_selectors"):
        email_detail.append("DKIM")
    factors.append(
        {
            "name": "Email Security",
            "score": email_score,
            "max": 25,
            "detail": ", ".join(email_detail) if email_detail else "No email authentication records",
        }
    )

    # WAF (max 10)
    waf = report.get("waf", {})
    if waf.get("waf_present"):
        score += 10
        factors.append(
            {"name": "WAF", "score": 10, "max": 10, "detail": f"Behind {', '.join(waf.get('detected', []))}"}
        )
    else:
        factors.append({"name": "WAF", "score": 0, "max": 10, "detail": "No WAF detected"})

    # DNS (max 15)
    dns = report.get("dns", {})
    dns_score = 0
    dns_details = []
    if dns.get("ns"):
        dns_score += 5
        dns_details.append(f"{len(dns['ns'])} nameservers")
    if dns.get("mx"):
        dns_score += 5
        dns_details.append("MX configured")
    if dns.get("a") or dns.get("aaaa"):
        dns_score += 5
        dns_details.append("A/AAAA records present")
    score += dns_score
    factors.append(
        {
            "name": "DNS",
            "score": dns_score,
            "max": 15,
            "detail": ", ".join(dns_details) if dns_details else "Incomplete DNS configuration",
        }
    )

    # WHOIS (max 10)
    whois = report.get("whois", {})
    whois_score = 0
    if not whois.get("error"):
        if whois.get("registrar"):
            whois_score += 5
        if whois.get("expiry_date") or whois.get("creation_date"):
            whois_score += 5
    score += whois_score
    factors.append(
        {
            "name": "WHOIS",
            "score": whois_score,
            "max": 10,
            "detail": f"Registered with {whois.get('registrar', 'unknown')}"
            if whois_score > 0
            else "WHOIS data unavailable",
        }
    )

    # Subdomains exposure (max 10)
    subs = report.get("subdomains", {})
    sub_count = subs.get("count", 0)
    if sub_count <= 5:
        sub_score = 10
        sub_detail = "Minimal subdomain exposure"
    elif sub_count <= 15:
        sub_score = 7
        sub_detail = f"{sub_count} subdomains (moderate exposure)"
    elif sub_count <= 30:
        sub_score = 4
        sub_detail = f"{sub_count} subdomains (high exposure)"
    else:
        sub_score = 2
        sub_detail = f"{sub_count} subdomains (very high exposure)"
    score += sub_score
    factors.append({"name": "Subdomain Exposure", "score": sub_score, "max": 10, "detail": sub_detail})

    # Certificate transparency (max 10)
    certs = report.get("certificates", {})
    cert_count = certs.get("total_certificates", 0)
    if cert_count > 0:
        score += 10
        factors.append(
            {"name": "Certificate Transparency", "score": 10, "max": 10, "detail": f"{cert_count} certificates logged"}
        )
    else:
        factors.append({"name": "Certificate Transparency", "score": 0, "max": 10, "detail": "No CT log entries"})

    # Threat intelligence (penalty, max -15)
    threat = report.get("threat", {})
    threat_urls = threat.get("url_count", 0)
    threat_online = threat.get("urls_online", 0)
    if threat_online > 0:
        penalty = min(15, threat_online * 5)
        score = max(0, score - penalty)
        factors.append(
            {
                "name": "Threat Intelligence",
                "score": -penalty,
                "max": 0,
                "detail": f"{threat_online} active malware URLs (URLhaus)",
            }
        )
    elif threat_urls > 0:
        penalty = min(5, threat_urls)
        score = max(0, score - penalty)
        factors.append(
            {
                "name": "Threat Intelligence",
                "score": -penalty,
                "max": 0,
                "detail": f"{threat_urls} historic malware URLs (URLhaus)",
            }
        )
    else:
        factors.append({"name": "Threat Intelligence", "score": 0, "max": 0, "detail": "No threats found"})

    # Reputation penalty (max -15)
    reputation = report.get("reputation", {})
    rep_penalty = 0
    rep_details = []

    abuseipdb = reputation.get("abuseipdb", {})
    if abuseipdb.get("status") == "ok":
        abuse_score = abuseipdb.get("abuse_score", 0)
        if abuse_score >= 75:
            rep_penalty += 10
            rep_details.append(f"AbuseIPDB score {abuse_score} (high)")
        elif abuse_score >= 25:
            rep_penalty += 5
            rep_details.append(f"AbuseIPDB score {abuse_score} (moderate)")

    rep_penalty = min(rep_penalty, 15)
    if rep_penalty > 0:
        score = max(0, score - rep_penalty)
        factors.append({"name": "IP Reputation", "score": -rep_penalty, "max": 0, "detail": "; ".join(rep_details)})
    elif reputation:
        has_ok = any(v.get("status") == "ok" for v in reputation.values() if isinstance(v, dict))
        detail = "No reputation issues" if has_ok else "Reputation data unavailable"
        factors.append({"name": "IP Reputation", "score": 0, "max": 0, "detail": detail})
    else:
        factors.append({"name": "IP Reputation", "score": 0, "max": 0, "detail": "Reputation data unavailable"})

    # Grade
    grade = _score_to_grade(score)

    return {
        "score": score,
        "max_score": 100,
        "grade": grade,
        "factors": factors,
    }


def _score_to_grade(score: int) -> str:
    """Convert numeric score to letter grade."""
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"
