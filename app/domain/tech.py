"""Technology fingerprinting — detect CMS, frameworks, servers, CDNs, analytics from headers + HTML."""

import re

# --- Header-based rules ---
# Each rule: name, category, header to check, regex (group 1 = version if present)

HEADER_RULES = [
    # Servers
    ("Nginx", "Server", "server", r"nginx(?:/([\d.]+))?"),
    ("Apache", "Server", "server", r"apache(?:/([\d.]+))?"),
    ("LiteSpeed", "Server", "server", r"litespeed"),
    ("Microsoft IIS", "Server", "server", r"microsoft-iis(?:/([\d.]+))?"),
    ("Caddy", "Server", "server", r"caddy"),
    ("OpenResty", "Server", "server", r"openresty(?:/([\d.]+))?"),
    ("Gunicorn", "Server", "server", r"gunicorn(?:/([\d.]+))?"),
    ("Uvicorn", "Server", "server", r"uvicorn"),
    ("Cowboy", "Server", "server", r"cowboy"),
    ("Tengine", "Server", "server", r"tengine(?:/([\d.]+))?"),
    # Language/Runtime (x-powered-by)
    ("PHP", "Language", "x-powered-by", r"php(?:/([\d.]+))?"),
    ("ASP.NET", "Language", "x-powered-by", r"asp\.net"),
    ("Express.js", "Language", "x-powered-by", r"express"),
    ("Java Servlet", "Language", "x-powered-by", r"servlet(?:/([\d.]+))?"),
    ("JSP", "Language", "x-powered-by", r"jsp(?:/([\d.]+))?"),
    ("Phusion Passenger", "Language", "x-powered-by", r"phusion passenger(?:/([\d.]+))?"),
    ("Plesk", "Language", "x-powered-by", r"plesk"),
    # ASP.NET version header
    ("ASP.NET", "Language", "x-aspnet-version", r"([\d.]+)"),
    # CDN/Proxy (from headers)
    ("Cloudflare", "CDN", "cf-ray", r".+"),
    ("AWS CloudFront", "CDN", "x-amz-cf-id", r".+"),
    ("AWS CloudFront", "CDN", "x-amz-cf-pop", r".+"),
    ("Fastly", "CDN", "x-fastly-request-id", r".+"),
    ("Akamai", "CDN", "x-akamai-transformed", r".+"),
    ("Varnish", "CDN", "x-varnish", r".+"),
    ("Sucuri", "CDN", "x-sucuri-id", r".+"),
    ("KeyCDN", "CDN", "server", r"keycdn"),
    ("Imperva", "CDN", "x-iinfo", r".+"),
    # Framework detection from headers
    ("Next.js", "Framework", "x-nextjs-cache", r".+"),
    ("Next.js", "Framework", "x-nextjs-matched-path", r".+"),
    ("Vercel", "Platform", "x-vercel-id", r".+"),
    ("Netlify", "Platform", "x-nf-request-id", r".+"),
    ("Heroku", "Platform", "via", r"vegur"),
    ("Wix", "CMS", "x-wix-request-id", r".+"),
]

# --- Cookie-based rules ---
# Each rule: name, category, cookie name pattern (regex)

COOKIE_RULES = [
    ("PHP", "Language", r"PHPSESSID"),
    ("ASP.NET", "Language", r"ASP\.NET_SessionId"),
    ("ASP.NET", "Language", r"__RequestVerificationToken"),
    ("Java", "Language", r"JSESSIONID"),
    ("Laravel", "Framework", r"laravel_session"),
    ("Django", "Framework", r"csrftoken"),
    ("Django", "Framework", r"sessionid"),
    ("Rails", "Framework", r"_[a-z]+_session"),
    ("Cloudflare", "CDN", r"__cfruid"),
    ("WordPress", "CMS", r"wordpress_logged_in"),
    ("WordPress", "CMS", r"wp-settings-"),
    ("Shopify", "CMS", r"_shopify_"),
]

# --- HTML-based rules ---
# Each rule: name, category, list of detection patterns, optional version regex

HTML_RULES = [
    # CMS
    ("WordPress", "CMS", [r"wp-content/", r"wp-includes/", r"WordPress\s*[\d.]*"], r"WordPress\s+([\d.]+)"),
    (
        "Drupal",
        "CMS",
        [r"sites/default/files", r"Drupal\.settings", r"/misc/drupal\.js"],
        r'content=["\']Drupal\s*([\d.]+)',
    ),
    ("Joomla", "CMS", [r"/media/jui/", r"/media/system/js/"], r'content=["\']Joomla!\s*([\d.]+)'),
    ("Shopify", "CMS", [r"cdn\.shopify\.com", r"Shopify\.theme"], None),
    ("Squarespace", "CMS", [r"static1\.squarespace\.com", r"squarespace-cdn\.com"], None),
    ("Wix", "CMS", [r"static\.wixstatic\.com", r"wix\.com/"], None),
    ("Ghost", "CMS", [r'content=["\']Ghost'], r'content=["\']Ghost\s*([\d.]+)'),
    ("Hugo", "CMS", [r'content=["\']Hugo'], r'content=["\']Hugo\s*([\d.]+)'),
    ("Webflow", "CMS", [r"assets\.website-files\.com", r"webflow\.com"], None),
    # JS Frameworks
    ("React", "Framework", [r"data-reactroot", r"__REACT_DEVTOOLS_", r"_reactRootContainer"], None),
    ("Next.js", "Framework", [r"__NEXT_DATA__", r"/_next/static/"], r'__NEXT_DATA__.*?"version"\s*:\s*"([\d.]+)"'),
    ("Nuxt.js", "Framework", [r"__NUXT__", r"/_nuxt/"], None),
    (
        "Angular",
        "Framework",
        [r"ng-version=[\"']([\d.]+)", r"ng-app", r"ng-controller"],
        r'ng-version=["\'](\d+[\d.]*)',
    ),
    ("Vue.js", "Framework", [r"__vue__", r"v-cloak", r"data-v-[a-f0-9]"], None),
    ("Svelte", "Framework", [r"__svelte", r'class="svelte-'], None),
    ("Gatsby", "Framework", [r"___gatsby", r"/page-data/"], None),
    ("Remix", "Framework", [r"__remixContext", r"__remixManifest"], None),
    # JS Libraries
    ("jQuery", "JavaScript", [r"jquery[.\-/][\d.]+", r"jquery\.min\.js"], r"jquery[.\-/]([\d]+(?:\.[\d]+)*)"),
    ("Bootstrap", "JavaScript", [r"bootstrap[.\-/]([\d.]+)", r"bootstrap\.min\.(js|css)"], r"bootstrap[.\-/]([\d.]+)"),
    ("Tailwind CSS", "CSS", [r"tailwindcss", r"tailwind\.min\.css"], None),
    ("Font Awesome", "JavaScript", [r"font-?awesome", r"fontawesome"], r"font-?awesome[/\-]([\d.]+)"),
    ("Lodash", "JavaScript", [r"lodash[.\-/]([\d.]+)", r"lodash\.min\.js"], r"lodash[.\-/]([\d.]+)"),
    # Analytics
    (
        "Google Analytics",
        "Analytics",
        [r"google-analytics\.com/analytics\.js", r"googletagmanager\.com/gtag/js\?id="],
        None,
    ),
    ("Google Tag Manager", "Analytics", [r"googletagmanager\.com/gtm\.js"], None),
    ("Facebook Pixel", "Analytics", [r"connect\.facebook\.net/.+/fbevents\.js"], None),
    ("Hotjar", "Analytics", [r"static\.hotjar\.com"], None),
    ("Segment", "Analytics", [r"cdn\.segment\.com/analytics"], None),
    ("Matomo", "Analytics", [r"matomo\.js", r"piwik\.js"], None),
    ("Plausible", "Analytics", [r"plausible\.io/js/"], None),
    ("Clarity", "Analytics", [r"clarity\.ms/tag/"], None),
    # Other
    ("Google Fonts", "Font", [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"], None),
    ("reCAPTCHA", "Security", [r"google\.com/recaptcha", r"gstatic\.com/recaptcha"], None),
    ("hCaptcha", "Security", [r"hcaptcha\.com"], None),
    ("Turbolinks", "JavaScript", [r"turbolinks", r"data-turbolinks-track"], None),
    ("HTMX", "JavaScript", [r"htmx\.org", r"hx-get", r"hx-post"], r"htmx\.org@([\d.]+)"),
    ("Alpine.js", "JavaScript", [r"alpinejs", r"\bx-data\s*=", r"\bx-bind\s*:"], None),
]


def detect_technologies(headers: dict, html: str | None = None) -> dict:
    """Identify technologies from HTTP headers, cookies, and HTML content.

    Args:
        headers: Lowercased HTTP response headers dict.
        html: First 64KB of HTML body (optional).

    Returns:
        Dict with technologies list, categories, count, and summary.
    """
    seen = set()
    techs = []

    def _add(name, version, category, source):
        key = (name, category)
        if key not in seen:
            seen.add(key)
            entry = {"name": name, "category": category, "source": source}
            if version:
                entry["version"] = version
            techs.append(entry)

    # Headers
    for name, category, header, regex in HEADER_RULES:
        val = headers.get(header, "")
        if val:
            m = re.search(regex, val, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                _add(name, version, category, "header")

    # Cookies
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        for name, category, pattern in COOKIE_RULES:
            if re.search(pattern, set_cookie, re.IGNORECASE):
                _add(name, None, category, "cookie")

    # HTML
    if html:
        for name, category, patterns, version_regex in HTML_RULES:
            matched = False
            for p in patterns:
                if re.search(p, html, re.IGNORECASE):
                    matched = True
                    break
            if matched:
                version = None
                if version_regex:
                    vm = re.search(version_regex, html, re.IGNORECASE)
                    if vm:
                        version = vm.group(1)
                _add(name, version, category, "html")

    # Build categories dict
    categories = {}
    for t in techs:
        cat = t["category"]
        label = f"{t['name']} {t.get('version', '')}".strip()
        categories.setdefault(cat, []).append(label)

    # Summary
    if techs:
        labels = []
        for t in techs[:10]:
            label = t["name"]
            if t.get("version"):
                label += f" {t['version']}"
            labels.append(label)
        suffix = f"... (+{len(techs) - 10} more)" if len(techs) > 10 else ""
        summary = f"{len(techs)} technologies detected: {', '.join(labels)}{suffix}"
    else:
        summary = "No technologies detected"

    return {
        "technologies": techs,
        "categories": categories,
        "count": len(techs),
        "summary": summary,
    }
