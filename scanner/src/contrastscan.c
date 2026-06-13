#define _GNU_SOURCE  /* for strcasestr */

/*
 * contrastscan — Unified Security Scanner
 *
 * Combines 11 modules in a single binary:
 *   1. HTTP Security Headers (25 pts)
 *   2. SSL/TLS Check (20 pts)
 *   3. DNS Security (15 pts)
 *   4. HTTPS Redirect (8 pts)
 *   5. Information Disclosure (5 pts)
 *   6. Cookie Security (5 pts)
 *   7. DNSSEC (5 pts)
 *   8. HTTP Methods (5 pts)
 *   9. CORS (5 pts)
 *  10. HTML Analysis (5 pts)
 *  11. CSP Deep Analysis (2 pts)
 *
 * Total: 100 points → A-F grade
 * Output: single JSON object
 *
 * Libraries used:
 *   libcurl   — HTTP header fetching
 *   openssl   — TLS handshake + certificate
 *   libresolv — DNS TXT queries
 *   cJSON     — JSON output
 */

#include <stdio.h>       // printf, fprintf, snprintf
#include <stdlib.h>       // EXIT_SUCCESS, EXIT_FAILURE, free
#include <string.h>       // strcmp, strstr, strncasecmp, memset, memcpy, strlen
#include <unistd.h>       // close
#include <netdb.h>        // getaddrinfo, freeaddrinfo
#include <sys/socket.h>   // socket, connect
#include <curl/curl.h>    // curl_easy_init, curl_easy_setopt, curl_easy_perform
#include <openssl/ssl.h>  // SSL_*, TLS_client_method
#include <openssl/x509.h> // X509_*, ASN1_TIME_*
#include <openssl/err.h>  // ERR_*
#include <arpa/inet.h>    // inet_pton
#include <arpa/nameser.h> // ns_initparse, ns_parserr, NS_PACKETSZ
#include <resolv.h>       // res_query
#include <cjson/cJSON.h>  // cJSON_*
#include <time.h>         // time, difftime, gmtime_r

#include "../include/csp_util.h"  // csp_has_keyword, count_script_data_blocks

/* ============================
 *  SCORE CONSTANTS
 * ============================ */

#define HEADERS_MAX    25
#define SSL_MAX        20
#define DNS_MAX        15
#define REDIRECT_MAX    8
#define DISCLOSURE_MAX  5
#define COOKIES_MAX     5
#define DNSSEC_MAX      5
#define METHODS_MAX     5
#define CORS_MAX        5
#define HTML_MAX        5
#define CSP_DEEP_MAX    2
#define TOTAL_MAX     100

/* SSL sub-scores (7+7+6=20) */
#define TLS_SCORE_13     7
#define TLS_SCORE_12     5
#define TLS_SCORE_11     2
#define CERT_SCORE_GOOD  7
#define CERT_SCORE_WARN  4
#define CERT_SCORE_CRIT  2
#define CIPHER_SCORE_STRONG 6
#define CIPHER_SCORE_OK     4
#define CIPHER_SCORE_WEAK   2

/* Header sub-score */
#define HEADER_PER_SCORE   4
#define HEADER_ALL_BONUS   1

/* DNS sub-scores (5+5+5=15) */
#define SPF_SCORE    5
#define DMARC_SCORE  5
#define DKIM_SCORE   5

#define TLS_CONNECT_TIMEOUT 5
#define HTTP_TIMEOUT        7
#define URL_BUFFER_SIZE   512
#define HEADER_VALUE_SIZE 256
#define COOKIE_LINE_SIZE 2048
#define DNS_ANSWER_SIZE  4096
#define DNS_DOMAIN_SIZE  512

/* Browser impersonation — Chrome 116 (matches curl-impersonate target) */
#define BROWSER_UA \
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
  "(KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"

/* resolved IP from Python validator (SSRF rebinding protection) */
static const char *g_resolved_ip = NULL;

/*
 * safe_cjson_object / safe_cjson_array — NULL-safe cJSON constructors.
 * On OOM, cJSON_Create* returns NULL → any subsequent cJSON_Add* segfaults.
 * Exit cleanly with an error message instead of crashing.
 */
static cJSON *safe_cjson_object(void)
{
  cJSON *obj = cJSON_CreateObject();
  if (!obj) {
    fprintf(stderr, "contrastscan: out of memory (cJSON_CreateObject)\n");
    exit(EXIT_FAILURE);
  }
  return obj;
}

static cJSON *safe_cjson_array(void)
{
  cJSON *arr = cJSON_CreateArray();
  if (!arr) {
    fprintf(stderr, "contrastscan: out of memory (cJSON_CreateArray)\n");
    exit(EXIT_FAILURE);
  }
  return arr;
}

/*
 * make_resolve_list — create curl_slist for CURLOPT_RESOLVE
 *
 * @in  domain — target domain
 * @return     — slist with "domain:443:ip" and "domain:80:ip", or NULL
 *
 * Pins DNS resolution to the pre-validated IP, preventing
 * TOCTOU DNS rebinding attacks between Python and C.
 *
 * SSRF TRIPWIRE — the pin covers ONLY the original `domain:443/80`. Two modules
 * set CURLOPT_FOLLOWLOCATION=1 (REDIR_PROTOCOLS restricted to https), and a
 * redirect to a *different* host is NOT in this list, so curl resolves it fresh
 * and unpinned. Today the only thing stopping a redirect to an internal host is
 * curl's DEFAULT TLS verification (the redirect target must present a publicly
 * trusted cert for its hostname). THEREFORE: do NOT set CURLOPT_SSL_VERIFYPEER/
 * VERIFYHOST to 0 anywhere — doing so converts the redirect path into a full
 * SSRF (banner/header exfil from internal TLS services). Proper fix when this
 * is hardened: re-validate every redirect hop's peer IP against is_private_ip
 * (PREREQFUNCTION/OPENSOCKETFUNCTION) or disable FOLLOWLOCATION and walk hops here.
 */
static struct curl_slist *make_resolve_list(const char *domain)
{
  if (!g_resolved_ip) return NULL;

  char entry443[512], entry80[512];
  snprintf(entry443, sizeof(entry443), "%s:443:%s", domain, g_resolved_ip);
  snprintf(entry80, sizeof(entry80), "%s:80:%s", domain, g_resolved_ip);

  struct curl_slist *list = NULL;
  list = curl_slist_append(list, entry443);
  list = curl_slist_append(list, entry80);
  return list;
}

/*
 * make_browser_headers — realistic Chrome headers for WAF bypass
 *
 * Returns curl_slist with browser-like headers. Caller must free with
 * curl_slist_free_all(). Pass existing list to append (e.g. CORS Origin).
 */
static struct curl_slist *make_browser_headers(struct curl_slist *base)
{
  struct curl_slist *h = base;
  h = curl_slist_append(h, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
  h = curl_slist_append(h, "Accept-Language: en-US,en;q=0.5");
  h = curl_slist_append(h, "Sec-Fetch-Dest: document");
  h = curl_slist_append(h, "Sec-Fetch-Mode: navigate");
  h = curl_slist_append(h, "Sec-Fetch-Site: none");
  h = curl_slist_append(h, "Sec-Fetch-User: ?1");
  h = curl_slist_append(h, "Upgrade-Insecure-Requests: 1");
  return h;
}

/*
 * setup_curl_browser — apply browser impersonation to a curl handle
 *
 * Sets User-Agent, browser headers, HTTP/2, and auto-decompression.
 * For curl-impersonate builds, also applies Chrome TLS fingerprint.
 */
static void setup_curl_browser(CURL *curl, struct curl_slist *headers)
{
  curl_easy_setopt(curl, CURLOPT_USERAGENT, BROWSER_UA);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
#ifdef HAVE_CURL_IMPERSONATE
  extern CURLcode curl_easy_impersonate(CURL *curl, const char *target, int default_headers);
  curl_easy_impersonate(curl, "chrome116", 0);
#endif
}

/* ============================
 *  1. HTTP SECURITY HEADERS
 * ============================ */

static const char *security_headers[] = {
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy"
};
#define NUM_HEADERS 6

static int hdr_found[NUM_HEADERS] = {0};

/* disclosure tracking — Server and X-Powered-By headers */
static char server_header[HEADER_VALUE_SIZE] = "";
static char powered_by_header[HEADER_VALUE_SIZE] = "";

/* cookie tracking — Set-Cookie flags */
#define MAX_COOKIES 16
static int cookie_count = 0;
static int cookie_has_secure[MAX_COOKIES];
static int cookie_has_httponly[MAX_COOKIES];
static int cookie_has_samesite[MAX_COOKIES];
static int cookie_samesite_none_no_secure[MAX_COOKIES];

/* CSP value tracking */
static char csp_value[4096] = "";

/* CORS tracking */
static char cors_acao[512] = "";
static int cors_credentials = 0;

/* HTML body storage */
#define HTML_BODY_MAX (256 * 1024)
#define MAX_REDIRECTS 5
static char html_body[HTML_BODY_MAX];
static size_t html_body_len = 0;

/* HTTP methods tracking */
static char allow_header[512] = "";

/*
 * header_callback — libcurl calls this for each HTTP header line
 *
 * @in  buffer   — header line ("Strict-Transport-Security: max-age=...\r\n")
 * @in  size     — always 1 (libcurl guarantee)
 * @in  nitems   — number of bytes in buffer
 * @in  userdata — not used (NULL)
 * @out          — updates hdr_found[], server_header, powered_by_header, cookie arrays
 * @return       — size * nitems (tells libcurl "processed all bytes")
 */
static size_t header_callback(char *buffer, size_t size, size_t nitems,
                              void *userdata)
{
  (void)userdata;
  size_t total = size * nitems;

  /* security headers */
  for (int i = 0; i < NUM_HEADERS; i++)
  {
    size_t len = strlen(security_headers[i]);
    if (total > len + 1 &&
        strncasecmp(buffer, security_headers[i], len) == 0 &&
        buffer[len] == ':')
    {
      hdr_found[i] = 1;
    }
  }

  /* Server header (information disclosure) */
  if (total > 7 && strncasecmp(buffer, "server:", 7) == 0)
  {
    size_t vlen = total - 7;
    if (vlen >= sizeof(server_header))
      vlen = sizeof(server_header) - 1;
    memcpy(server_header, buffer + 7, vlen);
    server_header[vlen] = '\0';
    /* trim whitespace and \r\n */
    char *p = server_header;
    while (*p == ' ') p++;
    memmove(server_header, p, strlen(p) + 1);
    size_t slen = strlen(server_header);
    while (slen > 0 && (server_header[slen-1] == '\r' || server_header[slen-1] == '\n'))
      server_header[--slen] = '\0';
  }

  /* X-Powered-By header (information disclosure) */
  if (total > 13 && strncasecmp(buffer, "x-powered-by:", 13) == 0)
  {
    size_t vlen = total - 13;
    if (vlen >= sizeof(powered_by_header))
      vlen = sizeof(powered_by_header) - 1;
    memcpy(powered_by_header, buffer + 13, vlen);
    powered_by_header[vlen] = '\0';
    char *p = powered_by_header;
    while (*p == ' ') p++;
    memmove(powered_by_header, p, strlen(p) + 1);
    size_t slen = strlen(powered_by_header);
    while (slen > 0 && (powered_by_header[slen-1] == '\r' || powered_by_header[slen-1] == '\n'))
      powered_by_header[--slen] = '\0';
  }

  /* Set-Cookie header (cookie security) */
  if (total > 11 && strncasecmp(buffer, "set-cookie:", 11) == 0 &&
      cookie_count < MAX_COOKIES)
  {
    /* case-insensitive search for flags in the cookie line */
    char lower[COOKIE_LINE_SIZE];
    size_t clen = total < sizeof(lower) - 1 ? total : sizeof(lower) - 1;
    for (size_t i = 0; i < clen; i++)
      lower[i] = (buffer[i] >= 'A' && buffer[i] <= 'Z') ? buffer[i] + 32 : buffer[i];
    lower[clen] = '\0';

    cookie_has_secure[cookie_count] = (strstr(lower, "; secure") || strstr(lower, ";secure")) ? 1 : 0;
    cookie_has_httponly[cookie_count] = (strstr(lower, "; httponly") || strstr(lower, ";httponly")) ? 1 : 0;
    cookie_has_samesite[cookie_count] = (strstr(lower, "; samesite") || strstr(lower, ";samesite")) ? 1 : 0;
    /* check SameSite=None without Secure */
    int has_none = (strstr(lower, "samesite=none") != NULL);
    cookie_samesite_none_no_secure[cookie_count] = (has_none && !cookie_has_secure[cookie_count]) ? 1 : 0;
    cookie_count++;
  }

  /* capture CSP value for deep analysis */
  if (total > 26 && strncasecmp(buffer, "content-security-policy:", 24) == 0)
  {
    size_t vlen = total - 24;
    if (vlen >= sizeof(csp_value)) vlen = sizeof(csp_value) - 1;
    memcpy(csp_value, buffer + 24, vlen);
    csp_value[vlen] = '\0';
    /* trim */
    char *p = csp_value;
    while (*p == ' ') p++;
    memmove(csp_value, p, strlen(p) + 1);
    size_t slen = strlen(csp_value);
    while (slen > 0 && (csp_value[slen-1] == '\r' || csp_value[slen-1] == '\n'))
      csp_value[--slen] = '\0';
  }

  return total;
}

/*
 * scan_headers — send HTTPS HEAD request to domain, check 6 security headers
 *
 * @in  domain — target domain (e.g. "example.com")
 * @return     — cJSON object: {score: 0-25, max: 25, details: [{header, present}]}
 *
 * Scoring: found_header_count × 4, all 6 found → +1 bonus
 *   0 headers → 0pt, 1 → 4pt, 2 → 8pt, 3 → 12pt, 4 → 16pt, 5 → 20pt, 6 → 25pt
 *
 * Edge cases:
 *   - domain NULL → NULL passed to snprintf → undefined behavior
 *   - curl_easy_init NULL → ok=0, score=0
 *   - connection failed → ok=0, score=0
 *   - redirect → FOLLOWLOCATION follows it
 *   - 10 second timeout
 */
static cJSON *scan_headers(const char *domain)
{
  /* reset all header tracking */
  memset(hdr_found, 0, sizeof(hdr_found));
  server_header[0] = '\0';
  powered_by_header[0] = '\0';
  cookie_count = 0;
  memset(cookie_has_secure, 0, sizeof(cookie_has_secure));
  memset(cookie_has_httponly, 0, sizeof(cookie_has_httponly));
  memset(cookie_has_samesite, 0, sizeof(cookie_has_samesite));
  memset(cookie_samesite_none_no_secure, 0, sizeof(cookie_samesite_none_no_secure));
  csp_value[0] = '\0';

  char url[URL_BUFFER_SIZE];
  snprintf(url, sizeof(url), "https://%s", domain);

  CURL *curl = curl_easy_init();
  struct curl_slist *resolve_list = make_resolve_list(domain);
  struct curl_slist *browser_hdrs = make_browser_headers(NULL);
  int ok = 0;
  if (curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, (long)MAX_REDIRECTS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)HTTP_TIMEOUT);
    setup_curl_browser(curl, browser_hdrs);
    if (resolve_list)
      curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    ok = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
  }
  if (resolve_list) curl_slist_free_all(resolve_list);
  if (browser_hdrs) curl_slist_free_all(browser_hdrs);

  int found_count = 0;
  for (int i = 0; i < NUM_HEADERS; i++)
    if (hdr_found[i])
      found_count++;

  int score = ok ? found_count * HEADER_PER_SCORE + (found_count == NUM_HEADERS ? HEADER_ALL_BONUS : 0) : 0;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", HEADERS_MAX);

  cJSON *details = safe_cjson_array();
  for (int i = 0; i < NUM_HEADERS; i++)
  {
    cJSON *item = safe_cjson_object();
    cJSON_AddStringToObject(item, "header", security_headers[i]);
    cJSON_AddBoolToObject(item, "present", hdr_found[i]);
    cJSON_AddItemToArray(details, item);
  }
  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  4. HTTPS REDIRECT CHECK
 * ============================ */

/*
 * scan_redirect — check if HTTP redirects to HTTPS
 *
 * @in  domain — target domain
 * @return     — cJSON object: {score: 0-8, max: 8, details: {redirects_to_https}}
 *
 * Scoring: redirects to HTTPS → 8, no redirect → 0
 */
static cJSON *scan_redirect(const char *domain)
{
  char url[URL_BUFFER_SIZE];
  snprintf(url, sizeof(url), "http://%s", domain);

  int redirects_to_https = 0;
  CURL *curl = curl_easy_init();
  struct curl_slist *resolve_list = make_resolve_list(domain);
  struct curl_slist *browser_hdrs = make_browser_headers(NULL);
  if (curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);  /* don't follow */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)HTTP_TIMEOUT);
    setup_curl_browser(curl, browser_hdrs);
    if (resolve_list)
      curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);

    if (curl_easy_perform(curl) == CURLE_OK)
    {
      long http_code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

      char *redirect_url = NULL;
      curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);

      if ((http_code == 301 || http_code == 302 || http_code == 307 || http_code == 308) &&
          redirect_url && strncasecmp(redirect_url, "https://", 8) == 0)
      {
        redirects_to_https = 1;
      }
    }
    curl_easy_cleanup(curl);
  }
  if (resolve_list) curl_slist_free_all(resolve_list);
  if (browser_hdrs) curl_slist_free_all(browser_hdrs);

  int score = redirects_to_https ? REDIRECT_MAX : 0;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", REDIRECT_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddBoolToObject(details, "redirects_to_https", redirects_to_https);
  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  5. INFORMATION DISCLOSURE
 * ============================ */

/*
 * scan_disclosure — check if server leaks version info
 *
 * @return — cJSON object: {score: 0-5, max: 5, details: {server_exposed, powered_by_exposed}}
 *
 * Must be called AFTER scan_headers() (uses global server_header, powered_by_header)
 *
 * Scoring: nothing exposed → 5, server only (non-CDN) → 2, powered_by or both → 0
 */
static cJSON *scan_disclosure(void)
{
  int server_exposed = (server_header[0] != '\0') ? 1 : 0;
  int powered_by_exposed = (powered_by_header[0] != '\0') ? 1 : 0;

  /* CDN/proxy/bare server names without version — not a real risk */
  int server_is_cdn = 0;
  if (server_exposed)
  {
    const char *cdn_names[] = {"cloudflare", "fastly", "akamai", "varnish",
                                "cloudfront", "vercel", "netlify", "nginx",
                                "apache", "lighttpd", "litespeed", NULL};
    char lower[256];
    size_t slen = strlen(server_header);
    if (slen >= sizeof(lower)) slen = sizeof(lower) - 1;
    for (size_t i = 0; i < slen; i++)
      lower[i] = (server_header[i] >= 'A' && server_header[i] <= 'Z')
                 ? server_header[i] + 32 : server_header[i];
    lower[slen] = '\0';

    for (int i = 0; cdn_names[i]; i++)
      if (strstr(lower, cdn_names[i]) && !strchr(lower, '/'))
        { server_is_cdn = 1; break; }
  }

  int score = DISCLOSURE_MAX;
  if (powered_by_exposed)
    score = 0;
  else if (server_exposed && !server_is_cdn)
    score = 2;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", DISCLOSURE_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddBoolToObject(details, "server_exposed", server_exposed);
  if (server_exposed)
    cJSON_AddStringToObject(details, "server_value", server_header);
  cJSON_AddBoolToObject(details, "powered_by_exposed", powered_by_exposed);
  if (powered_by_exposed)
    cJSON_AddStringToObject(details, "powered_by_value", powered_by_header);
  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  6. COOKIE SECURITY
 * ============================ */

/*
 * scan_cookies — check Set-Cookie flags (Secure, HttpOnly, SameSite)
 *
 * @return — cJSON object: {score: 0-5, max: 5, details: {cookies_found, ...}}
 *
 * Must be called AFTER scan_headers() (uses global cookie arrays)
 *
 * Scoring: no cookies → 5 (nothing to protect), all flags present → 5,
 *          partial flags → proportional, no flags → 0
 */
static cJSON *scan_cookies(void)
{
  int score;

  if (cookie_count == 0)
  {
    /* no cookies set — full score (no risk) */
    score = COOKIES_MAX;
  }
  else
  {
    /* count total flags across all cookies (3 flags per cookie) */
    int total_flags = 0;
    int max_flags = cookie_count * 3;
    for (int i = 0; i < cookie_count; i++)
    {
      total_flags += cookie_has_secure[i];
      total_flags += cookie_has_httponly[i];
      total_flags += cookie_has_samesite[i];
    }
    score = (total_flags * COOKIES_MAX) / max_flags;
  }

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", COOKIES_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddNumberToObject(details, "cookies_found", cookie_count);

  if (cookie_count > 0)
  {
    int all_secure = 1, all_httponly = 1, all_samesite = 1;
    for (int i = 0; i < cookie_count; i++)
    {
      if (!cookie_has_secure[i]) all_secure = 0;
      if (!cookie_has_httponly[i]) all_httponly = 0;
      if (!cookie_has_samesite[i]) all_samesite = 0;
    }
    cJSON_AddBoolToObject(details, "all_secure", all_secure);
    cJSON_AddBoolToObject(details, "all_httponly", all_httponly);
    cJSON_AddBoolToObject(details, "all_samesite", all_samesite);
    int any_none_no_secure = 0;
    for (int i = 0; i < cookie_count; i++)
      if (cookie_samesite_none_no_secure[i]) any_none_no_secure = 1;
    cJSON_AddBoolToObject(details, "samesite_none_without_secure", any_none_no_secure);
  }

  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  2. SSL/TLS CHECK
 * ============================ */

/*
 * tcp_connect — open TCP connection to domain:port
 *
 * @in  host — target hostname or IP
 * @in  port — target port string ("443")
 * @return   — socket file descriptor (>= 0 success), -1 (error)
 *
 * Edge cases:
 *   - host NULL → getaddrinfo fail → -1
 *   - port NULL → getaddrinfo fail → -1
 *   - DNS cannot resolve → getaddrinfo fail → -1
 *   - connect fails for all IPs → -1 (each socket is closed)
 *   - IPv6 address → supported via AF_UNSPEC (tries both IPv4 and IPv6)
 *   - no timeout → depends on OS connect default (~75s)
 */
static int tcp_connect(const char *host, const char *port)
{
  struct addrinfo hints, *res, *p;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port, &hints, &res) != 0)
    return -1;

  int sockfd = -1;
  for (p = res; p != NULL; p = p->ai_next)
  {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd < 0)
      continue;
    /* 5 second connect + recv timeout */
    struct timeval tv = {.tv_sec = TLS_CONNECT_TIMEOUT, .tv_usec = 0};
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0)
      break;
    close(sockfd);
    sockfd = -1;
  }

  freeaddrinfo(res);
  return sockfd;
}

/*
 * scan_ssl — perform TLS handshake, check version + cipher + certificate
 *
 * @in  domain — target domain (also used for SNI)
 * @return     — cJSON object: {score: 0-20, max: 20, details: {tls_version, cipher, cert_valid, ...}}
 *               on error: {score: 0, max: 20, error: "..."}
 *
 * Scoring (7+7+6 = 20):
 *   TLS version:  1.3→7, 1.2→5, 1.1→2, 1.0→0
 *   Certificate:  >30d→7, >7d→4, >0d→2, expired→0
 *   Cipher:       AES-256/CHACHA20→6, AES-128→4, other→2, NULL→0
 *
 * Edge cases:
 *   - domain NULL → getaddrinfo crash
 *   - port 443 closed → TCP fail → {score:0, error}
 *   - self-signed cert → cert_valid=1 (only expiry check, chain not verified)
 *   - expired cert → cert_valid=0, days_remaining negative
 *   - no cert (client auth only) → cert NULL → cert_score=0
 *   - unknown cipher → cipher_score=3
 */
static cJSON *scan_ssl(const char *domain)
{
  cJSON *obj = safe_cjson_object();

  /* OpenSSL 1.1.0+ auto-initializes, no need for SSL_library_init() */

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx)
  {
    cJSON_AddNumberToObject(obj, "score", 0);
    cJSON_AddNumberToObject(obj, "max", SSL_MAX);
    cJSON_AddStringToObject(obj, "error", "SSL_CTX_new failed");
    return obj;
  }

  /* load system CA certificates for chain verification */
  SSL_CTX_set_default_verify_paths(ctx);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  /* Require pinned IP to prevent DNS rebinding TOCTOU — never fall back to domain */
  if (!g_resolved_ip || g_resolved_ip[0] == '\0')
  {
    SSL_CTX_free(ctx);
    cJSON_AddStringToObject(obj, "error", "No resolved IP provided — DNS rebinding risk");
    return obj;
  }
  int sockfd = tcp_connect(g_resolved_ip, "443");
  if (sockfd < 0)
  {
    /* Retry once after 1 second — transient failures under load */
    usleep(1000000);
    sockfd = tcp_connect(g_resolved_ip, "443");
  }
  if (sockfd < 0)
  {
    SSL_CTX_free(ctx);
    cJSON_AddNumberToObject(obj, "score", 0);
    cJSON_AddNumberToObject(obj, "max", SSL_MAX);
    cJSON_AddStringToObject(obj, "error", "TCP connection failed");
    return obj;
  }

  SSL *ssl = SSL_new(ctx);
  if (!ssl)
  {
    close(sockfd);
    SSL_CTX_free(ctx);
    cJSON_AddNumberToObject(obj, "score", 0);
    cJSON_AddNumberToObject(obj, "max", SSL_MAX);
    cJSON_AddStringToObject(obj, "error", "SSL_new failed");
    return obj;
  }
  SSL_set_fd(ssl, sockfd);
  SSL_set_tlsext_host_name(ssl, domain);

  /* verify hostname matches certificate CN/SAN */
  SSL_set1_host(ssl, domain);

  ERR_clear_error(); /* clear stale errors from prior scans */
  if (SSL_connect(ssl) <= 0)
  {
    int ssl_err = SSL_get_error(ssl, 0);
    const char *reason = ERR_reason_error_string(ERR_get_error());
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    cJSON_AddNumberToObject(obj, "score", 0);
    cJSON_AddNumberToObject(obj, "max", SSL_MAX);
    if (ssl_err == SSL_ERROR_SYSCALL)
      cJSON_AddStringToObject(obj, "error", "Connection reset during TLS handshake");
    else if (reason)
    {
      char errbuf[256];
      snprintf(errbuf, sizeof(errbuf), "TLS handshake failed: %s", reason);
      cJSON_AddStringToObject(obj, "error", errbuf);
    }
    else
      cJSON_AddStringToObject(obj, "error", "TLS handshake failed");
    return obj;
  }

  const char *tls_version = SSL_get_version(ssl);
  const char *cipher = SSL_get_cipher_name(ssl);

  /* certificate chain verification result */
  long verify_result = SSL_get_verify_result(ssl);
  int chain_valid = (verify_result == X509_V_OK) ? 1 : 0;

  X509 *cert = SSL_get1_peer_certificate(ssl);
  int cert_valid = 0;
  int days_remaining = 0;
  if (cert)
  {
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    int day = 0, sec = 0;
    if (ASN1_TIME_diff(&day, &sec, NULL, not_after))
      days_remaining = day;
    cert_valid = (days_remaining > 0 && chain_valid) ? 1 : 0;
    X509_free(cert);
  }

  int tls_score = 0;
  if (strcmp(tls_version, "TLSv1.3") == 0)
    tls_score = TLS_SCORE_13;
  else if (strcmp(tls_version, "TLSv1.2") == 0)
    tls_score = TLS_SCORE_12;
  else if (strcmp(tls_version, "TLSv1.1") == 0)
    tls_score = TLS_SCORE_11;

  int cert_score = 0;
  if (cert_valid && days_remaining > 30)
    cert_score = CERT_SCORE_GOOD;
  else if (cert_valid && days_remaining > 7)
    cert_score = CERT_SCORE_WARN;
  else if (cert_valid)
    cert_score = CERT_SCORE_CRIT;

  int cipher_score = 0;
  if (cipher)
  {
    if (strstr(cipher, "AES256") || strstr(cipher, "AES_256") ||
        strstr(cipher, "CHACHA20"))
      cipher_score = CIPHER_SCORE_STRONG;
    else if (strstr(cipher, "AES128") || strstr(cipher, "AES_128"))
      cipher_score = CIPHER_SCORE_OK;
    else
      cipher_score = CIPHER_SCORE_WEAK;
  }

  int score = tls_score + cert_score + cipher_score;

  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", SSL_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddStringToObject(details, "tls_version", tls_version);
  cJSON_AddNumberToObject(details, "tls_score", tls_score);
  cJSON_AddStringToObject(details, "cipher", cipher ? cipher : "unknown");
  cJSON_AddNumberToObject(details, "cipher_score", cipher_score);
  cJSON_AddBoolToObject(details, "cert_valid", cert_valid);
  cJSON_AddBoolToObject(details, "chain_valid", chain_valid);
  cJSON_AddNumberToObject(details, "days_remaining", days_remaining);
  cJSON_AddNumberToObject(details, "cert_score", cert_score);
  cJSON_AddItemToObject(obj, "details", details);

  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sockfd);
  SSL_CTX_free(ctx);

  return obj;
}

/* ============================
 *  3. DNS SECURITY
 * ============================ */

static const char *dkim_selectors[] = {
  "google", "default", "selector1", "selector2",
  "k1", "k2", "mail", "dkim", "s1", "s2", "smtp",
  "mta", "key1", "key2", "mx", "email",
  "fm1", "fm2", "fm3",                /* Fastmail */
  "protonmail", "protonmail2", "protonmail3",  /* Proton */
  "s1024", "s2048",                    /* Yahoo */
  "ses",                               /* Amazon SES */
  "zoho",                              /* Zoho */
  NULL
};

/* MX-to-DKIM selector mapping — provider detection from MX hostname */
struct mx_dkim_map {
  const char *mx_pattern;      /* substring to match in MX hostname */
  const char *selectors[4];    /* provider-specific selectors to try */
};

static const struct mx_dkim_map mx_dkim_table[] = {
  {"google",        {"google", NULL}},  /* also uses date-based (20YYMMDD) */
  {"outlook",       {"selector1", "selector2", NULL}},
  {"protection.outlook", {"selector1", "selector2", NULL}},
  {"zoho",          {"zoho", "default", NULL}},
  {"infomaniak",    {NULL}},           /* date-based only */
  {"protonmail",    {"protonmail", "protonmail2", "protonmail3", NULL}},
  {"fastmail",      {"fm1", "fm2", "fm3", NULL}},
  {"messagingengine", {"fm1", "fm2", "fm3", NULL}}, /* Fastmail MX */
  {"yahoo",         {"s1024", "s2048", NULL}},
  {"amazonses",     {"ses", NULL}},    /* Amazon SES: <hash>.dkim.amazonses.com */
  {"mailgun",       {"smtp", "k1", NULL}},
  {"sendgrid",      {"s1", "s2", NULL}},
  {"mimecast",      {"mimecast", NULL}},
  {"barracuda",     {"barracuda", NULL}},
  {"messagelabs",   {"messagelabs", NULL}},
  {"pphosted",      {"s1", "s2", NULL}}, /* Proofpoint */
  {NULL,            {NULL}}
};

/*
 * generate_date_selectors — generate YYYYMMDD selectors for recent months
 * Some providers (Infomaniak, Google Workspace) use date-based selectors
 */
/*
 * generate_date_selectors — try YYYYMMDD for each day in current month
 * + 1st and 15th of each month for last 2 years
 * Infomaniak, Google Workspace use date-based selectors
 */
#define MAX_DATE_SELECTORS 90
#define DKIM_MAX_QUERIES 40
static char date_sel_buf[MAX_DATE_SELECTORS][32];
static const char *date_selectors[MAX_DATE_SELECTORS + 1];

static void init_dns_resolver(void)
{
  /* use Cloudflare + Google DNS directly (systemd-resolved blocks DNSKEY) */
  res_init();
  _res.retrans = 1;
  _res.retry = 1;
  _res.nscount = 2;
  _res.nsaddr_list[0].sin_family = AF_INET;
  _res.nsaddr_list[0].sin_port = htons(53);
  inet_pton(AF_INET, "1.1.1.1", &_res.nsaddr_list[0].sin_addr);
  _res.nsaddr_list[1].sin_family = AF_INET;
  _res.nsaddr_list[1].sin_port = htons(53);
  inet_pton(AF_INET, "8.8.8.8", &_res.nsaddr_list[1].sin_addr);
}

static void generate_date_selectors(void)
{
  time_t now = time(NULL);
  int count = 0;

  /* last 90 days — covers monthly rotators (Infomaniak), quarterly (Google Workspace) */
  for (int d = 0; d < MAX_DATE_SELECTORS; d++)
  {
    time_t t = now - (d * 86400);
    struct tm tmbuf;
    struct tm *tm = gmtime_r(&t, &tmbuf);
    if (!tm) continue;
    snprintf(date_sel_buf[count], sizeof(date_sel_buf[count]),
             "%04d%02d%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    date_selectors[count] = date_sel_buf[count];
    count++;
  }

  date_selectors[count] = NULL;
}

/*
 * query_txt — send DNS TXT query for domain, find record containing needle
 *
 * @in  domain — domain to query (e.g. "_dmarc.example.com")
 * @in  needle — string to search in TXT record (e.g. "v=spf1"), NULL means any TXT is sufficient
 * @out buf    — content of found TXT record (chunks concatenated)
 * @in  bufsz  — buf buffer size
 * @return     — 1 (needle found), 0 (not found or DNS error)
 *
 * TXT record format: [length_byte][text_data]... — records over 255 bytes are chunked
 *
 * Edge cases:
 *   - domain NULL → res_query crash
 *   - needle NULL → first TXT record is accepted (for DKIM)
 *   - DNS fail → 0
 *   - empty TXT record → buf[0]='\0', returns 1 if needle is NULL
 *   - very long TXT → truncated at bufsz-1, null terminated
 *   - multiple TXT records → first match returned, otherwise next one tried
 *   - non-TXT record → skipped (ns_t_txt filter)
 *   - bufsz == 0 → returns 0 immediately (guarded)
 *   - bufsz == 1 → only '\0' is written
 */
static int query_txt(const char *domain, const char *needle,
                     char *buf, size_t bufsz)
{
  if (bufsz == 0)
    return 0;

  unsigned char answer[4096];
  int len = res_query(domain, ns_c_in, ns_t_txt, answer, sizeof(answer));
  if (len < 0)
    return 0;

  ns_msg handle;
  if (ns_initparse(answer, len, &handle) < 0)
    return 0;

  int count = ns_msg_count(handle, ns_s_an);
  for (int i = 0; i < count; i++)
  {
    ns_rr rr;
    if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
      continue;
    if (ns_rr_type(rr) != ns_t_txt)
      continue;

    const unsigned char *rdata = ns_rr_rdata(rr);
    int rdlen = ns_rr_rdlen(rr);
    int pos = 0;
    size_t out = 0;

    while (pos < rdlen && out < bufsz - 1)
    {
      int chunk_len = rdata[pos];
      pos++;
      if (pos + chunk_len > rdlen)
        break;
      int copy = chunk_len;
      if (out + copy >= bufsz - 1)
        copy = bufsz - 1 - out;
      memcpy(buf + out, rdata + pos, copy);
      out += copy;
      pos += chunk_len;
    }
    buf[out] = '\0';

    if (needle == NULL || strstr(buf, needle))
      return 1;
  }

  return 0;
}

/*
 * query_mx — get first MX hostname for domain
 *
 * @in  domain — domain to query
 * @out buf    — MX hostname (lowercase)
 * @in  bufsz  — buf size
 * @return     — 1 if MX found, 0 otherwise
 */
static int query_mx(const char *domain, char *buf, size_t bufsz)
{
  if (bufsz == 0)
    return 0;

  unsigned char answer[DNS_ANSWER_SIZE];
  int len = res_query(domain, ns_c_in, ns_t_mx, answer, sizeof(answer));
  if (len < 0)
    return 0;

  ns_msg handle;
  if (ns_initparse(answer, len, &handle) < 0)
    return 0;

  int count = ns_msg_count(handle, ns_s_an);
  int best_pref = 65536;
  char best_mx[DNS_DOMAIN_SIZE] = "";

  for (int i = 0; i < count; i++)
  {
    ns_rr rr;
    if (ns_parserr(&handle, ns_s_an, i, &rr) < 0)
      continue;
    if (ns_rr_type(rr) != ns_t_mx)
      continue;

    const unsigned char *rdata = ns_rr_rdata(rr);
    int pref = (rdata[0] << 8) | rdata[1];

    char mx_name[DNS_DOMAIN_SIZE];
    if (dn_expand(answer, answer + len, rdata + 2,
                  mx_name, sizeof(mx_name)) < 0)
      continue;

    if (pref < best_pref)
    {
      best_pref = pref;
      snprintf(best_mx, sizeof(best_mx), "%s", mx_name);
    }
  }

  if (best_mx[0] == '\0')
    return 0;

  /* lowercase for matching */
  size_t mxlen = strlen(best_mx);
  if (mxlen >= bufsz)
    mxlen = bufsz - 1;
  for (size_t i = 0; i < mxlen; i++)
    buf[i] = (best_mx[i] >= 'A' && best_mx[i] <= 'Z') ? best_mx[i] + 32 : best_mx[i];
  buf[mxlen] = '\0';
  return 1;
}

/*
 * find_dkim_by_mx — detect email provider from MX, try provider-specific selectors
 *
 * @in  domain          — target domain
 * @in  mx_host         — MX hostname (lowercase)
 * @out selector_found  — matched selector name
 * @in  sel_sz          — selector_found buffer size
 * @out buf             — scratch buffer for DNS queries
 * @in  bufsz           — buf size
 * @return              — 1 if DKIM found, 0 otherwise
 */
static int find_dkim_by_mx(const char *domain, const char *mx_host,
                           char *selector_found, size_t sel_sz,
                           char *buf, size_t bufsz)
{
  int queries = 0;

  for (int m = 0; mx_dkim_table[m].mx_pattern != NULL; m++)
  {
    if (!strstr(mx_host, mx_dkim_table[m].mx_pattern))
      continue;

    /* matched provider — try provider-specific selectors */
    for (int s = 0; mx_dkim_table[m].selectors[s] != NULL; s++)
    {
      if (++queries > DKIM_MAX_QUERIES) return 0;
      char dkim_domain[DNS_DOMAIN_SIZE];
      snprintf(dkim_domain, sizeof(dkim_domain),
               "%s._domainkey.%s", mx_dkim_table[m].selectors[s], domain);
      if (query_txt(dkim_domain, NULL, buf, bufsz))
      {
        snprintf(selector_found, sel_sz, "%s", mx_dkim_table[m].selectors[s]);
        return 1;
      }
    }

    /* provider matched but no selector found — try date-based selectors */
    for (int i = 0; date_selectors[i] != NULL; i++)
    {
      if (++queries > DKIM_MAX_QUERIES) return 0;
      char dkim_domain[DNS_DOMAIN_SIZE];
      snprintf(dkim_domain, sizeof(dkim_domain),
               "%s._domainkey.%s", date_selectors[i], domain);
      if (query_txt(dkim_domain, NULL, buf, bufsz))
      {
        snprintf(selector_found, sel_sz, "%s", date_selectors[i]);
        return 1;
      }
    }

    /* monthly probe for last 5 years — 1st and 15th of each month */
    {
      time_t now = time(NULL);
      struct tm curbuf;
      struct tm *cur = gmtime_r(&now, &curbuf);
      if (!cur) break;
      int start_year = cur->tm_year + 1900;
      int start_mon = cur->tm_mon + 1;

      for (int offset = 3; offset < 60; offset++)
      {
        int y = start_year;
        int mo = start_mon - offset;
        while (mo <= 0) { mo += 12; y--; }

        /* try 1st of month */
        if (++queries > DKIM_MAX_QUERIES) return 0;
        char sel[32];
        snprintf(sel, sizeof(sel), "%04d%02d01", y, mo);
        char dkim_domain[DNS_DOMAIN_SIZE];
        snprintf(dkim_domain, sizeof(dkim_domain),
                 "%s._domainkey.%s", sel, domain);
        if (query_txt(dkim_domain, NULL, buf, bufsz))
        {
          snprintf(selector_found, sel_sz, "%s", sel);
          return 1;
        }

        /* try 15th as mid-month probe */
        if (++queries > DKIM_MAX_QUERIES) return 0;
        snprintf(sel, sizeof(sel), "%04d%02d15", y, mo);
        snprintf(dkim_domain, sizeof(dkim_domain),
                 "%s._domainkey.%s", sel, domain);
        if (query_txt(dkim_domain, NULL, buf, bufsz))
        {
          snprintf(selector_found, sel_sz, "%s", sel);
          return 1;
        }
      }
    }

    return 0;  /* provider matched, selectors exhausted */
  }

  return 0;  /* no provider matched */
}

/*
 * scan_dns — check SPF, DMARC, DKIM email security records
 *
 * @in  domain — target domain (e.g. "example.com")
 * @return     — cJSON object: {score: 0-15, max: 15, details: {spf, dmarc, dkim, ...}}
 *
 * Scoring (5+5+5=15):
 *   SPF:   present→5, missing→0
 *   DMARC: present→5, missing→0
 *   DKIM:  present→5, missing→0
 *
 * DKIM detection strategy (stops at first match):
 *   1. MX lookup → detect provider → try provider-specific selectors + date-based
 *   2. Common generic selectors (google, default, s1, selector1, ...)
 *   3. Date-based: last 90 days (daily YYYYMMDD)
 *   4. Monthly probe: 1st and 15th of each month for last 5 years
 *
 * Edge cases:
 *   - domain NULL → res_query crash
 *   - DNS server not responding → all queries return 0
 *   - DKIM selector not in list → has_dkim=0 (possible false negative)
 *   - multiple SPF records → first match is taken
 */
static cJSON *scan_dns(const char *domain)
{
  char buf[2048];

  /* SPF */
  int has_spf = query_txt(domain, "v=spf1", buf, sizeof(buf));
  char spf_record[2048] = "";
  if (has_spf)
    snprintf(spf_record, sizeof(spf_record), "%s", buf);

  /* DMARC — walk up labels per RFC 7489 §6.6.3 (organizational domain fallback).
   * E.g. api.contrastcyber.com → _dmarc.api.contrastcyber.com (miss) →
   * _dmarc.contrastcyber.com (hit). Stop before single-label TLD. */
  char dmarc_domain[512];
  int has_dmarc = 0;
  int dmarc_inherited = 0;
  char dmarc_record[2048] = "";
  const char *dmarc_name = domain;
  while (dmarc_name && *dmarc_name)
  {
    if (!strchr(dmarc_name, '.')) break;  /* single-label TLD guard */
    snprintf(dmarc_domain, sizeof(dmarc_domain), "_dmarc.%s", dmarc_name);
    if (query_txt(dmarc_domain, "v=DMARC1", buf, sizeof(buf)))
    {
      has_dmarc = 1;
      dmarc_inherited = (dmarc_name != domain);
      snprintf(dmarc_record, sizeof(dmarc_record), "%s", buf);
      break;
    }
    const char *dot = strchr(dmarc_name, '.');
    if (!dot) break;
    dmarc_name = dot + 1;
  }

  /* DKIM — MX-based provider detection, then generic fallback */
  int has_dkim = 0;
  char dkim_selector_found[64] = "";
  char mx_host[DNS_DOMAIN_SIZE] = "";

  /* Step 1: detect provider from MX record, try provider-specific selectors */
  if (query_mx(domain, mx_host, sizeof(mx_host)))
  {
    has_dkim = find_dkim_by_mx(domain, mx_host, dkim_selector_found,
                               sizeof(dkim_selector_found), buf, sizeof(buf));
  }

  /* Step 2: fallback — try common selectors if MX lookup didn't find DKIM */
  for (int i = 0; dkim_selectors[i] != NULL && !has_dkim; i++)
  {
    char dkim_domain[DNS_DOMAIN_SIZE];
    snprintf(dkim_domain, sizeof(dkim_domain),
             "%s._domainkey.%s", dkim_selectors[i], domain);
    if (query_txt(dkim_domain, NULL, buf, sizeof(buf)))
    {
      has_dkim = 1;
      snprintf(dkim_selector_found, sizeof(dkim_selector_found),
               "%s", dkim_selectors[i]);
    }
  }

  /* Step 3: date-based selectors — last 90 days (daily) */
  for (int i = 0; date_selectors[i] != NULL && !has_dkim; i++)
  {
    char dkim_domain[DNS_DOMAIN_SIZE];
    snprintf(dkim_domain, sizeof(dkim_domain),
             "%s._domainkey.%s", date_selectors[i], domain);
    if (query_txt(dkim_domain, NULL, buf, sizeof(buf)))
    {
      has_dkim = 1;
      snprintf(dkim_selector_found, sizeof(dkim_selector_found),
               "%s", date_selectors[i]);
    }
  }

  /* Step 4: monthly probe — 1st and 15th of each month for last 2 years */
  if (!has_dkim)
  {
    time_t now = time(NULL);
    struct tm curbuf;
    struct tm *cur = gmtime_r(&now, &curbuf);
    if (!cur) goto dkim_done;
    int start_year = cur->tm_year + 1900;
    int start_mon = cur->tm_mon + 1;

    for (int offset = 1; offset < 24 && !has_dkim; offset++)
    {
      int y = start_year;
      int m = start_mon - offset;
      while (m <= 0) { m += 12; y--; }

      char sel[32];
      char dkim_domain[DNS_DOMAIN_SIZE];

      snprintf(sel, sizeof(sel), "%04d%02d01", y, m);
      snprintf(dkim_domain, sizeof(dkim_domain),
               "%s._domainkey.%s", sel, domain);
      if (query_txt(dkim_domain, NULL, buf, sizeof(buf)))
      {
        has_dkim = 1;
        snprintf(dkim_selector_found, sizeof(dkim_selector_found), "%s", sel);
        break;
      }

      snprintf(sel, sizeof(sel), "%04d%02d15", y, m);
      snprintf(dkim_domain, sizeof(dkim_domain),
               "%s._domainkey.%s", sel, domain);
      if (query_txt(dkim_domain, NULL, buf, sizeof(buf)))
      {
        has_dkim = 1;
        snprintf(dkim_selector_found, sizeof(dkim_selector_found), "%s", sel);
        break;
      }
    }
  }
dkim_done:

  int spf_score = has_spf ? SPF_SCORE : 0;
  int dmarc_score = has_dmarc ? DMARC_SCORE : 0;
  int dkim_score = has_dkim ? DKIM_SCORE : 0;
  int score = spf_score + dmarc_score + dkim_score;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", DNS_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddBoolToObject(details, "spf", has_spf);
  cJSON_AddNumberToObject(details, "spf_score", spf_score);
  if (has_spf)
    cJSON_AddStringToObject(details, "spf_record", spf_record);

  cJSON_AddBoolToObject(details, "dmarc", has_dmarc);
  cJSON_AddNumberToObject(details, "dmarc_score", dmarc_score);
  if (has_dmarc)
  {
    cJSON_AddStringToObject(details, "dmarc_record", dmarc_record);
    cJSON_AddBoolToObject(details, "dmarc_inherited", dmarc_inherited);
  }

  cJSON_AddBoolToObject(details, "dkim", has_dkim);
  cJSON_AddNumberToObject(details, "dkim_score", dkim_score);
  if (has_dkim)
    cJSON_AddStringToObject(details, "dkim_selector", dkim_selector_found);

  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  7. DNSSEC CHECK
 * ============================ */

/*
 * scan_dnssec — check if domain has DNSSEC enabled
 *
 * @in  domain — target domain
 * @return     — cJSON object: {score: 0-5, max: 5, details: {dnssec_enabled}}
 *
 * DNSKEY records live at the zone apex (e.g. contrastcyber.com), not at
 * subdomains (e.g. api.contrastcyber.com). So we walk up labels until we
 * find DNSKEY, stopping before we reach a single-label name (TLD) — com.,
 * org., etc. are all signed and would give a false positive.
 */
static cJSON *scan_dnssec(const char *domain)
{
  unsigned char answer[4096];
  int has_dnssec = 0;

  const char *name = domain;
  while (name && *name)
  {
    /* stop before querying a single-label TLD */
    if (!strchr(name, '.')) break;

    int len = res_query(name, ns_c_in, ns_t_dnskey, answer, sizeof(answer));
    if (len > 0)
    {
      ns_msg handle;
      if (ns_initparse(answer, len, &handle) == 0 &&
          ns_msg_count(handle, ns_s_an) > 0)
      {
        has_dnssec = 1;
        break;
      }
    }
    /* strip leftmost label: "api.foo.com" → "foo.com" */
    const char *dot = strchr(name, '.');
    if (!dot) break;
    name = dot + 1;
  }

  int score = has_dnssec ? DNSSEC_MAX : 0;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", DNSSEC_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddBoolToObject(details, "dnssec_enabled", has_dnssec);
  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  8. HTTP METHODS CHECK
 * ============================ */

/*
 * methods_header_callback — capture Allow header from OPTIONS response
 */
static size_t methods_header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
  (void)userdata;
  size_t total = size * nitems;

  if (total > 6 && strncasecmp(buffer, "allow:", 6) == 0)
  {
    size_t vlen = total - 6;
    if (vlen >= sizeof(allow_header)) vlen = sizeof(allow_header) - 1;
    memcpy(allow_header, buffer + 6, vlen);
    allow_header[vlen] = '\0';
    char *p = allow_header;
    while (*p == ' ') p++;
    memmove(allow_header, p, strlen(p) + 1);
    size_t slen = strlen(allow_header);
    while (slen > 0 && (allow_header[slen-1] == '\r' || allow_header[slen-1] == '\n'))
      allow_header[--slen] = '\0';
  }

  return total;
}

/*
 * scan_methods — check if dangerous HTTP methods are enabled
 *
 * @in  domain — target domain
 * @return     — cJSON object: {score: 0-5, max: 5, details: {...}}
 *
 * Sends OPTIONS request, checks Allow header for TRACE, DELETE, PUT
 */
static cJSON *scan_methods(const char *domain)
{
  allow_header[0] = '\0';

  char url[URL_BUFFER_SIZE];
  snprintf(url, sizeof(url), "https://%s", domain);

  CURL *curl = curl_easy_init();
  struct curl_slist *resolve_list = make_resolve_list(domain);
  struct curl_slist *browser_hdrs = make_browser_headers(NULL);
  int ok = 0;
  if (curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, methods_header_callback);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)HTTP_TIMEOUT);
    setup_curl_browser(curl, browser_hdrs);
    if (resolve_list)
      curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    ok = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
  }
  if (resolve_list) curl_slist_free_all(resolve_list);
  if (browser_hdrs) curl_slist_free_all(browser_hdrs);

  int has_trace = 0, has_delete = 0, has_put = 0;
  if (ok && allow_header[0])
  {
    char lower[512];
    size_t len = strlen(allow_header);
    if (len >= sizeof(lower)) len = sizeof(lower) - 1;
    for (size_t i = 0; i < len; i++)
      lower[i] = (allow_header[i] >= 'A' && allow_header[i] <= 'Z') ? allow_header[i] + 32 : allow_header[i];
    lower[len] = '\0';

    has_trace = strstr(lower, "trace") != NULL;
    has_delete = strstr(lower, "delete") != NULL;
    has_put = strstr(lower, "put") != NULL;
  }

  int dangerous_count = has_trace + has_delete + has_put;
  int score = ok ? (dangerous_count == 0 ? METHODS_MAX : (dangerous_count == 1 ? 3 : (dangerous_count == 2 ? 1 : 0))) : METHODS_MAX;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", METHODS_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddBoolToObject(details, "trace_enabled", has_trace);
  cJSON_AddBoolToObject(details, "delete_enabled", has_delete);
  cJSON_AddBoolToObject(details, "put_enabled", has_put);
  if (allow_header[0])
    cJSON_AddStringToObject(details, "allowed_methods", allow_header);
  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  9. CORS CHECK
 * ============================ */

/*
 * cors_header_callback — capture CORS-related headers
 */
static size_t cors_header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
  (void)userdata;
  size_t total = size * nitems;

  if (total > 28 && strncasecmp(buffer, "access-control-allow-origin:", 28) == 0)
  {
    size_t vlen = total - 28;
    if (vlen >= sizeof(cors_acao)) vlen = sizeof(cors_acao) - 1;
    memcpy(cors_acao, buffer + 28, vlen);
    cors_acao[vlen] = '\0';
    char *p = cors_acao;
    while (*p == ' ') p++;
    memmove(cors_acao, p, strlen(p) + 1);
    size_t slen = strlen(cors_acao);
    while (slen > 0 && (cors_acao[slen-1] == '\r' || cors_acao[slen-1] == '\n'))
      cors_acao[--slen] = '\0';
  }

  if (total > 32 && strncasecmp(buffer, "access-control-allow-credentials:", 32) == 0)
  {
    char val[64];
    size_t vlen = total - 32;
    if (vlen >= sizeof(val)) vlen = sizeof(val) - 1;
    memcpy(val, buffer + 32, vlen);
    val[vlen] = '\0';
    if (strstr(val, "true")) cors_credentials = 1;
  }

  return total;
}

/*
 * scan_cors — check CORS misconfiguration
 *
 * @in  domain — target domain
 * @return     — cJSON object: {score: 0-5, max: 5, details: {...}}
 *
 * Sends request with evil Origin, checks if server reflects it or uses wildcard
 */
static cJSON *scan_cors(const char *domain)
{
  cors_acao[0] = '\0';
  cors_credentials = 0;

  char url[URL_BUFFER_SIZE];
  snprintf(url, sizeof(url), "https://%s", domain);

  CURL *curl = curl_easy_init();
  struct curl_slist *resolve_list = make_resolve_list(domain);
  /* Origin header first, then append browser headers onto same list */
  struct curl_slist *browser_hdrs = NULL;
  browser_hdrs = curl_slist_append(browser_hdrs, "Origin: https://evil.contrastscan.test");
  browser_hdrs = make_browser_headers(browser_hdrs);
  int ok = 0;
  if (curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, cors_header_callback);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)HTTP_TIMEOUT);
    setup_curl_browser(curl, browser_hdrs);
    if (resolve_list)
      curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    ok = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
  }
  if (resolve_list) curl_slist_free_all(resolve_list);
  if (browser_hdrs) curl_slist_free_all(browser_hdrs);

  int wildcard = 0, reflects_origin = 0;
  if (ok && cors_acao[0])
  {
    if (strcmp(cors_acao, "*") == 0) wildcard = 1;
    if (strstr(cors_acao, "evil.contrastscan.test")) reflects_origin = 1;
  }

  int score = CORS_MAX;
  if (wildcard && cors_credentials) score = 0;
  else if (reflects_origin) score = 0;
  else if (wildcard) score = 2;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", CORS_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddBoolToObject(details, "wildcard_origin", wildcard);
  cJSON_AddBoolToObject(details, "reflects_origin", reflects_origin);
  cJSON_AddBoolToObject(details, "credentials_with_wildcard", wildcard && cors_credentials);
  cJSON_AddBoolToObject(details, "cors_credentials", cors_credentials);
  if (cors_acao[0])
    cJSON_AddStringToObject(details, "acao_value", cors_acao);
  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  10. HTML ANALYSIS
 * ============================ */

/*
 * body_callback — store HTTP response body for HTML analysis
 */
static size_t body_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void)userdata;
  size_t total = size * nmemb;
  size_t space = HTML_BODY_MAX - html_body_len - 1;
  if (space == 0)
    return total; /* buffer full — discard overflow, keep transfer "successful" */
  size_t copy = total < space ? total : space;
  memcpy(html_body + html_body_len, ptr, copy);
  html_body_len += copy;
  html_body[html_body_len] = '\0';
  return total;
}

static int count_substr_ci(const char *hay, const char *needle)
{
  int count = 0;
  size_t nlen = strlen(needle);
  const char *p = hay;
  while ((p = strcasestr(p, needle)) != NULL) { count++; p += nlen; }
  return count;
}

/*
 * scan_html — analyze HTML body for security issues
 *
 * @in  domain — target domain
 * @return     — cJSON object: {score: 0-5, max: 5, details: {...}}
 *
 * Checks: mixed content, inline scripts, SRI, form actions
 */
static cJSON *scan_html(const char *domain)
{
  html_body_len = 0;
  html_body[0] = '\0';

  char url[URL_BUFFER_SIZE];
  snprintf(url, sizeof(url), "https://%s", domain);

  CURL *curl = curl_easy_init();
  struct curl_slist *resolve_list = make_resolve_list(domain);
  struct curl_slist *browser_hdrs = make_browser_headers(NULL);
  int ok = 0;
  if (curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_callback);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, (long)MAX_REDIRECTS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)HTTP_TIMEOUT);
    setup_curl_browser(curl, browser_hdrs);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, (long)HTML_BODY_MAX);
    if (resolve_list)
      curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    ok = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
  }
  if (resolve_list) curl_slist_free_all(resolve_list);
  if (browser_hdrs) curl_slist_free_all(browser_hdrs);

  /* sub-checks */
  int mixed_active = 0, mixed_passive = 0;
  int inline_scripts = 0, inline_handlers = 0;
  int ext_scripts_total = 0, ext_scripts_no_sri = 0;
  int form_http_action = 0, form_total = 0;
  int meta_set_cookie = 0, meta_refresh_http = 0;

  if (ok && html_body_len > 0)
  {
    /* mixed content: http:// in src= or href= */
    mixed_active += count_substr_ci(html_body, "<script src=\"http://");
    mixed_active += count_substr_ci(html_body, "<script src='http://");
    mixed_active += count_substr_ci(html_body, "<iframe src=\"http://");
    mixed_active += count_substr_ci(html_body, "<iframe src='http://");
    mixed_passive += count_substr_ci(html_body, "<img src=\"http://");
    mixed_passive += count_substr_ci(html_body, "<img src='http://");
    mixed_passive += count_substr_ci(html_body, "<link href=\"http://");
    mixed_passive += count_substr_ci(html_body, "<link href='http://");

    /* inline scripts: <script> without src= (inline code).
     * Excludes data blocks (JSON-LD / application+json / text/template) — per
     * HTML spec these are non-executable and CSP does not require 'unsafe-inline'.
     */
    int total_script_tags = count_substr_ci(html_body, "<script");
    int script_with_src = count_substr_ci(html_body, "<script src");
    int data_block_scripts = count_script_data_blocks(html_body);
    inline_scripts = total_script_tags - script_with_src - data_block_scripts;
    if (inline_scripts < 0) inline_scripts = 0;

    /* inline event handlers */
    inline_handlers += count_substr_ci(html_body, "onclick=");
    inline_handlers += count_substr_ci(html_body, "onload=");
    inline_handlers += count_substr_ci(html_body, "onerror=");
    inline_handlers += count_substr_ci(html_body, "onmouseover=");

    /* external scripts SRI */
    ext_scripts_total = count_substr_ci(html_body, "<script src=\"https://");
    ext_scripts_total += count_substr_ci(html_body, "<script src='https://");
    int sri_count = count_substr_ci(html_body, "integrity=\"sha");
    sri_count += count_substr_ci(html_body, "integrity='sha");
    ext_scripts_no_sri = ext_scripts_total - sri_count;
    if (ext_scripts_no_sri < 0) ext_scripts_no_sri = 0;

    /* form actions */
    form_total = count_substr_ci(html_body, "<form");
    form_http_action = count_substr_ci(html_body, "<form action=\"http://");
    form_http_action += count_substr_ci(html_body, "<form action='http://");

    /* meta set-cookie (bypasses HttpOnly, insecure pattern) */
    meta_set_cookie = count_substr_ci(html_body, "http-equiv=\"set-cookie\"");
    meta_set_cookie += count_substr_ci(html_body, "http-equiv='set-cookie'");

    /* meta refresh to HTTP (HTTPS bypass) */
    meta_refresh_http = count_substr_ci(html_body, "http-equiv=\"refresh\"");
    meta_refresh_http += count_substr_ci(html_body, "http-equiv='refresh'");
    /* only count as insecure if it refreshes to http:// */
    if (meta_refresh_http > 0)
    {
      int has_http_url = count_substr_ci(html_body, "url=http://");
      meta_refresh_http = has_http_url;
    }
  }

  /* scoring: 5 points total */
  int mixed_score = (mixed_active == 0 && mixed_passive == 0) ? 2 : (mixed_active == 0 ? 1 : 0);
  int inline_score = (inline_scripts == 0 && inline_handlers == 0) ? 1 : 0;
  int sri_score = (ext_scripts_no_sri == 0) ? 1 : 0;
  int form_score = (form_http_action == 0) ? 1 : 0;
  int score = ok ? (mixed_score + inline_score + sri_score + form_score) : HTML_MAX;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", HTML_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddNumberToObject(details, "mixed_active", mixed_active);
  cJSON_AddNumberToObject(details, "mixed_passive", mixed_passive);
  cJSON_AddNumberToObject(details, "inline_scripts", inline_scripts);
  cJSON_AddNumberToObject(details, "inline_handlers", inline_handlers);
  cJSON_AddNumberToObject(details, "external_scripts", ext_scripts_total);
  cJSON_AddNumberToObject(details, "external_scripts_no_sri", ext_scripts_no_sri);
  cJSON_AddNumberToObject(details, "forms_total", form_total);
  cJSON_AddNumberToObject(details, "forms_http_action", form_http_action);
  cJSON_AddNumberToObject(details, "meta_set_cookie", meta_set_cookie);
  cJSON_AddNumberToObject(details, "meta_refresh_http", meta_refresh_http);
  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  11. CSP DEEP ANALYSIS
 * ============================ */

/*
 * scan_csp_deep — deep analysis of Content-Security-Policy value
 *
 * @return — cJSON object: {score: 0-2, max: 2, details: {...}}
 *
 * Must be called AFTER scan_headers() (uses global csp_value)
 * Checks for unsafe-inline, unsafe-eval, wildcard, data:, blob:
 */
static cJSON *scan_csp_deep(void)
{
  int has_unsafe_inline = 0, has_unsafe_eval = 0;
  int has_wildcard = 0, has_data_uri = 0, has_blob = 0;

  if (csp_value[0])
  {
    has_unsafe_inline = csp_has_keyword(csp_value, "unsafe-inline");
    has_unsafe_eval = csp_has_keyword(csp_value, "unsafe-eval");
    has_wildcard = (strstr(csp_value, " * ") != NULL || strstr(csp_value, " *;") != NULL || strstr(csp_value, " *'") != NULL);
    has_data_uri = (strcasestr(csp_value, "data:") != NULL);
    has_blob = (strcasestr(csp_value, "blob:") != NULL);
  }

  int weaknesses = has_unsafe_inline + has_unsafe_eval + has_wildcard + has_data_uri + has_blob;
  int score = csp_value[0] ? (weaknesses == 0 ? CSP_DEEP_MAX : (weaknesses <= 2 ? 1 : 0)) : 0;

  cJSON *obj = safe_cjson_object();
  cJSON_AddNumberToObject(obj, "score", score);
  cJSON_AddNumberToObject(obj, "max", CSP_DEEP_MAX);

  cJSON *details = safe_cjson_object();
  cJSON_AddBoolToObject(details, "csp_present", csp_value[0] != '\0');
  cJSON_AddBoolToObject(details, "unsafe_inline", has_unsafe_inline);
  cJSON_AddBoolToObject(details, "unsafe_eval", has_unsafe_eval);
  cJSON_AddBoolToObject(details, "wildcard_source", has_wildcard);
  cJSON_AddBoolToObject(details, "data_uri", has_data_uri);
  cJSON_AddBoolToObject(details, "blob_uri", has_blob);
  cJSON_AddItemToObject(obj, "details", details);

  return obj;
}

/* ============================
 *  CALCULATE GRADE
 * ============================ */

/*
 * calc_grade — convert total score to A-F grade
 *
 * @in  score — total score (0-100)
 * @in  max   — maximum score (100)
 * @return    — grade string: "A", "B", "C", "D", "F"
 *
 * Thresholds: A >= 90, B >= 75, C >= 60, D >= 40, F < 40
 *
 * Edge cases:
 *   - score == 0 → "F"
 *   - score == 100 → "A"
 *   - max == 0 → division by zero → undefined behavior
 *   - score > max → "A"
 *   - score < 0 → "F"
 */
static const char *calc_grade(int score, int max)
{
  if (max <= 0) return "F";
  int pct = (score * 100) / max;
  if (pct >= 90) return "A";
  if (pct >= 75) return "B";
  if (pct >= 60) return "C";
  if (pct >= 40) return "D";
  return "F";
}

/* ============================
 *  MAIN
 * ============================ */

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    fprintf(stderr, "Usage: %s <domain> [resolved_ip]\n", argv[0]);
    return EXIT_FAILURE;
  }

  const char *domain = argv[1];

  /* optional: pre-validated IP from Python (SSRF rebinding protection) */
  if (argc >= 3 && strlen(argv[2]) > 0)
    g_resolved_ip = argv[2];

  /* DNS domain max 253 characters */
  size_t dlen = strlen(domain);
  if (dlen == 0 || dlen > 253)
  {
    fprintf(stderr, "Error: domain too long (max 253 chars)\n");
    return EXIT_FAILURE;
  }

  /* validate characters: [a-zA-Z0-9.-] only */
  for (size_t i = 0; i < dlen; i++)
  {
    char c = domain[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '-'))
    {
      fprintf(stderr, "Error: invalid character in domain\n");
      return EXIT_FAILURE;
    }
  }

  init_dns_resolver();
  generate_date_selectors();

  if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0)
  {
    fprintf(stderr, "curl_global_init failed\n");
    return EXIT_FAILURE;
  }

  /* run 11 modules */
  cJSON *headers = scan_headers(domain);
  /* disclosure + cookies + csp_deep must run AFTER scan_headers (uses globals) */
  cJSON *disclosure = scan_disclosure();
  cJSON *cookies = scan_cookies();
  cJSON *redirect = scan_redirect(domain);
  cJSON *ssl = scan_ssl(domain);
  cJSON *dns = scan_dns(domain);
  cJSON *dnssec = scan_dnssec(domain);
  cJSON *methods = scan_methods(domain);
  cJSON *cors = scan_cors(domain);
  cJSON *html = scan_html(domain);
  cJSON *csp_deep = scan_csp_deep();  /* must run AFTER scan_headers */

  /* total score — NULL guard (prevents segfault on OOM) */
  cJSON *h_score = cJSON_GetObjectItem(headers, "score");
  cJSON *s_score = cJSON_GetObjectItem(ssl, "score");
  cJSON *d_score = cJSON_GetObjectItem(dns, "score");
  cJSON *r_score = cJSON_GetObjectItem(redirect, "score");
  cJSON *disc_score = cJSON_GetObjectItem(disclosure, "score");
  cJSON *cook_score = cJSON_GetObjectItem(cookies, "score");
  cJSON *dsec_score = cJSON_GetObjectItem(dnssec, "score");
  cJSON *meth_score = cJSON_GetObjectItem(methods, "score");
  cJSON *cors_score_item = cJSON_GetObjectItem(cors, "score");
  cJSON *html_score = cJSON_GetObjectItem(html, "score");
  cJSON *csp_score = cJSON_GetObjectItem(csp_deep, "score");
  int total_score = (h_score ? h_score->valueint : 0) +
                    (s_score ? s_score->valueint : 0) +
                    (d_score ? d_score->valueint : 0) +
                    (r_score ? r_score->valueint : 0) +
                    (disc_score ? disc_score->valueint : 0) +
                    (cook_score ? cook_score->valueint : 0) +
                    (dsec_score ? dsec_score->valueint : 0) +
                    (meth_score ? meth_score->valueint : 0) +
                    (cors_score_item ? cors_score_item->valueint : 0) +
                    (html_score ? html_score->valueint : 0) +
                    (csp_score ? csp_score->valueint : 0);
  int total_max = TOTAL_MAX;

  /* JSON output */
  cJSON *root = safe_cjson_object();
  cJSON_AddStringToObject(root, "domain", domain);
  cJSON_AddNumberToObject(root, "total_score", total_score);
  cJSON_AddNumberToObject(root, "max_score", total_max);
  cJSON_AddStringToObject(root, "grade", calc_grade(total_score, total_max));
  cJSON_AddItemToObject(root, "headers", headers);
  cJSON_AddItemToObject(root, "ssl", ssl);
  cJSON_AddItemToObject(root, "dns", dns);
  cJSON_AddItemToObject(root, "redirect", redirect);
  cJSON_AddItemToObject(root, "disclosure", disclosure);
  cJSON_AddItemToObject(root, "cookies", cookies);
  cJSON_AddItemToObject(root, "dnssec", dnssec);
  cJSON_AddItemToObject(root, "methods", methods);
  cJSON_AddItemToObject(root, "cors", cors);
  cJSON_AddItemToObject(root, "html", html);
  cJSON_AddItemToObject(root, "csp_analysis", csp_deep);

  char *json_str = cJSON_Print(root);
  if (json_str)
  {
    printf("%s\n", json_str);
    free(json_str);
  }
  else
  {
    fprintf(stderr, "JSON output failed\n");
  }
  cJSON_Delete(root);
  curl_global_cleanup();

  return EXIT_SUCCESS;
}
