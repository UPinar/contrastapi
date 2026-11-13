#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "certspotter.h"
#include "config.h"
#include "http.h"
#include "jsonread.h"
#include "quota.h"
#include "retryafter.h"
#include "validate.h"

#define CERTSPOTTER_MAX_BODY_BYTE_COUNT  (2 * 1024 * 1024)

#define CERTSPOTTER_URL_PREFIX  "https://api.certspotter.com/v1/issuances?domain="
#define CERTSPOTTER_URL_QUERY   "&match_wildcards=true&expand=dns_names&expand=issuer&expand=issuer.caa_domains"

#define CERTSPOTTER_URL_AFTER  "&after="

#define CERTSPOTTER_SUBTREE_URL_QUERY  "&include_subdomains=true&match_wildcards=true&expand=dns_names"

typedef bool (*CertSpotterBodyReaderFunction_t)(const char* body, size_t body_len, void* context);

typedef struct {
  const char*           mp_domain;
  SubdomainNameSet_t*   mp_nameSet;
  bool*                 mp_isAnswerEmpty;
} CertSpotterSubtreeReadContext_t;

typedef struct {
  bool  m_isExact;
  bool  m_isWildcard;
} CertSpotterHostMatch_t;

typedef struct {
  const char*                    mp_hostName;
  CertSpotterCertificateList_t*  mp_certificateList;
  bool                           m_isPastPageCap;
  int                            m_pageElementCount;
  char                           ma_nextPageAfterId[CERTSPOTTER_CERTIFICATE_ID_MAX_LEN + 1];
} CertSpotterPageReadContext_t;

_Static_assert(CERTSPOTTER_ISSUER_MAX_LEN <= CERTSPOTTER_ISSUER_KEY_MAX_LEN, "an issuer name must fit an issuer key");

#define CERTSPOTTER_AUTHORIZATION_PREFIX  "Authorization: Bearer "

static char g_authorizationHeader[sizeof(CERTSPOTTER_AUTHORIZATION_PREFIX) + CONFIG_CERTSPOTTER_API_KEY_MAX_LEN];

void certspotter_setApiKey(const char* api_key)
{
  if (api_key == NULL)
  {
    g_authorizationHeader[0] = '\0';
    return;
  }

  assert(strlen(api_key) <= CONFIG_CERTSPOTTER_API_KEY_MAX_LEN);
  snprintf(g_authorizationHeader, sizeof(g_authorizationHeader), CERTSPOTTER_AUTHORIZATION_PREFIX "%s", api_key);
}

bool certspotter_hasApiKey(void)
{
  return g_authorizationHeader[0] != '\0';
}

static bool static_isSha256Hex(const char* text)
{
  for (int i = 0; i < CERTSPOTTER_SHA256_HEX_LEN; i++)
  {
    unsigned char c = (unsigned char)text[i];
    if (!isxdigit(c) || isupper(c))
      return false;
  }
  return true;
}

static bool static_isTime(const char* text)
{
  static const char TIME_PATTERN[] = "dddd-dd-ddTdd:dd:ddZ";
  for (int i = 0; i < CERTSPOTTER_TIME_LEN; i++)
  {
    bool is_match = TIME_PATTERN[i] == 'd' ? isdigit((unsigned char)text[i]) != 0 : text[i] == TIME_PATTERN[i];
    if (!is_match)
      return false;
  }
  return true;
}

static void static_readCaaDomains(JsonReadSpan_t caa_span, CertSpotterCertificate_t* certificate)
{
  JsonReadSpan_t    domain_span   = { 0 };
  size_t            domain_offset = 0;
  int               domain_count  = 0;
  JsonReadStatus_t  status;
  while ((status = jsonread_arrayNextElement(caa_span, &domain_offset, &domain_span)) == JSONREAD_OK)
  {
    if (domain_count == CERTSPOTTER_CAA_DOMAIN_MAX_COUNT)
      return;

    char* domain = certificate->ma_caaDomains[domain_count];
    if (jsonread_spanToStrStatus(domain_span, domain, CERTSPOTTER_CAA_DOMAIN_MAX_LEN + 1) != JSONREAD_OK || domain[0] == '\0')
      return;

    domain_count++;
  }

  if (status != JSONREAD_ERR_NOTFOUND)
    return;

  certificate->m_caaDomainCount       = domain_count;
  certificate->m_isCaaDomainListKnown = true;
}

static void static_readIssuer(JsonReadSpan_t issuer_span, CertSpotterCertificate_t* certificate)
{
  JsonReadSpan_t value_span = { 0 };
  if (jsonread_objectKey(issuer_span, "friendly_name", &value_span) != JSONREAD_OK ||
      jsonread_spanToStrStatus(value_span, certificate->ma_issuer, sizeof(certificate->ma_issuer)) != JSONREAD_OK)
  {
    certificate->ma_issuer[0] = '\0';
  }

  if (jsonread_objectKey(issuer_span, "caa_domains", &value_span) == JSONREAD_OK)
    static_readCaaDomains(value_span, certificate);
}

static bool static_isWildcardMatch(const char* name, const char* host_name)
{
  const char* parent = strchr(host_name, '.');
  return name[0] == '*' && name[1] == '.' && parent != NULL && strcasecmp(name + 2, parent + 1) == 0;
}

static bool static_tryReadDnsNames(JsonReadSpan_t names_span, const char* host_name, CertSpotterCertificate_t* certificate, CertSpotterHostMatch_t* match)
{
  if (names_span.m_len == 0 || names_span.mp_start[0] != '[')
    return false;

  JsonReadSpan_t name_span   = { 0 };
  size_t         name_offset = 0;
  while (jsonread_arrayNextElement(names_span, &name_offset, &name_span) == JSONREAD_OK)
  {
    char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
    JsonReadStatus_t status = jsonread_spanToStrStatus(name_span, name, sizeof(name));
    if (status == JSONREAD_ERR_TYPE)
      return false;
    if (status != JSONREAD_OK || name[0] == '\0')
      continue;

    if (certificate->m_dnsNameCount < CERTSPOTTER_DNS_NAME_MAX_COUNT)
      snprintf(certificate->ma_dnsNames[certificate->m_dnsNameCount], sizeof(certificate->ma_dnsNames[0]), "%s", name);
    if (certificate->m_dnsNameCount < INT_MAX)
      certificate->m_dnsNameCount++;

    if (strcasecmp(name, host_name) == 0)
      match->m_isExact = true;
    else if (static_isWildcardMatch(name, host_name))
      match->m_isWildcard = true;
  }

  return true;
}

static bool static_tryReadCertificate(JsonReadSpan_t certificate_span, const char* host_name, CertSpotterCertificate_t* certificate, CertSpotterHostMatch_t* match)
{
  memset(certificate, 0, sizeof(*certificate));
  memset(match, 0, sizeof(*match));
  JsonReadSpan_t value_span = { 0 };

  if (jsonread_objectKey(certificate_span, "cert_sha256", &value_span) != JSONREAD_OK                                   ||
      jsonread_spanToStrStatus(value_span, certificate->ma_sha256Hex, sizeof(certificate->ma_sha256Hex)) != JSONREAD_OK ||
      !static_isSha256Hex(certificate->ma_sha256Hex))
    return false;

  if (jsonread_objectKey(certificate_span, "not_before", &value_span) != JSONREAD_OK                                    ||
      jsonread_spanToStrStatus(value_span, certificate->ma_validFrom, sizeof(certificate->ma_validFrom)) != JSONREAD_OK ||
      !static_isTime(certificate->ma_validFrom))
    return false;

  if (jsonread_objectKey(certificate_span, "not_after", &value_span) != JSONREAD_OK                                       ||
      jsonread_spanToStrStatus(value_span, certificate->ma_validUntil, sizeof(certificate->ma_validUntil)) != JSONREAD_OK ||
      !static_isTime(certificate->ma_validUntil))
    return false;

  if (jsonread_objectKey(certificate_span, "revoked", &value_span) == JSONREAD_OK && !jsonread_isSpanEqual(value_span, "null"))
  {
    bool is_revoked = false;
    if (jsonread_spanToBoolStatus(value_span, &is_revoked) != JSONREAD_OK)
      return false;
    certificate->m_revocation = is_revoked ? CERTSPOTTER_REVOCATION_REVOKED : CERTSPOTTER_REVOCATION_NOT_REVOKED;
  }

  if (jsonread_objectKey(certificate_span, "dns_names", &value_span) != JSONREAD_OK ||
      !static_tryReadDnsNames(value_span, host_name, certificate, match))
    return false;

  if (jsonread_objectKey(certificate_span, "issuer", &value_span) == JSONREAD_OK)
    static_readIssuer(value_span, certificate);

  return true;
}

static bool static_isListedBefore(const CertSpotterCertificate_t* first, const CertSpotterCertificate_t* second)
{
  int time_order = strcmp(first->ma_validFrom, second->ma_validFrom);
  if (time_order != 0)
    return time_order > 0;

  return strcmp(first->ma_sha256Hex, second->ma_sha256Hex) < 0;
}

static void static_keepCertificate(CertSpotterCertificateList_t* list, const CertSpotterCertificate_t* certificate)
{
  CertSpotterCertificate_t* certificates = list->ma_certificates;
  const int                 max_count    = CERTSPOTTER_CERTIFICATE_MAX_COUNT;
  int                       kept_count   = list->m_keptCount;

  int position = kept_count;
  while (position > 0 && static_isListedBefore(certificate, &certificates[position - 1]))
    position--;
  if (position == max_count)
    return;

  int moved_count = kept_count < max_count  ? kept_count - position
                                            : max_count - 1 - position;
  memmove(&certificates[position + 1], &certificates[position], (size_t)moved_count * sizeof(certificates[0]));
  certificates[position] = *certificate;
  if (kept_count < max_count)
    list->m_keptCount++;
}

static void static_addIssuer(CertSpotterCertificateList_t* list, const CertSpotterCertificate_t* certificate, const CertSpotterHostMatch_t* match)
{
  CertSpotterIssuer_t candidate;
  memset(&candidate, 0, sizeof(candidate));
  candidate.m_isCaaDomainListKnown = certificate->m_isCaaDomainListKnown;
  if (certificate->m_isCaaDomainListKnown)
  {
    for (int i = 0; i < certificate->m_caaDomainCount; i++)
    {
      int position = i;
      while (position > 0 && strcmp(certificate->ma_caaDomains[i], candidate.ma_caaDomains[position - 1]) < 0)
      {
        memcpy(candidate.ma_caaDomains[position], candidate.ma_caaDomains[position - 1], sizeof(candidate.ma_caaDomains[0]));
        position--;
      }
      memcpy(candidate.ma_caaDomains[position], certificate->ma_caaDomains[i], sizeof(candidate.ma_caaDomains[0]));
    }
    candidate.m_caaDomainCount = certificate->m_caaDomainCount;
  }

  size_t key_len = 0;
  for (int i = 0; i < candidate.m_caaDomainCount; i++)
    key_len += (size_t)snprintf(candidate.ma_key + key_len, sizeof(candidate.ma_key) - key_len, "%s%s", i > 0 ? "," : "", candidate.ma_caaDomains[i]);
  assert(key_len <= CERTSPOTTER_ISSUER_KEY_MAX_LEN);
  if (candidate.m_caaDomainCount == 0)
    snprintf(candidate.ma_key, sizeof(candidate.ma_key), "%s", certificate->ma_issuer);

  if (candidate.ma_key[0] == '\0')
  {
    list->m_isIssuerDropped = true;
    return;
  }

  for (int i = 0; i < list->m_issuerCount; i++)
  {
    CertSpotterIssuer_t* issuer = &list->ma_issuers[i];
    if (strcmp(issuer->ma_key, candidate.ma_key) == 0)
    {
      issuer->m_isSeenOnExactName    = issuer->m_isSeenOnExactName    || match->m_isExact;
      issuer->m_isSeenOnWildcardName = issuer->m_isSeenOnWildcardName || match->m_isWildcard;
      return;
    }
  }

  if (list->m_issuerCount == CERTSPOTTER_ISSUER_MAX_COUNT)
  {
    list->m_isIssuerDropped = true;
    return;
  }

  candidate.m_isSeenOnExactName    = match->m_isExact;
  candidate.m_isSeenOnWildcardName = match->m_isWildcard;
  list->ma_issuers[list->m_issuerCount] = candidate;
  list->m_issuerCount++;
}

static void static_readNextPageAfterId(JsonReadSpan_t certificate_span, char* id_out)
{
  JsonReadSpan_t value_span = { 0 };
  if (jsonread_objectKey(certificate_span, "id", &value_span) != JSONREAD_OK ||
      jsonread_spanToStrStatus(value_span, id_out, CERTSPOTTER_CERTIFICATE_ID_MAX_LEN + 1) != JSONREAD_OK)
  {
    id_out[0] = '\0';
    return;
  }

  for (const char* digit = id_out; *digit != '\0'; digit++)
  {
    if (!isdigit((unsigned char)*digit))
    {
      id_out[0] = '\0';
      return;
    }
  }
}

static bool static_tryReadPage(const char* body, size_t body_len, void* context)
{
  CertSpotterPageReadContext_t* page = context;
  CertSpotterCertificateList_t* list = page->mp_certificateList;
  page->m_pageElementCount    = 0;
  page->ma_nextPageAfterId[0] = '\0';

  JsonReadSpan_t root_span = { 0 };
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK || root_span.mp_start[0] != '[')
    return false;

  JsonReadSpan_t            certificate_span   = { 0 };
  size_t                    certificate_offset = 0;
  CertSpotterCertificate_t  certificate;
  CertSpotterHostMatch_t    match;
  while (jsonread_arrayNextElement(root_span, &certificate_offset, &certificate_span) == JSONREAD_OK)
  {
    page->m_pageElementCount++;
    if (page->m_isPastPageCap)
      break;

    static_readNextPageAfterId(certificate_span, page->ma_nextPageAfterId);
    if (!static_tryReadCertificate(certificate_span, page->mp_hostName, &certificate, &match))
      continue;

    list->m_readCount++;
    static_keepCertificate(list, &certificate);
    static_addIssuer(list, &certificate, &match);
  }
  return true;
}

static CertSpotterStatus_t static_askCertSpotter(const char* url, int timeout_ms, CertSpotterBodyReaderFunction_t reader, void* context, unsigned int* retry_after_seconds_out)
{
  const char* const        extra_headers[] = { g_authorizationHeader, NULL };
  static const char* const header_names[]  = { RETRYAFTER_HEADER_NAME, NULL };
  const HttpRequest_t request = {
    .mp_url                  = url,
    .m_timeoutMs             = timeout_ms,
    .mp_extraHeaders         = extra_headers,
    .m_maxBodyByteCount      = CERTSPOTTER_MAX_BODY_BYTE_COUNT,
    .mp_headerNamesToCapture = header_names,
    .m_isTargetTrusted       = true,
  };
  HttpResponse_t response = http_GETWithOptions(&request);

  CertSpotterStatus_t status = CERTSPOTTER_UPSTREAM_ERROR;
  if (response.m_status == 429)
  {
    *retry_after_seconds_out = retryafter_parseSeconds(response.m_capturedHeaderValueCount > 0 ? response.mp_capturedHeaderValues[0] : NULL);
    status = CERTSPOTTER_RATE_LIMITED;
  }
  else if (response.m_status == 200 && response.mp_body != NULL &&
           reader(response.mp_body, response.m_bodyLen, context))
  {
    status = CERTSPOTTER_OK;
  }

  http_free(&response);
  return status;
}

static CertSpotterStatus_t static_cutWalk(CertSpotterCertificateList_t* list, CertSpotterStatus_t status)
{
  memset(list, 0, sizeof(*list));
  return status;
}

CertSpotterStatus_t certspotter_lookupCertificates(PGconn* conn, const QuotaRule_t* quota_rule, const char* host_name, CertSpotterCertificateList_t* list_out, unsigned int* retry_after_seconds_out)
{
  assert(quota_rule              != NULL);
  assert(host_name               != NULL);
  assert(list_out                != NULL);
  assert(retry_after_seconds_out != NULL);

  memset(list_out, 0, sizeof(*list_out));
  *retry_after_seconds_out = 0;
  if (!validate_domainName(host_name))
    return CERTSPOTTER_INVALID_NAME;
  if (!certspotter_hasApiKey())
    return CERTSPOTTER_NO_API_KEY;

  char url[sizeof(CERTSPOTTER_URL_PREFIX) - 1 + VALIDATE_DOMAIN_NAME_MAX_LEN + sizeof(CERTSPOTTER_URL_QUERY) - 1 +
           sizeof(CERTSPOTTER_URL_AFTER) - 1 + CERTSPOTTER_CERTIFICATE_ID_MAX_LEN + 1];
  int url_len = snprintf(url, sizeof(url), CERTSPOTTER_URL_PREFIX "%s" CERTSPOTTER_URL_QUERY, host_name);

  CertSpotterPageReadContext_t page = { .mp_hostName = host_name, .mp_certificateList = list_out };
  for (int page_index = 0; page_index <= CERTSPOTTER_MAX_PAGE_COUNT; page_index++)
  {
    QuotaStatus_t quota_status = quota_dbReserve(conn, quota_rule);
    if (quota_status != QUOTA_GRANTED)
      return static_cutWalk(list_out, quota_status == QUOTA_EXHAUSTED ? CERTSPOTTER_QUOTA_EXHAUSTED : CERTSPOTTER_DB_ERROR);

    page.m_isPastPageCap = page_index == CERTSPOTTER_MAX_PAGE_COUNT;
    CertSpotterStatus_t status = static_askCertSpotter(url, CERTSPOTTER_LOOKUP_TIMEOUT_MS, static_tryReadPage, &page, retry_after_seconds_out);
    if (status != CERTSPOTTER_OK)
      return static_cutWalk(list_out, status);

    if (page.m_pageElementCount == 0)
    {
      list_out->m_isComplete = true;
      return CERTSPOTTER_OK;
    }
    if (page.m_isPastPageCap)
      return CERTSPOTTER_OK;
    if (page.ma_nextPageAfterId[0] == '\0')
      return static_cutWalk(list_out, CERTSPOTTER_UPSTREAM_ERROR);

    snprintf(url + url_len, sizeof(url) - (size_t)url_len, CERTSPOTTER_URL_AFTER "%s", page.ma_nextPageAfterId);
  }
  return CERTSPOTTER_OK;
}

bool certspotter_tryReadSubdomainNames(const char* body, size_t body_len, const char* domain, SubdomainNameSet_t* name_set, bool* is_answer_empty_out)
{
  assert(body                != NULL);
  assert(domain              != NULL);
  assert(name_set            != NULL);
  assert(is_answer_empty_out != NULL);

  *is_answer_empty_out = false;

  JsonReadSpan_t root_span = { 0 };
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK || root_span.mp_start[0] != '[')
    return false;

  JsonReadSpan_t certificate_span   = { 0 };
  size_t         certificate_offset = 0;
  int            element_count      = 0;
  while (jsonread_arrayNextElement(root_span, &certificate_offset, &certificate_span) == JSONREAD_OK)
  {
    element_count++;
    JsonReadSpan_t names_span = { 0 };
    if (jsonread_objectKey(certificate_span, "dns_names", &names_span) != JSONREAD_OK)
      continue;

    JsonReadSpan_t name_span   = { 0 };
    size_t         name_offset = 0;
    while (jsonread_arrayNextElement(names_span, &name_offset, &name_span) == JSONREAD_OK)
    {
      char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
      if (jsonread_spanToStrStatus(name_span, name, sizeof(name)) == JSONREAD_OK)
        subdomain_addName(name_set, name, domain, SUBDOMAIN_SOURCE_CERTIFICATE_LOGS);
    }
  }
  *is_answer_empty_out = element_count == 0;
  return true;
}

static bool static_tryReadSubtreeNames(const char* body, size_t body_len, void* context)
{
  const CertSpotterSubtreeReadContext_t* target = context;
  return certspotter_tryReadSubdomainNames(body, body_len, target->mp_domain, target->mp_nameSet, target->mp_isAnswerEmpty);
}

CertSpotterStatus_t certspotter_lookupSubdomainNames(const char* domain, SubdomainNameSet_t* name_set, bool* is_answer_empty_out, unsigned int* retry_after_seconds_out)
{
  assert(domain                  != NULL);
  assert(name_set                != NULL);
  assert(is_answer_empty_out     != NULL);
  assert(retry_after_seconds_out != NULL);

  *is_answer_empty_out     = false;
  *retry_after_seconds_out = 0;
  
  if (!validate_domainName(domain))
    return CERTSPOTTER_INVALID_NAME;
  if (!certspotter_hasApiKey())
    return CERTSPOTTER_NO_API_KEY;

  char url[sizeof(CERTSPOTTER_URL_PREFIX) - 1 + VALIDATE_DOMAIN_NAME_MAX_LEN + sizeof(CERTSPOTTER_SUBTREE_URL_QUERY)];
  snprintf(url, sizeof(url), CERTSPOTTER_URL_PREFIX "%s" CERTSPOTTER_SUBTREE_URL_QUERY, domain);

  CertSpotterSubtreeReadContext_t target = { .mp_domain = domain, .mp_nameSet = name_set, .mp_isAnswerEmpty = is_answer_empty_out };
  return static_askCertSpotter(url, CERTSPOTTER_SUBTREE_TIMEOUT_MS, static_tryReadSubtreeNames, &target, retry_after_seconds_out);
}
