#include <assert.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#include "shodan.h"
#include "cve.h"
#include "http.h"
#include "jsonread.h"
#include "validate.h"

#define SHODAN_HOST_URL_PREFIX  "https://api.shodan.io/shodan/host/"
#define SHODAN_HOST_URL_KEY     "?key="
#define SHODAN_HOST_URL_SUFFIX  "&minify=true"

#define SHODAN_API_INFO_URL_PREFIX  "https://api.shodan.io/api-info?key="

#define SHODAN_STRINGIFY_(value)  #value
#define SHODAN_STRINGIFY(value)   SHODAN_STRINGIFY_(value)
#define SHODAN_COUNT_URL_PREFIX   "https://api.shodan.io/shodan/host/count?key="
#define SHODAN_COUNT_URL_QUERY    "&query=ip:"
#define SHODAN_COUNT_URL_FACETS   "&facets=port:" SHODAN_STRINGIFY(SHODAN_FACET_SIZE) \
                                  ",vuln:" SHODAN_STRINGIFY(SHODAN_FACET_SIZE)        \
                                  ",tag:" SHODAN_STRINGIFY(SHODAN_FACET_SIZE)

#define SHODAN_IP_TEXT_MAX_LEN  (INET6_ADDRSTRLEN - 1)

#define SHODAN_TEXT_BUF_SIZE  (VALIDATE_DOMAIN_NAME_MAX_LEN + 1)
_Static_assert(SHODAN_TAG_MAX_LEN   < SHODAN_TEXT_BUF_SIZE, "a tag must fit the text buffer");
_Static_assert(CVELOOKUP_ID_MAX_LEN < SHODAN_TEXT_BUF_SIZE, "a CVE id must fit the text buffer");

typedef bool (*ShodanTextCheckFunction_t)(const char* text);

typedef struct {
  const char*                mp_jsonKey;
  size_t                     m_maxLen;
  ShodanTextCheckFunction_t  m_isKeptFunction;
  bool                       m_isUpperCased;
  ShodanTextArray_t*         mp_array;
} ShodanTextList_t;

bool shodan_isKeyAccepted(const char* vendor_key)
{
  size_t key_len = strnlen(vendor_key, SHODAN_KEY_MAX_LEN + 1);
  if (key_len == 0 || key_len > SHODAN_KEY_MAX_LEN)
    return false;

  for (size_t i = 0; i < key_len; i++)
    if (!isalnum((unsigned char)vendor_key[i]))
      return false;
  return true;
}

static HttpResponse_t static_sendGet(const char* url)
{
  const HttpRequest_t request = {
    .mp_url                   = url,
    .m_timeoutMs              = SHODAN_TIMEOUT_MS,
    .m_maxBodyByteCount       = SHODAN_MAX_BODY_BYTE_COUNT,
    .m_isTargetTrusted        = true,
    .m_isRedirectLeftToCaller = true,
  };
  return http_GETWithOptions(&request);
}

static ShodanStatus_t static_mapOtherStatus(int http_status, unsigned int* retry_after_seconds_out)
{
  if (http_status == 401 || http_status == 403)
    return SHODAN_KEY_REJECTED;
  else if (http_status == 429)
  {
    *retry_after_seconds_out = SHODAN_RATE_LIMIT_RETRY_SECONDS;
    return SHODAN_RATE_LIMITED;
  }
  return SHODAN_UNAVAILABLE;
}

static bool static_tryFindList(JsonReadSpan_t object_span, const char* key, JsonReadSpan_t* list_span_out, size_t* element_count_out)
{
  JsonReadStatus_t status = jsonread_objectKey(object_span, key, list_span_out);
  if (status == JSONREAD_ERR_NOTFOUND)
    return true;

  return status == JSONREAD_OK && jsonread_arrayLen(*list_span_out, element_count_out) == JSONREAD_OK;
}

static bool static_tryReadTextList(JsonReadSpan_t object_span, const ShodanTextList_t* list)
{
  JsonReadSpan_t list_span     = { 0 };
  size_t         element_count = 0;
  if (!static_tryFindList(object_span, list->mp_jsonKey, &list_span, &element_count))
    return false;
  if (element_count == 0)
    return true;

  ShodanTextArray_t* text_array = list->mp_array;
  text_array->mp_items = calloc(element_count, sizeof(char*));
  if (text_array->mp_items == NULL)
    return false;

  JsonReadSpan_t   element_span   = { 0 };
  size_t           element_offset = 0;
  JsonReadStatus_t next_status;
  while ((next_status = jsonread_arrayNextElement(list_span, &element_offset, &element_span)) == JSONREAD_OK)
  {
    char             text[SHODAN_TEXT_BUF_SIZE];
    JsonReadStatus_t text_status = jsonread_spanToStrStatus(element_span, text, list->m_maxLen + 1);
    if (text_status == JSONREAD_ERR_TYPE || text_status == JSONREAD_ERR_SYNTAX)
      return false;
    if (text_status != JSONREAD_OK || text[0] == '\0' || (list->m_isKeptFunction != NULL && !list->m_isKeptFunction(text)))
    {
      text_array->m_skippedCount++;
      continue;
    }

    char* kept = strdup(text);
    if (kept == NULL)
      return false;
    text_array->mp_items[text_array->m_count++] = kept;
  }
  if (next_status != JSONREAD_ERR_NOTFOUND)
    return false;

  if (text_array->m_count == 0)
  {
    free(text_array->mp_items);
    text_array->mp_items = NULL;
  }
  return true;
}

static bool static_tryReadPorts(JsonReadSpan_t object_span, ShodanHost_t* host)
{
  JsonReadSpan_t list_span     = { 0 };
  size_t         element_count = 0;
  if (!static_tryFindList(object_span, "ports", &list_span, &element_count))
    return false;
  if (element_count == 0)
    return true;

  host->mp_ports = calloc(element_count, sizeof(int));
  if (host->mp_ports == NULL)
    return false;

  JsonReadSpan_t   element_span   = { 0 };
  size_t           element_offset = 0;
  JsonReadStatus_t next_status;
  while ((next_status = jsonread_arrayNextElement(list_span, &element_offset, &element_span)) == JSONREAD_OK)
  {
    long             port        = 0;
    JsonReadStatus_t port_status = jsonread_spanToLongStatus(element_span, &port);
    if (port_status == JSONREAD_ERR_RANGE || (port_status == JSONREAD_OK && (port < 0 || port > SHODAN_PORT_MAX)))
    {
      host->m_skippedPortCount++;
      continue;
    }
    if (port_status != JSONREAD_OK)
      return false;
    host->mp_ports[host->m_portCount++] = (int)port;
  }
  if (next_status != JSONREAD_ERR_NOTFOUND)
    return false;

  if (host->m_portCount == 0)
  {
    free(host->mp_ports);
    host->mp_ports = NULL;
  }
  return true;
}

static bool static_tryReadLastUpdate(JsonReadSpan_t object_span, ShodanHost_t* host)
{
  JsonReadSpan_t   value_span = { 0 };
  JsonReadStatus_t status     = jsonread_objectKey(object_span, "last_update", &value_span);
  if (status == JSONREAD_ERR_NOTFOUND)
    return true;
  if (status != JSONREAD_OK)
    return false;

  JsonReadStatus_t text_status = jsonread_spanToStrStatus(value_span, host->ma_lastUpdate, sizeof(host->ma_lastUpdate));
  if (text_status == JSONREAD_ERR_TYPE || text_status == JSONREAD_ERR_SYNTAX)
    return false;
  if (text_status != JSONREAD_OK)
    host->ma_lastUpdate[0] = '\0';
  return true;
}

static bool static_tryReadHost(const char* body, size_t body_len, ShodanHost_t* host)
{
  JsonReadSpan_t root_span = { 0 };
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK)
    return false;

  const ShodanTextList_t text_lists[] = {
    { "vulns",     CVELOOKUP_ID_MAX_LEN,         validate_cveId, false, &host->m_vulns     },
    { "hostnames", VALIDATE_DOMAIN_NAME_MAX_LEN, NULL,           false, &host->m_hostnames },
    { "tags",      SHODAN_TAG_MAX_LEN,           NULL,           false, &host->m_tags      },
  };
  if (!static_tryReadPorts(root_span, host))
    return false;
  for (size_t i = 0; i < sizeof(text_lists) / sizeof(text_lists[0]); i++)
    if (!static_tryReadTextList(root_span, &text_lists[i]))
      return false;
  return static_tryReadLastUpdate(root_span, host);
}

static bool static_tryNextFacetValue(JsonReadSpan_t list_span, size_t* offset, JsonReadSpan_t* value_span_out, JsonReadStatus_t* next_status_out)
{
  JsonReadSpan_t element_span = { 0 };
  *next_status_out = jsonread_arrayNextElement(list_span, offset, &element_span);
  if (*next_status_out != JSONREAD_OK)
    return false;
  if (jsonread_objectKey(element_span, "value", value_span_out) == JSONREAD_OK)
    return true;

  *next_status_out = JSONREAD_ERR_TYPE;
  return false;
}

static bool static_tryReadFacetTexts(JsonReadSpan_t facets_span, const ShodanTextList_t* list)
{
  JsonReadSpan_t list_span     = { 0 };
  size_t         element_count = 0;
  if (!static_tryFindList(facets_span, list->mp_jsonKey, &list_span, &element_count))
    return false;
  if (element_count == 0)
    return true;

  ShodanTextArray_t* text_array = list->mp_array;
  text_array->mp_items = calloc(element_count, sizeof(char*));
  if (text_array->mp_items == NULL)
    return false;

  JsonReadSpan_t   value_span     = { 0 };
  size_t           element_offset = 0;
  JsonReadStatus_t next_status    = JSONREAD_OK;
  while (static_tryNextFacetValue(list_span, &element_offset, &value_span, &next_status))
  {
    char             text[SHODAN_TEXT_BUF_SIZE];
    JsonReadStatus_t text_status = jsonread_spanToStrStatus(value_span, text, list->m_maxLen + 1);
    if (text_status == JSONREAD_ERR_TYPE || text_status == JSONREAD_ERR_SYNTAX)
      return false;
    if (text_status == JSONREAD_OK && list->m_isUpperCased)
      for (char* cursor = text; *cursor != '\0'; cursor++)
        *cursor = (char)toupper((unsigned char)*cursor);
    if (text_status != JSONREAD_OK || text[0] == '\0' || (list->m_isKeptFunction != NULL && !list->m_isKeptFunction(text)))
    {
      text_array->m_skippedCount++;
      continue;
    }

    char* kept = strdup(text);
    if (kept == NULL)
      return false;
    text_array->mp_items[text_array->m_count++] = kept;
  }
  if (next_status != JSONREAD_ERR_NOTFOUND)
    return false;

  if (text_array->m_count == 0)
  {
    free(text_array->mp_items);
    text_array->mp_items = NULL;
  }
  return true;
}

static bool static_tryReadFacetPorts(JsonReadSpan_t facets_span, ShodanHost_t* host)
{
  JsonReadSpan_t list_span     = { 0 };
  size_t         element_count = 0;
  if (!static_tryFindList(facets_span, "port", &list_span, &element_count))
    return false;
  if (element_count == 0)
    return true;

  host->mp_ports = calloc(element_count, sizeof(int));
  if (host->mp_ports == NULL)
    return false;

  JsonReadSpan_t   value_span     = { 0 };
  size_t           element_offset = 0;
  JsonReadStatus_t next_status    = JSONREAD_OK;
  while (static_tryNextFacetValue(list_span, &element_offset, &value_span, &next_status))
  {
    long             port        = 0;
    JsonReadStatus_t port_status = jsonread_spanToLongStatus(value_span, &port);
    if (port_status == JSONREAD_ERR_RANGE || (port_status == JSONREAD_OK && (port < 0 || port > SHODAN_PORT_MAX)))
    {
      host->m_skippedPortCount++;
      continue;
    }
    if (port_status != JSONREAD_OK)
      return false;
    host->mp_ports[host->m_portCount++] = (int)port;
  }
  if (next_status != JSONREAD_ERR_NOTFOUND)
    return false;

  if (host->m_portCount == 0)
  {
    free(host->mp_ports);
    host->mp_ports = NULL;
  }
  return true;
}

static bool static_tryReadFacets(const char* body, size_t body_len, ShodanHost_t* host, long* total_out)
{
  JsonReadSpan_t root_span = { 0 };
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK)
    return false;

  JsonReadSpan_t total_span = { 0 };
  if (jsonread_objectKey(root_span, "total", &total_span) != JSONREAD_OK ||
      jsonread_spanToLongStatus(total_span, total_out) != JSONREAD_OK)
  {
    return false;
  }

  JsonReadSpan_t   facets_span   = { 0 };
  JsonReadStatus_t facets_status = jsonread_objectKey(root_span, "facets", &facets_span);
  if (facets_status == JSONREAD_ERR_NOTFOUND)
    return true;
  if (facets_status != JSONREAD_OK)
    return false;

  const ShodanTextList_t text_lists[] = {
    { "vuln", CVELOOKUP_ID_MAX_LEN, validate_cveId, true,  &host->m_vulns },
    { "tag",  SHODAN_TAG_MAX_LEN,   NULL,           false, &host->m_tags  },
  };
  if (!static_tryReadFacetPorts(facets_span, host))
    return false;
  for (size_t i = 0; i < sizeof(text_lists) / sizeof(text_lists[0]); i++)
    if (!static_tryReadFacetTexts(facets_span, &text_lists[i]))
      return false;
  host->m_isVulnListCut = host->m_vulns.m_count + host->m_vulns.m_skippedCount >= SHODAN_FACET_SIZE;
  return true;
}

static ShodanStatus_t static_lookupFacets(const char* vendor_key, const char* ip_text, ShodanHost_t* host_out, unsigned int* retry_after_seconds_out)
{
  char url[sizeof(SHODAN_COUNT_URL_PREFIX) + SHODAN_KEY_MAX_LEN + sizeof(SHODAN_COUNT_URL_QUERY) + SHODAN_IP_TEXT_MAX_LEN + sizeof(SHODAN_COUNT_URL_FACETS)];
  snprintf(url, sizeof(url), SHODAN_COUNT_URL_PREFIX "%s" SHODAN_COUNT_URL_QUERY "%s" SHODAN_COUNT_URL_FACETS, vendor_key, ip_text);
  HttpResponse_t response = static_sendGet(url);
  OPENSSL_cleanse(url, sizeof(url));

  ShodanStatus_t status = SHODAN_UNAVAILABLE;
  long           total  = 0;
  if (response.m_status == 200)
  {
    if (response.mp_body != NULL && static_tryReadFacets(response.mp_body, response.m_bodyLen, host_out, &total))
      status = total > 0 ? SHODAN_OK : SHODAN_NOT_FOUND;
  }
  else
    status = static_mapOtherStatus(response.m_status, retry_after_seconds_out);

  http_free(&response);
  return status;
}

ShodanStatus_t shodan_lookupHost(const char* vendor_key, const char* ip_text, ShodanHost_t* host_out, unsigned int* retry_after_seconds_out)
{
  assert(vendor_key              != NULL);
  assert(ip_text                 != NULL);
  assert(host_out                != NULL);
  assert(retry_after_seconds_out != NULL);

  memset(host_out, 0, sizeof(*host_out));
  *retry_after_seconds_out = 0;

  if (!shodan_isKeyAccepted(vendor_key))
    return SHODAN_KEY_REJECTED;

  size_t ip_len = strnlen(ip_text, SHODAN_IP_TEXT_MAX_LEN + 1);
  if (ip_len == 0 || ip_len > SHODAN_IP_TEXT_MAX_LEN)
    return SHODAN_UNAVAILABLE;

  char url[sizeof(SHODAN_HOST_URL_PREFIX) + SHODAN_IP_TEXT_MAX_LEN + sizeof(SHODAN_HOST_URL_KEY) + SHODAN_KEY_MAX_LEN + sizeof(SHODAN_HOST_URL_SUFFIX)];
  snprintf(url, sizeof(url), SHODAN_HOST_URL_PREFIX "%s" SHODAN_HOST_URL_KEY "%s" SHODAN_HOST_URL_SUFFIX, ip_text, vendor_key);
  HttpResponse_t response = static_sendGet(url);
  OPENSSL_cleanse(url, sizeof(url));

  ShodanStatus_t status         = SHODAN_UNAVAILABLE;
  bool           is_from_facets = false;
  if (response.m_status == 200)
  {
    if (response.mp_body != NULL && static_tryReadHost(response.mp_body, response.m_bodyLen, host_out))
      status = SHODAN_OK;
  }
  else if (response.m_status == 404)
    status = SHODAN_NOT_FOUND;
  else if (response.m_status == 403)
  {
    http_free(&response);
    is_from_facets = true;
    status         = static_lookupFacets(vendor_key, ip_text, host_out, retry_after_seconds_out);
  }
  else
    status = static_mapOtherStatus(response.m_status, retry_after_seconds_out);

  http_free(&response);
  if (status != SHODAN_OK)
    shodan_freeHost(host_out);
  host_out->m_isFromFacets = is_from_facets;

  return status;
}

ShodanStatus_t shodan_checkKey(const char* vendor_key, unsigned int* retry_after_seconds_out)
{
  assert(vendor_key              != NULL);
  assert(retry_after_seconds_out != NULL);

  *retry_after_seconds_out = 0;
  if (!shodan_isKeyAccepted(vendor_key))
    return SHODAN_KEY_REJECTED;

  char url[sizeof(SHODAN_API_INFO_URL_PREFIX) + SHODAN_KEY_MAX_LEN];
  snprintf(url, sizeof(url), SHODAN_API_INFO_URL_PREFIX "%s", vendor_key);
  HttpResponse_t response = static_sendGet(url);
  OPENSSL_cleanse(url, sizeof(url));

  ShodanStatus_t status = response.m_status == 200 ? SHODAN_OK : static_mapOtherStatus(response.m_status, retry_after_seconds_out);
  http_free(&response);
  return status;
}

static void static_freeTextList(char** list, size_t count)
{
  for (size_t i = 0; i < count; i++)
    free(list[i]);
  free(list);
}

void shodan_freeHost(ShodanHost_t* host)
{
  assert(host != NULL);

  free(host->mp_ports);
  static_freeTextList(host->m_vulns.mp_items,     host->m_vulns.m_count);
  static_freeTextList(host->m_hostnames.mp_items, host->m_hostnames.m_count);
  static_freeTextList(host->m_tags.mp_items,      host->m_tags.m_count);
  memset(host, 0, sizeof(*host));
}
