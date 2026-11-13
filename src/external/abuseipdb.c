#include <assert.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>

#include "abuseipdb.h"
#include "http.h"
#include "jsonread.h"
#include "retryafter.h"

#define ABUSEIPDB_CHECK_URL_PREFIX  "https://api.abuseipdb.com/api/v2/check?ipAddress="
#define ABUSEIPDB_CHECK_URL_SUFFIX  "&maxAgeInDays=90"

#define ABUSEIPDB_KEY_HEADER_PREFIX  "Key: "

#define ABUSEIPDB_ACCEPT_HEADER  "Accept: application/json"

#define ABUSEIPDB_IP_TEXT_MAX_LEN  (INET6_ADDRSTRLEN - 1)

bool abuseipdb_isKeyAccepted(const char* vendor_key)
{
  size_t key_len = strnlen(vendor_key, ABUSEIPDB_KEY_MAX_LEN + 1);
  if (key_len == 0 || key_len > ABUSEIPDB_KEY_MAX_LEN)
    return false;

  for (size_t i = 0; i < key_len; i++)
  {
    unsigned char byte = (unsigned char)vendor_key[i];
    if (byte < '!' || byte > '~')
      return false;
  }
  return true;
}

static bool static_tryReadCount(JsonReadSpan_t data_span, const char* key, long max_value, int* value_out)
{
  JsonReadSpan_t value_span = { 0 };
  long           value      = 0;
  if (jsonread_objectKey(data_span, key, &value_span) != JSONREAD_OK ||
      jsonread_spanToLongStatus(value_span, &value) != JSONREAD_OK   ||
      value < 0 || value > max_value)
    return false;

  *value_out = (int)value;
  return true;
}

static bool static_tryReadNullableText(JsonReadSpan_t data_span, const char* key, char* text_out, size_t text_size)
{
  JsonReadSpan_t   value_span = { 0 };
  JsonReadStatus_t status     = jsonread_objectKey(data_span, key, &value_span);
  if (status == JSONREAD_ERR_NOTFOUND)
    return true;
  if (status != JSONREAD_OK)
    return false;
  if (jsonread_isSpanEqual(value_span, "null"))
    return true;

  JsonReadStatus_t text_status = jsonread_spanToStrStatus(value_span, text_out, text_size);
  if (text_status == JSONREAD_ERR_TYPE || text_status == JSONREAD_ERR_SYNTAX)
    return false;
  if (text_status != JSONREAD_OK)
    text_out[0] = '\0';
  return true;
}

static bool static_tryReadWhitelist(JsonReadSpan_t data_span, AbuseIpDbWhitelist_t* whitelist_out)
{
  JsonReadSpan_t   value_span = { 0 };
  JsonReadStatus_t status     = jsonread_objectKey(data_span, "isWhitelisted", &value_span);
  if (status == JSONREAD_ERR_NOTFOUND)
    return true;
  if (status != JSONREAD_OK)
    return false;
  if (jsonread_isSpanEqual(value_span, "null"))
    return true;

  bool is_whitelisted = false;
  if (jsonread_spanToBoolStatus(value_span, &is_whitelisted) != JSONREAD_OK)
    return false;
  *whitelist_out = is_whitelisted ? ABUSEIPDB_WHITELIST_YES : ABUSEIPDB_WHITELIST_NO;
  return true;
}

static bool static_tryReadReport(const char* body, size_t body_len, AbuseIpDbReport_t* report_out)
{
  JsonReadSpan_t root_span = { 0 };
  JsonReadSpan_t data_span = { 0 };
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK || jsonread_objectKey(root_span, "data", &data_span) != JSONREAD_OK)
    return false;

  return static_tryReadCount(data_span, "abuseConfidenceScore", ABUSEIPDB_SCORE_MAX, &report_out->m_abuseConfidenceScore)              &&
         static_tryReadCount(data_span, "totalReports", INT_MAX, &report_out->m_reportCount)                                           &&
         static_tryReadCount(data_span, "numDistinctUsers", INT_MAX, &report_out->m_distinctReporterCount)                             &&
         static_tryReadNullableText(data_span, "lastReportedAt", report_out->ma_lastReportedAt, sizeof(report_out->ma_lastReportedAt)) &&
         static_tryReadNullableText(data_span, "usageType", report_out->ma_usageType, sizeof(report_out->ma_usageType))                &&
         static_tryReadWhitelist(data_span, &report_out->m_whitelist);
}

static unsigned int static_readRetryAfterSeconds(const HttpResponse_t* response)
{
  const char* reset_value       = response->m_capturedHeaderValueCount > 0 ? response->mp_capturedHeaderValues[0] : NULL;
  const char* retry_after_value = response->m_capturedHeaderValueCount > 1 ? response->mp_capturedHeaderValues[1] : NULL;

  unsigned int seconds = 0;
  if (retryafter_tryReadResetSeconds(reset_value, time(NULL), &seconds))
    return seconds;
  return retryafter_parseSeconds(retry_after_value);
}

AbuseIpDbStatus_t abuseipdb_checkAddress(const char* vendor_key, const char* ip_text, AbuseIpDbReport_t* report_out, unsigned int* retry_after_seconds_out)
{
  assert(vendor_key              != NULL);
  assert(ip_text                 != NULL);
  assert(report_out              != NULL);
  assert(retry_after_seconds_out != NULL);

  memset(report_out, 0, sizeof(*report_out));
  *retry_after_seconds_out = 0;

  if (!abuseipdb_isKeyAccepted(vendor_key))
    return ABUSEIPDB_KEY_REJECTED;
  size_t ip_len = strnlen(ip_text, ABUSEIPDB_IP_TEXT_MAX_LEN + 1);
  if (ip_len == 0 || ip_len > ABUSEIPDB_IP_TEXT_MAX_LEN)
    return ABUSEIPDB_UNAVAILABLE;

  char url[sizeof(ABUSEIPDB_CHECK_URL_PREFIX) + ABUSEIPDB_IP_TEXT_MAX_LEN + sizeof(ABUSEIPDB_CHECK_URL_SUFFIX)];
  snprintf(url, sizeof(url), ABUSEIPDB_CHECK_URL_PREFIX "%s" ABUSEIPDB_CHECK_URL_SUFFIX, ip_text);
  char key_header[sizeof(ABUSEIPDB_KEY_HEADER_PREFIX) + ABUSEIPDB_KEY_MAX_LEN];
  snprintf(key_header, sizeof(key_header), ABUSEIPDB_KEY_HEADER_PREFIX "%s", vendor_key);

  const char* const        extra_headers[] = { key_header, ABUSEIPDB_ACCEPT_HEADER, NULL };
  static const char* const header_names[]  = { RETRYAFTER_RESET_HEADER_NAME, RETRYAFTER_HEADER_NAME, NULL };
  const HttpRequest_t request = {
    .mp_url                   = url,
    .m_timeoutMs              = ABUSEIPDB_TIMEOUT_MS,
    .mp_extraHeaders          = extra_headers,
    .m_maxBodyByteCount       = ABUSEIPDB_MAX_BODY_BYTE_COUNT,
    .mp_headerNamesToCapture  = header_names,
    .m_isTargetTrusted        = true,
    .m_isRedirectLeftToCaller = true,
  };
  HttpResponse_t response = http_GETWithOptions(&request);
  OPENSSL_cleanse(key_header, sizeof(key_header));

  AbuseIpDbStatus_t status = ABUSEIPDB_UNAVAILABLE;
  if (response.m_status == 200)
  {
    if (response.mp_body != NULL && static_tryReadReport(response.mp_body, response.m_bodyLen, report_out))
      status = ABUSEIPDB_OK;
  }
  else if (response.m_status == 401 || response.m_status == 403)
    status = ABUSEIPDB_KEY_REJECTED;
  else if (response.m_status == 429)
  {
    *retry_after_seconds_out = static_readRetryAfterSeconds(&response);
    status                   = ABUSEIPDB_RATE_LIMITED;
  }

  http_free(&response);
  if (status != ABUSEIPDB_OK)
    memset(report_out, 0, sizeof(*report_out));
  return status;
}
