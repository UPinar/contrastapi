#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "hibp.h"
#include "http.h"
#include "retryafter.h"
#include "validate.h"

#define HIBP_TIMEOUT_MS      5000
#define HIBP_RANGE_URL       "https://api.pwnedpasswords.com/range/"
#define HIBP_PADDING_HEADER  "Add-Padding: true"

#define HIBP_MIN_LINE_LEN    (HIBP_SUFFIX_LEN + 2)

static bool static_isSameHex(const char* left, const char* right, size_t len)
{
  for (size_t i = 0; i < len; i++)
    if (toupper((unsigned char)left[i]) != toupper((unsigned char)right[i]))
      return false;

  return true;
}

static bool static_tryReadSuffixAndBreachCount(const char* line, size_t line_len, uint64_t* breach_count_out)
{
  if (line_len < HIBP_MIN_LINE_LEN || line[HIBP_SUFFIX_LEN] != ':')
    return false;
  
  for (size_t i = 0; i < HIBP_SUFFIX_LEN; i++)
    if (!isxdigit((unsigned char)line[i]))
      return false;

  uint64_t breach_count = 0;
  for (size_t i = HIBP_SUFFIX_LEN + 1; i < line_len; i++)
  {
    if (!isdigit((unsigned char)line[i]))
      return false;
    
    uint64_t digit = (uint64_t)(line[i] - '0');
    if (breach_count > (UINT64_MAX - digit) / 10)
      return false;
    breach_count = breach_count * 10 + digit;
  }
  *breach_count_out = breach_count;
  return true;
}

static bool static_tryReadNextLine(const char** cursor, const char* body_end, const char** line_out, size_t* line_len_out)
{
  if (*cursor >= body_end)
    return false;

  const char* line     = *cursor;
  const char* line_end = memchr(line, '\n', (size_t)(body_end - line));
  if (line_end == NULL)
  {
    line_end = body_end;
    *cursor  = body_end;
  }
  else
    *cursor = line_end + 1;

  size_t line_len = (size_t)(line_end - line);
  if (line_len > 0 && line[line_len - 1] == '\r')
    line_len--;
  
  *line_out     = line;
  *line_len_out = line_len;
  return true;
}

bool hibp_tryReadBreachCount(const char* body, size_t body_len, const char* suffix, uint64_t* breach_count_out)
{
  assert(body             != NULL);
  assert(suffix           != NULL);
  assert(breach_count_out != NULL);

  *breach_count_out = 0;
  if (memchr(body, '\0', body_len) != NULL)
    return false;

  bool        has_readable_line = false;
  const char* cursor            = body;
  const char* body_end          = body + body_len;
  const char* line              = NULL;
  size_t      line_len          = 0;
  while (static_tryReadNextLine(&cursor, body_end, &line, &line_len))
  {
    uint64_t breach_count     = 0;
    bool     is_readable      = static_tryReadSuffixAndBreachCount(line, line_len, &breach_count);
    bool     is_our_hash_line = line_len >= HIBP_SUFFIX_LEN && static_isSameHex(line, suffix, HIBP_SUFFIX_LEN);
    if (is_our_hash_line)
    {
      if (!is_readable)
        return false;
      
      *breach_count_out = breach_count;
      return true;
    }
    if (is_readable)
      has_readable_line = true;
  }
  return has_readable_line;
}

HibpStatus_t hibp_check(const char* sha1_hex, PASSWORDCHECKRecord_t* record_out, unsigned int* retry_after_seconds_out)
{
  assert(sha1_hex                != NULL);
  assert(record_out              != NULL);
  assert(retry_after_seconds_out != NULL);

  memset(record_out, 0, sizeof(*record_out));
  *retry_after_seconds_out = 0;

  if (!validate_sha1Hex(sha1_hex))
    return HIBP_INVALID_HASH;
  
  for (size_t i = 0; i < HIBP_PREFIX_LEN; i++)
    record_out->ma_hashPrefix[i] = (char)toupper((unsigned char)sha1_hex[i]);

  char range_url[sizeof(HIBP_RANGE_URL) + HIBP_PREFIX_LEN];
  snprintf(range_url, sizeof(range_url), "%s%s", HIBP_RANGE_URL, record_out->ma_hashPrefix);

  static const char* const extra_headers[] = { HIBP_PADDING_HEADER, NULL };
  static const char* const header_names[]  = { RETRYAFTER_HEADER_NAME, NULL };
  const HttpRequest_t request = {
    .mp_url                  = range_url,
    .m_timeoutMs             = HIBP_TIMEOUT_MS,
    .mp_extraHeaders         = extra_headers,
    .mp_headerNamesToCapture = header_names,
    .m_isTargetTrusted       = true,
  };
  HttpResponse_t http_resp    = http_GETWithOptions(&request);
  HibpStatus_t   hibp_status  = HIBP_UPSTREAM_ERROR;
  const char*    hash_suffix  = sha1_hex + HIBP_PREFIX_LEN;
  uint64_t       breach_count = 0;
  if (http_resp.m_status == 429)
  {
    *retry_after_seconds_out = retryafter_parseSeconds(http_resp.m_capturedHeaderValueCount > 0 ? http_resp.mp_capturedHeaderValues[0] : NULL);
    hibp_status = HIBP_RATE_LIMITED;
  }
  else if ( http_resp.m_status == 200   &&
            http_resp.mp_body != NULL   &&
            hibp_tryReadBreachCount(http_resp.mp_body, http_resp.m_bodyLen, hash_suffix, &breach_count))
  {
    record_out->m_breachCount = breach_count;
    hibp_status               = HIBP_OK;
  }

  http_free(&http_resp);
  return hibp_status;
}
