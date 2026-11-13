#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "wayback.h"
#include "http.h"
#include "jsonread.h"
#include "monotonic.h"
#include "retryafter.h"
#include "validate.h"

#define WAYBACK_MAX_BODY_BYTE_COUNT  (64 * 1024)

#define WAYBACK_CDX_URL_PREFIX        "https://web.archive.org/cdx/search/cdx?url="
#define WAYBACK_CDX_URL_QUERY         "&output=json&fl=timestamp,statuscode,mimetype&collapse=timestamp:8&limit="
#define WAYBACK_CDX_URL_SORT_REVERSE  "&sort=reverse"

#define WAYBACK_INT_TEXT_MAX_LEN 11

#define WAYBACK_CDX_FIELD_COUNT 3

static bool static_tryReadRowFields(JsonReadSpan_t row_span, JsonReadSpan_t field_spans[WAYBACK_CDX_FIELD_COUNT])
{
  JsonReadSpan_t field_span   = { 0 };
  size_t         field_offset = 0;
  int            field_count  = 0;
  while (jsonread_arrayNextElement(row_span, &field_offset, &field_span) == JSONREAD_OK)
  {
    if (field_count == WAYBACK_CDX_FIELD_COUNT)
      return false;

    field_spans[field_count++] = field_span;
  }

  return field_count == WAYBACK_CDX_FIELD_COUNT;
}

static bool static_tryReadCapture(JsonReadSpan_t row_span, WaybackCapture_t* capture)
{
  JsonReadSpan_t field_spans[WAYBACK_CDX_FIELD_COUNT];
  if (!static_tryReadRowFields(row_span, field_spans))
    return false;

  if (jsonread_spanToStrStatus(field_spans[0], capture->ma_timestamp, sizeof(capture->ma_timestamp)) != JSONREAD_OK)
    return false;
  for (int i = 0; i < WAYBACK_TIMESTAMP_LEN; i++)
  {
    if (!isdigit((unsigned char)capture->ma_timestamp[i]))
      return false;
  }

  char status_text[4];
  if (jsonread_spanToStrStatus(field_spans[1], status_text, sizeof(status_text)) != JSONREAD_OK)
    return false;
  if (strcmp(status_text, "-") == 0)
    capture->m_httpStatus = 0;
  else if (isdigit((unsigned char)status_text[0]) && isdigit((unsigned char)status_text[1]) && isdigit((unsigned char)status_text[2]))
    capture->m_httpStatus = (status_text[0] - '0') * 100 + (status_text[1] - '0') * 10 + (status_text[2] - '0');
  else
    return false;

  if (jsonread_spanToStrStatus(field_spans[2], capture->ma_mediaType, sizeof(capture->ma_mediaType)) != JSONREAD_OK ||
      strcmp(capture->ma_mediaType, "-") == 0)
  {
    capture->ma_mediaType[0] = '\0';
  }

  return true;
}

bool wayback_tryReadCaptures(const char* body, size_t body_len, WaybackCapture_t* captures_out, int max_count, int* count_out)
{
  assert(body         != NULL);
  assert(captures_out != NULL);
  assert(count_out    != NULL);
  assert(max_count    >  0);

  memset(captures_out, 0, (size_t)max_count * sizeof(captures_out[0]));
  *count_out = 0;

  JsonReadSpan_t root_span  = { 0 };
  JsonReadSpan_t row_span   = { 0 };
  size_t         row_offset = 0;
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK)
    return false;

  JsonReadStatus_t status = jsonread_arrayNextElement(root_span, &row_offset, &row_span);
  if (status == JSONREAD_ERR_NOTFOUND)
    return true;

  JsonReadSpan_t header_spans[WAYBACK_CDX_FIELD_COUNT];
  if (status != JSONREAD_OK || !static_tryReadRowFields(row_span, header_spans) ||
      !jsonread_isSpanEqual(header_spans[0], "\"timestamp\"")                   ||
      !jsonread_isSpanEqual(header_spans[1], "\"statuscode\"")                  ||
      !jsonread_isSpanEqual(header_spans[2], "\"mimetype\""))
    return false;

  int count = 0;
  while (jsonread_arrayNextElement(root_span, &row_offset, &row_span) == JSONREAD_OK)
  {
    if (count == max_count || !static_tryReadCapture(row_span, &captures_out[count]))
      return false;
    count++;
  }

  *count_out = count;
  return true;
}

WaybackStatus_t wayback_lookupCaptures(const char* host_name, WaybackOrder_t order, int capture_limit, int64_t deadline_ms, WaybackCapture_t* captures_out, int* count_out, unsigned int* retry_after_seconds_out)
{
  assert(host_name               != NULL);
  assert(captures_out            != NULL);
  assert(count_out               != NULL);
  assert(retry_after_seconds_out != NULL);
  assert(capture_limit > 0);

  *count_out               = 0;
  *retry_after_seconds_out = 0;
  if (!validate_domainName(host_name))
    return WAYBACK_INVALID_NAME;

  int64_t remaining_ms = deadline_ms - monotonic_nowMs();
  if (remaining_ms <= 0)
    return WAYBACK_UPSTREAM_ERROR;

  char url[sizeof(WAYBACK_CDX_URL_PREFIX) - 1 + VALIDATE_DOMAIN_NAME_MAX_LEN + sizeof(WAYBACK_CDX_URL_QUERY) - 1 + WAYBACK_INT_TEXT_MAX_LEN + sizeof(WAYBACK_CDX_URL_SORT_REVERSE)];
  snprintf(url, sizeof(url), WAYBACK_CDX_URL_PREFIX "%s" WAYBACK_CDX_URL_QUERY "%d%s", host_name, capture_limit, order == WAYBACK_ORDER_NEWEST_FIRST ? WAYBACK_CDX_URL_SORT_REVERSE : "");

  static const char* const header_names[] = { RETRYAFTER_HEADER_NAME, NULL };
  const HttpRequest_t request = {
    .mp_url                  = url,
    .m_timeoutMs             = remaining_ms < WAYBACK_LOOKUP_DEADLINE_MS ? (int)remaining_ms : WAYBACK_LOOKUP_DEADLINE_MS,
    .mp_extraHeaders         = NULL,
    .m_maxBodyByteCount      = WAYBACK_MAX_BODY_BYTE_COUNT,
    .mp_headerNamesToCapture = header_names,
    .m_isTargetTrusted       = true,
  };
  HttpResponse_t response = http_GETWithOptions(&request);

  WaybackStatus_t status = WAYBACK_UPSTREAM_ERROR;
  if (response.m_status == 429)
  {
    *retry_after_seconds_out = retryafter_parseSeconds(response.m_capturedHeaderValueCount > 0 ? response.mp_capturedHeaderValues[0] : NULL);
    status = WAYBACK_RATE_LIMITED;
  }
  else if (response.m_status == 200 && response.mp_body != NULL &&
           wayback_tryReadCaptures(response.mp_body, response.m_bodyLen, captures_out, capture_limit, count_out))
  {
    status = WAYBACK_OK;
  }

  http_free(&response);
  return status;
}
