#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "cveservices.h"
#include "http.h"
#include "jsonread.h"
#include "monotonic.h"
#include "retryafter.h"

#define CVESERVICES_CVE_ID_URL_PREFIX "https://cveawg.mitre.org/api/cve-id/"

#define CVESERVICES_CVE_ID_MAX_LEN 24

static bool static_isCveIdSendable(const char* cve_id)
{
  size_t len = strlen(cve_id);
  if (len == 0 || len > CVESERVICES_CVE_ID_MAX_LEN)
    return false;

  for (size_t i = 0; i < len; i++)
  {
    unsigned char byte = (unsigned char)cve_id[i];
    if (!(isupper(byte) || isdigit(byte) || byte == '-'))
      return false;
  }
  return true;
}

bool cveservices_tryReadCveIdState(const char* body, size_t body_len, CveServicesCveIdState_t* state_out)
{
  assert(body      != NULL);
  assert(state_out != NULL);

  *state_out = CVESERVICES_CVE_ID_STATE_NOT_CHECKED;

  JsonReadSpan_t root_span  = { 0 };
  JsonReadSpan_t state_span = { 0 };
  if (jsonread_root(body, body_len, &root_span) != JSONREAD_OK  ||
      jsonread_objectKey(root_span, "state", &state_span) != JSONREAD_OK)
  {
    return false;
  }

  if (jsonread_isSpanEqual(state_span, "\"PUBLISHED\""))
    *state_out = CVESERVICES_CVE_ID_STATE_PUBLISHED;
  else if (jsonread_isSpanEqual(state_span, "\"RESERVED\""))
    *state_out = CVESERVICES_CVE_ID_STATE_RESERVED;
  else if (jsonread_isSpanEqual(state_span, "\"REJECTED\""))
    *state_out = CVESERVICES_CVE_ID_STATE_REJECTED;
  else
    return false;

  return true;
}

bool cveservices_isUnknownCveIdBody(const char* body, size_t body_len)
{
  assert(body != NULL);

  JsonReadSpan_t root_span  = { 0 };
  JsonReadSpan_t error_span = { 0 };
  return jsonread_root(body, body_len, &root_span) == JSONREAD_OK           &&
         jsonread_objectKey(root_span, "error", &error_span) == JSONREAD_OK &&
         jsonread_isSpanEqual(error_span, "\"CVE_ID_NOT_FOUND\"");
}

const char* cveservices_cveIdStateName(CveServicesCveIdState_t state)
{
  switch (state)
  {
    case CVESERVICES_CVE_ID_STATE_PUBLISHED:   return "published";
    case CVESERVICES_CVE_ID_STATE_RESERVED:    return "reserved";
    case CVESERVICES_CVE_ID_STATE_REJECTED:    return "rejected";
    case CVESERVICES_CVE_ID_STATE_UNKNOWN_ID:  return "unknown_id";
    case CVESERVICES_CVE_ID_STATE_NOT_CHECKED: break;
  }
  return NULL;
}

CveServicesStatus_t cveservices_askCveIdState(const char* cve_id, int64_t deadline_ms, CveServicesCveIdState_t* state_out, unsigned int* retry_after_seconds_out)
{
  assert(cve_id                  != NULL);
  assert(state_out               != NULL);
  assert(retry_after_seconds_out != NULL);

  *state_out               = CVESERVICES_CVE_ID_STATE_NOT_CHECKED;
  *retry_after_seconds_out = 0;

  if (!static_isCveIdSendable(cve_id))
    return CVESERVICES_INVALID_ID;

  int64_t remaining_ms = deadline_ms - monotonic_nowMs();
  if (remaining_ms <= 0)
    return CVESERVICES_UPSTREAM_ERROR;

  char url[sizeof(CVESERVICES_CVE_ID_URL_PREFIX) + CVESERVICES_CVE_ID_MAX_LEN];
  int url_len = snprintf(url, sizeof(url), CVESERVICES_CVE_ID_URL_PREFIX "%s", cve_id);
  if (url_len < 0 || (size_t)url_len >= sizeof(url))
    return CVESERVICES_INVALID_ID;

  static const char* const header_names[] = { RETRYAFTER_HEADER_NAME, NULL };
  const HttpRequest_t request = {
    .mp_url                  = url,
    .m_timeoutMs             = remaining_ms < CVESERVICES_ASK_DEADLINE_MS ? (int)remaining_ms : CVESERVICES_ASK_DEADLINE_MS,
    .mp_extraHeaders         = NULL,
    .m_maxBodyByteCount      = CVESERVICES_MAX_BODY_BYTE_COUNT,
    .mp_headerNamesToCapture = header_names,
    .m_isTargetTrusted       = true,
  };
  HttpResponse_t response = http_GETWithOptions(&request);

  CveServicesStatus_t status = CVESERVICES_UPSTREAM_ERROR;
  if (response.m_status == 429)
  {
    *retry_after_seconds_out = retryafter_parseSeconds(response.m_capturedHeaderValueCount > 0 ? response.mp_capturedHeaderValues[0] : NULL);
    status = CVESERVICES_RATE_LIMITED;
  }
  else if (response.m_status == 200 && response.mp_body != NULL &&
           cveservices_tryReadCveIdState(response.mp_body, response.m_bodyLen, state_out))
  {
    status = CVESERVICES_OK;
  }
  else if (response.m_status == 404 && response.mp_body != NULL &&
           cveservices_isUnknownCveIdBody(response.mp_body, response.m_bodyLen))
  {
    *state_out = CVESERVICES_CVE_ID_STATE_UNKNOWN_ID;
    status     = CVESERVICES_OK;
  }

  http_free(&response);
  return status;
}
