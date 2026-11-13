#include <stddef.h>
#include <string.h>

#include "wayback_stub.h"

#define WAYBACK_STUB_DEFAULT_ANSWERS {                                                                    \
  { .m_status = WAYBACK_OK, .m_captureCount = 2,                                                          \
    .ma_captures = { { "20261024162230", 200, "text/html" }, { "20190305010203", 301, "text/plain" } } },  \
  { .m_status = WAYBACK_OK, .m_captureCount = 1,                                                          \
    .ma_captures = { { "20020120142510", 404, "application/pdf" } } },                                   \
}

const WaybackStubAnswer_t g_stub_WAYBACK_default_answers[WAYBACK_STUB_CALL_MAX_COUNT] = WAYBACK_STUB_DEFAULT_ANSWERS;

WaybackStubAnswer_t g_stub_WAYBACK_answers[WAYBACK_STUB_CALL_MAX_COUNT] = WAYBACK_STUB_DEFAULT_ANSWERS;

int            g_stub_WAYBACK_lookup_count = 0;
char           g_stub_WAYBACK_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
WaybackOrder_t g_stub_WAYBACK_orders[WAYBACK_STUB_CALL_MAX_COUNT];
int            g_stub_WAYBACK_capture_limits[WAYBACK_STUB_CALL_MAX_COUNT];
int64_t        g_stub_WAYBACK_deadlines[WAYBACK_STUB_CALL_MAX_COUNT];

void (*g_stub_WAYBACK_on_call)(void) = NULL;

WaybackStatus_t wayback_lookupCaptures(const char* host_name, WaybackOrder_t order, int capture_limit, int64_t deadline_ms, WaybackCapture_t* captures_out, int* count_out, unsigned int* retry_after_seconds_out)
{
  int call_index = g_stub_WAYBACK_lookup_count++;
  if (g_stub_WAYBACK_on_call)
    g_stub_WAYBACK_on_call();
  strncpy(g_stub_WAYBACK_last_lookup_name, host_name, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_WAYBACK_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';

  *count_out               = 0;
  *retry_after_seconds_out = 0;
  memset(captures_out, 0, (size_t)capture_limit * sizeof(captures_out[0]));
  if (call_index >= WAYBACK_STUB_CALL_MAX_COUNT)
    return WAYBACK_UPSTREAM_ERROR;

  g_stub_WAYBACK_orders[call_index]         = order;
  g_stub_WAYBACK_capture_limits[call_index] = capture_limit;
  g_stub_WAYBACK_deadlines[call_index]      = deadline_ms;

  const WaybackStubAnswer_t* answer = &g_stub_WAYBACK_answers[call_index];
  if (answer->m_status == WAYBACK_OK)
  {
    for (int i = 0; i < answer->m_captureCount && i < capture_limit && i < WAYBACK_LATEST_CAPTURE_MAX_COUNT; i++)
      captures_out[i] = answer->ma_captures[i];
    *count_out = answer->m_captureCount;
  }
  if (answer->m_status == WAYBACK_RATE_LIMITED)
    *retry_after_seconds_out = answer->m_retryAfterSeconds;
  return answer->m_status;
}
