#include <string.h>

#include "external/hibp.h"

HibpStatus_t g_stub_PASSWORDCHECK_status       = HIBP_OK;
uint64_t     g_stub_PASSWORDCHECK_breach_count = 0;

unsigned int g_stub_PASSWORDCHECK_retry_after_seconds = 0;

int g_stub_PASSWORDCHECK_call_count = 0;

char g_stub_PASSWORDCHECK_last_sha1_hex[VALIDATE_SHA1_HEX_LEN + 1] = "";

void (*g_stub_PASSWORDCHECK_on_call)(void) = NULL;

HibpStatus_t hibp_check(const char* sha1_hex, PASSWORDCHECKRecord_t* record_out, unsigned int* retry_after_seconds_out)
{
  g_stub_PASSWORDCHECK_call_count++;
  if (g_stub_PASSWORDCHECK_on_call)
    g_stub_PASSWORDCHECK_on_call();
  strncpy(g_stub_PASSWORDCHECK_last_sha1_hex, sha1_hex, VALIDATE_SHA1_HEX_LEN);
  g_stub_PASSWORDCHECK_last_sha1_hex[VALIDATE_SHA1_HEX_LEN] = '\0';

  memset(record_out, 0, sizeof(*record_out));
  memcpy(record_out->ma_hashPrefix, sha1_hex, HIBP_PREFIX_LEN);
  *retry_after_seconds_out = g_stub_PASSWORDCHECK_status == HIBP_RATE_LIMITED ? g_stub_PASSWORDCHECK_retry_after_seconds : 0;
  if (g_stub_PASSWORDCHECK_status != HIBP_OK)
    return g_stub_PASSWORDCHECK_status;

  record_out->m_breachCount = g_stub_PASSWORDCHECK_breach_count;
  return HIBP_OK;
}
