#include <stddef.h>
#include <string.h>

#include "cveservices_stub.h"

CveServicesStatus_t     g_stub_CVESERVICES_status              = CVESERVICES_UPSTREAM_ERROR;
CveServicesCveIdState_t g_stub_CVESERVICES_state               = CVESERVICES_CVE_ID_STATE_NOT_CHECKED;
unsigned int            g_stub_CVESERVICES_retry_after_seconds = 0;

int     g_stub_CVESERVICES_call_count                                = 0;
char    g_stub_CVESERVICES_last_cve_id[CVELOOKUP_ID_MAX_LEN + 1]     = "";
int64_t g_stub_CVESERVICES_last_deadline_ms                          = 0;

void (*g_stub_CVESERVICES_on_call)(void) = NULL;

CveServicesStatus_t cveservices_askCveIdState(const char* cve_id, int64_t deadline_ms, CveServicesCveIdState_t* state_out, unsigned int* retry_after_seconds_out)
{
  g_stub_CVESERVICES_call_count++;
  if (g_stub_CVESERVICES_on_call)
    g_stub_CVESERVICES_on_call();
  strncpy(g_stub_CVESERVICES_last_cve_id, cve_id, CVELOOKUP_ID_MAX_LEN);
  g_stub_CVESERVICES_last_cve_id[CVELOOKUP_ID_MAX_LEN] = '\0';
  g_stub_CVESERVICES_last_deadline_ms = deadline_ms;

  *state_out               = CVESERVICES_CVE_ID_STATE_NOT_CHECKED;
  *retry_after_seconds_out = 0;
  if (g_stub_CVESERVICES_status == CVESERVICES_OK)
    *state_out = g_stub_CVESERVICES_state;
  else if (g_stub_CVESERVICES_status == CVESERVICES_RATE_LIMITED)
    *retry_after_seconds_out = g_stub_CVESERVICES_retry_after_seconds;
  return g_stub_CVESERVICES_status;
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
