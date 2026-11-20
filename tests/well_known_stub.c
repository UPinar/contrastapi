#include <stddef.h>
#include <string.h>

#include "well_known.h"
#include "validate.h"

HttpError_t       g_stub_WELL_KNOWN_error  = HTTP_ERROR_NONE;
WellKnownReport_t g_stub_WELL_KNOWN_report = { 0 };

int  g_stub_WELL_KNOWN_call_count = 0;
int  g_stub_WELL_KNOWN_free_count = 0;
char g_stub_WELL_KNOWN_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
int64_t g_stub_WELL_KNOWN_last_now_epoch = 0;

void (*g_stub_WELL_KNOWN_on_call)(void) = NULL;

HttpError_t well_known_fetchFiles(const char* hostname, int64_t now_epoch, WellKnownReport_t* report_out)
{
  g_stub_WELL_KNOWN_last_now_epoch = now_epoch;
  g_stub_WELL_KNOWN_call_count++;
  if (g_stub_WELL_KNOWN_on_call)
    g_stub_WELL_KNOWN_on_call();
  strncpy(g_stub_WELL_KNOWN_last_hostname, hostname, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_WELL_KNOWN_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';

  memset(report_out, 0, sizeof(*report_out));
  if (g_stub_WELL_KNOWN_error != HTTP_ERROR_NONE)
    return g_stub_WELL_KNOWN_error;
  *report_out = g_stub_WELL_KNOWN_report;
  return HTTP_ERROR_NONE;
}

void well_known_reportFree(WellKnownReport_t* report)
{
  g_stub_WELL_KNOWN_free_count++;
  memset(report, 0, sizeof(*report));
}
