#include <stdio.h>
#include <string.h>

#include "abuseipdb_stub.h"

AbuseIpDbStatus_t g_stub_ABUSEIPDB_status              = ABUSEIPDB_OK;
AbuseIpDbReport_t g_stub_ABUSEIPDB_report              = { .m_abuseConfidenceScore = 7, .m_reportCount = 3, .m_distinctReporterCount = 2 };
unsigned int      g_stub_ABUSEIPDB_retry_after_seconds = 0;
int               g_stub_ABUSEIPDB_check_count         = 0;
size_t            g_stub_ABUSEIPDB_last_key_len        = 0;
char              g_stub_ABUSEIPDB_last_ip[64]         = "";

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

AbuseIpDbStatus_t abuseipdb_checkAddress(const char* vendor_key, const char* ip_text, AbuseIpDbReport_t* report_out, unsigned int* retry_after_seconds_out)
{
  g_stub_ABUSEIPDB_check_count++;
  g_stub_ABUSEIPDB_last_key_len = strnlen(vendor_key, ABUSEIPDB_KEY_MAX_LEN + 1);
  snprintf(g_stub_ABUSEIPDB_last_ip, sizeof(g_stub_ABUSEIPDB_last_ip), "%s", ip_text);
  if (g_stub_ABUSEIPDB_status == ABUSEIPDB_OK)
    *report_out = g_stub_ABUSEIPDB_report;
  else
    memset(report_out, 0, sizeof(*report_out));
  *retry_after_seconds_out = g_stub_ABUSEIPDB_retry_after_seconds;
  return g_stub_ABUSEIPDB_status;
}
