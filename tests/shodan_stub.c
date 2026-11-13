#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "shodan_stub.h"

ShodanStatus_t g_stub_SHODAN_check_status            = SHODAN_OK;
ShodanStatus_t g_stub_SHODAN_lookup_status           = SHODAN_NOT_FOUND;
unsigned int   g_stub_SHODAN_retry_after_seconds     = 0;
int            g_stub_SHODAN_check_count             = 0;
int            g_stub_SHODAN_lookup_count            = 0;
size_t         g_stub_SHODAN_last_key_len            = 0;
char           g_stub_SHODAN_last_ip[64]             = "";
ShodanHost_t   g_stub_SHODAN_host                    = { 0 };
int            g_stub_SHODAN_free_count              = 0;
int            g_stub_SHODAN_free_unknown_host_count = 0;

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

ShodanStatus_t shodan_checkKey(const char* vendor_key, unsigned int* retry_after_seconds_out)
{
  g_stub_SHODAN_check_count++;
  g_stub_SHODAN_last_key_len = strnlen(vendor_key, SHODAN_KEY_MAX_LEN + 1);
  *retry_after_seconds_out   = g_stub_SHODAN_retry_after_seconds;
  return g_stub_SHODAN_check_status;
}

ShodanStatus_t shodan_lookupHost(const char* vendor_key, const char* ip_text, ShodanHost_t* host_out, unsigned int* retry_after_seconds_out)
{
  g_stub_SHODAN_lookup_count++;
  g_stub_SHODAN_last_key_len = strnlen(vendor_key, SHODAN_KEY_MAX_LEN + 1);
  snprintf(g_stub_SHODAN_last_ip, sizeof(g_stub_SHODAN_last_ip), "%s", ip_text);
  if (g_stub_SHODAN_lookup_status == SHODAN_OK)
    *host_out = g_stub_SHODAN_host;
  else
    memset(host_out, 0, sizeof(*host_out));
  *retry_after_seconds_out = g_stub_SHODAN_retry_after_seconds;
  return g_stub_SHODAN_lookup_status;
}

void shodan_freeHost(ShodanHost_t* host)
{
  static const ShodanHost_t zero_host = { 0 };
  g_stub_SHODAN_free_count++;
  if (memcmp(host, &zero_host, sizeof(*host)) != 0 && memcmp(host, &g_stub_SHODAN_host, sizeof(*host)) != 0)
    g_stub_SHODAN_free_unknown_host_count++;
  memset(host, 0, sizeof(*host));
}
