#include <stddef.h>
#include <string.h>

#include "external/rdap.h"

#define RDAP_STUB_DEFAULT_SERVER_BASE_URL "https://rdap.example.test/"

#define RDAP_STUB_DEFAULT_REGISTRATION {                                   \
  .ma_registrarName   = "Stub Registrar LLC",                              \
  .m_registrarIanaId  = 1234,                                              \
  .ma_createdAt       = "2001-02-03T04:05:06Z",                            \
  .ma_updatedAt       = "2025-06-07T08:09:10Z",                            \
  .ma_expiresAt       = "2030-11-12T13:14:15Z",                            \
  .ma_statuses        = { "client transfer prohibited", "server delete prohibited" }, \
  .m_statusCount      = 2,                                                 \
  .ma_nameServers     = { "ns1.stub-dns.test", "ns2.stub-dns.test" },      \
  .m_nameServerCount  = 2,                                                 \
  .m_delegationSigned = RDAP_DELEGATION_SIGNED_YES,                        \
}

const char* const        g_stub_RDAP_default_server_base_url = RDAP_STUB_DEFAULT_SERVER_BASE_URL;
const RdapRegistration_t g_stub_RDAP_default_registration    = RDAP_STUB_DEFAULT_REGISTRATION;

const char* g_stub_RDAP_server_base_url = RDAP_STUB_DEFAULT_SERVER_BASE_URL;

RdapStatus_t       g_stub_RDAP_lookup_status = RDAP_OK;
RdapRegistration_t g_stub_RDAP_registration  = RDAP_STUB_DEFAULT_REGISTRATION;

unsigned int g_stub_RDAP_retry_after_seconds = 0;

int  g_stub_RDAP_find_count   = 0;
int  g_stub_RDAP_lookup_count = 0;
char g_stub_RDAP_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1]   = "";
char g_stub_RDAP_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
char g_stub_RDAP_last_lookup_base_url[256]                          = "";

void (*g_stub_RDAP_on_call)(void) = NULL;

const char* rdap_findServerBaseUrl(const char* domain_name)
{
  g_stub_RDAP_find_count++;
  strncpy(g_stub_RDAP_last_find_name, domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_RDAP_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  return g_stub_RDAP_server_base_url;
}

RdapStatus_t rdap_lookupDomain(const char* domain_name, const char* base_url, RdapRegistration_t* registration_out, unsigned int* retry_after_seconds_out)
{
  g_stub_RDAP_lookup_count++;
  if (g_stub_RDAP_on_call)
    g_stub_RDAP_on_call();
  strncpy(g_stub_RDAP_last_lookup_name, domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_RDAP_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  strncpy(g_stub_RDAP_last_lookup_base_url, base_url, sizeof(g_stub_RDAP_last_lookup_base_url) - 1);
  g_stub_RDAP_last_lookup_base_url[sizeof(g_stub_RDAP_last_lookup_base_url) - 1] = '\0';

  memset(registration_out, 0, sizeof(*registration_out));
  registration_out->m_registrarIanaId = -1;
  if (g_stub_RDAP_lookup_status == RDAP_OK)
    *registration_out = g_stub_RDAP_registration;
  *retry_after_seconds_out = g_stub_RDAP_lookup_status == RDAP_RATE_LIMITED ? g_stub_RDAP_retry_after_seconds : 0;
  return g_stub_RDAP_lookup_status;
}
