#include <stddef.h>
#include <string.h>

#include "external/whois.h"

const WhoisServer_t g_stub_WHOIS_test_server = { "test", "whois.example.test", NULL, NULL };

const WhoisServer_t* g_stub_WHOIS_server = NULL;

WhoisStatus_t      g_stub_WHOIS_lookup_status = WHOIS_OK;
RdapRegistration_t g_stub_WHOIS_registration  = { .m_registrarIanaId = -1 };

int                  g_stub_WHOIS_find_count         = 0;
int                  g_stub_WHOIS_lookup_count       = 0;
char                 g_stub_WHOIS_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1]   = "";
char                 g_stub_WHOIS_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
const WhoisServer_t* g_stub_WHOIS_last_lookup_server = NULL;

const WhoisServer_t* whois_findServer(const char* domain_name)
{
  g_stub_WHOIS_find_count++;
  strncpy(g_stub_WHOIS_last_find_name, domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_WHOIS_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  return g_stub_WHOIS_server;
}

WhoisStatus_t whois_lookupDomain(const char* domain_name, const WhoisServer_t* server, RdapRegistration_t* registration_out)
{
  g_stub_WHOIS_lookup_count++;
  strncpy(g_stub_WHOIS_last_lookup_name, domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_WHOIS_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  g_stub_WHOIS_last_lookup_server = server;

  memset(registration_out, 0, sizeof(*registration_out));
  registration_out->m_registrarIanaId = -1;
  if (g_stub_WHOIS_lookup_status == WHOIS_OK)
    *registration_out = g_stub_WHOIS_registration;
  return g_stub_WHOIS_lookup_status;
}
