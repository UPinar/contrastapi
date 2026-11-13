#include <stdlib.h>
#include <string.h>

#include "subdomain_stub.h"

#define SUBDOMAIN_STUB_DEFAULT_DNS_ANSWER {                                          \
  .ma_names      = { "www.example.com", "mail.example.com" },                        \
  .ma_sources    = { SUBDOMAIN_SOURCE_DNS_WORDLIST, SUBDOMAIN_SOURCE_DNS_RECORDS },  \
  .m_nameCount   = 2,                                                                \
  .m_wildcardDns = SUBDOMAIN_WILDCARD_ABSENT,                                        \
}

const SubdomainStubDnsAnswer_t g_stub_SUBDOMAIN_default_dns_answer = SUBDOMAIN_STUB_DEFAULT_DNS_ANSWER;
SubdomainStubDnsAnswer_t       g_stub_SUBDOMAIN_dns_answer         = SUBDOMAIN_STUB_DEFAULT_DNS_ANSWER;

int  g_stub_SUBDOMAIN_lookup_count = 0;
char g_stub_SUBDOMAIN_last_lookup_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";

bool g_stub_SUBDOMAIN_create_fails  = false;
int  g_stub_SUBDOMAIN_create_count  = 0;
int  g_stub_SUBDOMAIN_destroy_count = 0;

SubdomainNameSet_t* subdomain_createNameSet(void)
{
  if (g_stub_SUBDOMAIN_create_fails)
    return NULL;

  SubdomainNameSet_t* name_set = calloc(1, sizeof(*name_set));
  if (name_set == NULL)
    return NULL;
  name_set->mp_names   = calloc(SUBDOMAIN_MAX_NAME_COUNT, sizeof(name_set->mp_names[0]));
  name_set->mp_sources = calloc(SUBDOMAIN_MAX_NAME_COUNT, sizeof(name_set->mp_sources[0]));
  if (name_set->mp_names == NULL || name_set->mp_sources == NULL)
  {
    free(name_set->mp_names);
    free(name_set->mp_sources);
    free(name_set);
    return NULL;
  }
  g_stub_SUBDOMAIN_create_count++;
  return name_set;
}

void subdomain_destroyNameSet(SubdomainNameSet_t* name_set)
{
  if (name_set == NULL)
    return;

  g_stub_SUBDOMAIN_destroy_count++;
  free(name_set->mp_names);
  free(name_set->mp_sources);
  free(name_set);
}

void subdomain_addName(SubdomainNameSet_t* name_set, const char* name, const char* domain, unsigned int source)
{
  (void)domain;
  if (name[0] == '*' && name[1] == '.')
    name += 2;

  size_t name_len = strlen(name);
  if (name_len > VALIDATE_DOMAIN_NAME_MAX_LEN)
    return;

  for (int i = 0; i < name_set->m_count; i++)
  {
    if (strcmp(name_set->mp_names[i], name) == 0)
    {
      name_set->mp_sources[i] |= source;
      return;
    }
  }

  if (name_set->m_count == SUBDOMAIN_MAX_NAME_COUNT)
    return;

  memcpy(name_set->mp_names[name_set->m_count], name, name_len + 1);
  name_set->mp_sources[name_set->m_count] = source;
  name_set->m_count++;
}

void subdomain_lookupDnsNames(const char* domain, SubdomainNameSet_t* name_set, SubdomainWildcard_t* wildcard_dns_out)
{
  g_stub_SUBDOMAIN_lookup_count++;
  strncpy(g_stub_SUBDOMAIN_last_lookup_domain, domain, VALIDATE_DOMAIN_NAME_MAX_LEN);
  g_stub_SUBDOMAIN_last_lookup_domain[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';

  const SubdomainStubDnsAnswer_t* answer = &g_stub_SUBDOMAIN_dns_answer;
  for (int i = 0; i < answer->m_nameCount && i < SUBDOMAIN_STUB_NAME_MAX_COUNT; i++)
    subdomain_addName(name_set, answer->ma_names[i], domain, answer->ma_sources[i]);
  *wildcard_dns_out = answer->m_wildcardDns;
}
