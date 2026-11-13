#ifndef SUBDOMAIN_STUB_H
#define SUBDOMAIN_STUB_H

#include <stdbool.h>

#include "subdomain.h"
#include "validate.h"

#define SUBDOMAIN_STUB_NAME_MAX_COUNT 64

typedef struct {
  char                 ma_names[SUBDOMAIN_STUB_NAME_MAX_COUNT][VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  unsigned int         ma_sources[SUBDOMAIN_STUB_NAME_MAX_COUNT];
  int                  m_nameCount;
  SubdomainWildcard_t  m_wildcardDns;
} SubdomainStubDnsAnswer_t;

extern const SubdomainStubDnsAnswer_t g_stub_SUBDOMAIN_default_dns_answer;

extern SubdomainStubDnsAnswer_t g_stub_SUBDOMAIN_dns_answer;

extern int  g_stub_SUBDOMAIN_lookup_count;
extern char g_stub_SUBDOMAIN_last_lookup_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

extern bool g_stub_SUBDOMAIN_create_fails;
extern int  g_stub_SUBDOMAIN_create_count;
extern int  g_stub_SUBDOMAIN_destroy_count;

#endif
