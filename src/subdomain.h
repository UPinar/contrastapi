#ifndef SUBDOMAIN_H
#define SUBDOMAIN_H

#include <stdbool.h>

#include "validate.h"

#define SUBDOMAIN_WORDLIST_COUNT 94

extern const char* const subdomain_wordlist[SUBDOMAIN_WORDLIST_COUNT];

typedef enum {
  SUBDOMAIN_SOURCE_CERTIFICATE_LOGS = 1u << 0,
  SUBDOMAIN_SOURCE_DNS_WORDLIST     = 1u << 1,
  SUBDOMAIN_SOURCE_DNS_RECORDS      = 1u << 2,
} SubdomainSource_t;

#define SUBDOMAIN_MAX_NAME_COUNT 1000

typedef struct {
  char            (*mp_names)[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  unsigned int*   mp_sources;
  int             m_count;
} SubdomainNameSet_t;

typedef enum {
  SUBDOMAIN_WILDCARD_ABSENT = 0,
  SUBDOMAIN_WILDCARD_PRESENT,
  SUBDOMAIN_WILDCARD_UNDETERMINED,
} SubdomainWildcard_t;

#define SUBDOMAIN_DNS_DEADLINE_MS 2000

#define SUBDOMAINENUM_MAX_LISTED_NAME_COUNT 50

typedef struct {
  char  ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} SUBDOMAINENUMParams_t;

typedef enum {
  SUBDOMAINENUM_CERTIFICATE_LOGS_AVAILABLE = 0,
  SUBDOMAINENUM_CERTIFICATE_LOGS_QUOTA_EXHAUSTED,
  SUBDOMAINENUM_CERTIFICATE_LOGS_UPSTREAM_ERROR,
} SUBDOMAINENUMCertificateLogStatus_t;

typedef struct {
  char                                 ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  SubdomainNameSet_t*                  mp_nameSet;
  SubdomainWildcard_t                  m_wildcardDns;
  SUBDOMAINENUMCertificateLogStatus_t  m_certificateLogStatus;
  unsigned int                         m_retryAfterSeconds;
  bool                                 m_isCertificateLogAnswerEmpty;
} SUBDOMAINENUMRecord_t;

SubdomainNameSet_t* subdomain_createNameSet  (void);
void                subdomain_destroyNameSet (SubdomainNameSet_t* name_set);
void                subdomain_addName        (SubdomainNameSet_t* name_set, const char* name, const char* domain, unsigned int source);
void                subdomain_lookupDnsNames (const char* domain, SubdomainNameSet_t* name_set, SubdomainWildcard_t* wildcard_dns_out);

#endif
