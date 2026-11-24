#ifndef SUBDOMAIN_H
#define SUBDOMAIN_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "dns.h"
#include "validate.h"

#define SUBDOMAIN_WORDLIST_COUNT 94

extern const char* const subdomain_wordlist[SUBDOMAIN_WORDLIST_COUNT];

typedef enum {
  SUBDOMAIN_SOURCE_CERTIFICATE_LOGS = 1u << 0,
  SUBDOMAIN_SOURCE_DNS_WORDLIST     = 1u << 1,
  SUBDOMAIN_SOURCE_DNS_RECORDS      = 1u << 2,
} SubdomainSource_t;

#define SUBDOMAIN_MAX_NAME_COUNT 1000

typedef enum {
  SUBDOMAIN_ADDRESS_UNMEASURED = 0,
  SUBDOMAIN_ADDRESS_FOUND,
  SUBDOMAIN_ADDRESS_NONE,
} SubdomainAddressState_t;

typedef struct {
  char                     (*mp_names)[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  unsigned int*            mp_sources;
  SubdomainAddressState_t* mp_addressStates;
  int                      m_count;
} SubdomainNameSet_t;

typedef enum {
  SUBDOMAIN_WILDCARD_ABSENT = 0,
  SUBDOMAIN_WILDCARD_PRESENT,
  SUBDOMAIN_WILDCARD_UNDETERMINED,
} SubdomainWildcard_t;

typedef struct {
  int   m_count;
  char  ma_ipAddresses[DNS_ANSWER_MAX_RECORD_COUNT][INET_ADDRSTRLEN];
} SubdomainWildcardIpAddresses_t;

#define SUBDOMAIN_DNS_DEADLINE_MS 2000

#define SUBDOMAIN_ADDRESS_DEADLINE_MS 1000

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
  SubdomainWildcardIpAddresses_t       m_wildcardIpAddresses;
  SUBDOMAINENUMCertificateLogStatus_t  m_certificateLogStatus;
  unsigned int                         m_retryAfterSeconds;
  bool                                 m_isCertificateLogAnswerEmpty;
} SUBDOMAINENUMRecord_t;

SubdomainNameSet_t* subdomain_createNameSet       (void);
void                subdomain_destroyNameSet      (SubdomainNameSet_t* name_set);
void                subdomain_addName             (SubdomainNameSet_t* name_set, const char* name, const char* domain, unsigned int source);
void                subdomain_lookupDnsNames      (const char* domain, SubdomainNameSet_t* name_set, SubdomainWildcard_t* wildcard_dns_out, SubdomainWildcardIpAddresses_t* wildcard_ip_addresses_out);
void                subdomain_lookupAddressStates (SubdomainNameSet_t* name_set, const int* name_indexes, int name_index_count, SubdomainWildcard_t wildcard_dns, const SubdomainWildcardIpAddresses_t* wildcard_ip_addresses);

#endif
