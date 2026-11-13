#ifndef WATCHLIST_DNS_LOOKUP_TYPES_H
#define WATCHLIST_DNS_LOOKUP_TYPES_H

#include "emailcheck.h"
#include "validate.h"

typedef struct {
  char  ma_domainName[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} WATCHLISTDNSLOOKUPItem_t;

typedef struct {
  char   ma_degradedEmailCheckId[EMAILCHECK_KIND_ID_MAX_LEN + 1];
  char*  mp_previousValue;
  char*  mp_currentValue;
} WATCHLISTDNSLOOKUPChange_t;

typedef struct {
  char*  mp_dnsPresenceValue;
  char*  mp_nsValue;
  char*  mp_mxValue;
  char*  mp_ipAddressReachabilityValue;
  char*  mp_cnameTakeoverValue;
  char*  mp_emailAuthValue;
} WATCHLISTDNSLOOKUPFacts_t;

#endif
