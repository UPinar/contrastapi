#ifndef WATCHLIST_WHOIS_LOOKUP_TYPES_H
#define WATCHLIST_WHOIS_LOOKUP_TYPES_H

#include "validate.h"

typedef struct {
  char  ma_domainName[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} WATCHLISTWHOISLOOKUPItem_t;

typedef struct {
  char*  mp_previousValue;
  char*  mp_currentValue;
} WATCHLISTWHOISLOOKUPChange_t;

#endif
