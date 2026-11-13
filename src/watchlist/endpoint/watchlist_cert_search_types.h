#ifndef WATCHLIST_CERT_SEARCH_TYPES_H
#define WATCHLIST_CERT_SEARCH_TYPES_H

#include "validate.h"

typedef struct {
  char  ma_domainName[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} WATCHLISTCERTSEARCHItem_t;

typedef struct {
  char*  mp_previousValue;
  char*  mp_currentValue;
} WATCHLISTCERTSEARCHChange_t;

#endif
