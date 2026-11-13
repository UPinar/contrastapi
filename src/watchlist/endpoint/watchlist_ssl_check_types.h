#ifndef WATCHLIST_SSL_CHECK_TYPES_H
#define WATCHLIST_SSL_CHECK_TYPES_H

#include "validate.h"

typedef struct {
  char  ma_domainName[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
} WATCHLISTSSLCHECKItem_t;

typedef struct {
  char*  mp_previousValue;
  char*  mp_currentValue;
} WATCHLISTSSLCHECKChange_t;

#endif
