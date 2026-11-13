#ifndef WATCHLIST_IP_LOOKUP_TYPES_H
#define WATCHLIST_IP_LOOKUP_TYPES_H

#include <netinet/in.h>

#include "cve.h"

#define WATCHLIST_IP_DROP_COPYRIGHT_MAX_LEN 256

typedef struct {
  char  ma_ipAddress[INET6_ADDRSTRLEN];
} WATCHLISTIPLOOKUPItem_t;

typedef struct {
  char*  mp_previousValue;
  char*  mp_currentValue;
  char   ma_dropListTime[CVELOOKUP_PUBLISHED_LEN + 1];
  char   ma_dropCopyright[WATCHLIST_IP_DROP_COPYRIGHT_MAX_LEN + 1];
} WATCHLISTIPLOOKUPChange_t;

#endif
