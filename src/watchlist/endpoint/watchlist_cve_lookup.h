#ifndef WATCHLIST_CVE_LOOKUP_H
#define WATCHLIST_CVE_LOOKUP_H

#include "cve.h"

typedef struct {
  char  ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
} WATCHLISTCVELOOKUPItem_t;

#endif
