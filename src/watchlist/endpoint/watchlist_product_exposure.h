#ifndef WATCHLIST_PRODUCT_EXPOSURE_H
#define WATCHLIST_PRODUCT_EXPOSURE_H

#include <stdbool.h>

#include "cve.h"
#include "package.h"

typedef struct {
  char  ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char  ma_product[CVESEARCH_PRODUCT_LEN + 1];
  char  ma_version[PACKAGECHECK_VERSION_MAX_LEN + 1];
  bool  m_hasCves;
} WATCHLISTPRODUCTEXPOSUREItem_t;

typedef struct {
  char ma_eolProduct[PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN + 1];
  char ma_cycle[PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN + 1];
  char ma_eolDate[PRODUCTEXPOSURE_EOL_DATE_LEN + 1];
  char ma_previousEolDate[PRODUCTEXPOSURE_EOL_DATE_LEN + 1];
} WATCHLISTPRODUCTEXPOSUREChange_t;

#endif
