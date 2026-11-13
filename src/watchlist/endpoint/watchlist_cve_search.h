#ifndef WATCHLIST_CVE_SEARCH_H
#define WATCHLIST_CVE_SEARCH_H

#include <stdbool.h>

#include "cve.h"

typedef struct {
  char           ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char           ma_product[CVESEARCH_PRODUCT_LEN + 1];
  char           ma_severity[CVELOOKUP_SEVERITY_LEN + 1];
  char           ma_cweId[CVELOOKUP_CWE_ID_LEN + 1];
  double         m_minCvss;
  double         m_minEpss;
  CveKevFilter_t m_kevFilter;
  bool           m_knownRansomware;
  bool           m_hasNucleiTemplate;
} WATCHLISTCVESEARCHItem_t;

#endif
