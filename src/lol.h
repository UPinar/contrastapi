#ifndef LOL_H
#define LOL_H

#include <stdbool.h>

#include "validate.h"
#include "bulk.h"

#define DRIVERLOOKUP_MATCH_MAX_ROWS        16
#define DRIVERLOOKUP_MATCHES_MAX_LEN  1048576

typedef struct {
  char ma_fileHash[VALIDATE_SHA256_HEX_LEN + 1];
  bool m_isCommandIncluded;
} DRIVERLOOKUPParams_t;

typedef struct {
  char  ma_fileHash[VALIDATE_SHA256_HEX_LEN + 1];
  int   m_matchCount;
  bool  m_isDriverFeedLoaded;
  char* mp_matches;
} DRIVERLOOKUPRecord_t;

#define DRIVERLOOKUPBULK_MAX_IDS  20

typedef struct {
  int                   m_total;
  int                   m_processed;
  int                   m_successful;
  int                   m_skipped;
  int                   m_failed;
  DRIVERLOOKUPRecord_t* mp_items;
  const char          (*mp_notProcessedIds)[BULK_ID_MAX_LEN + 1];
  int                   m_notProcessedCount;
} DRIVERLOOKUPBULKResult_t;

#endif
