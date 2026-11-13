#ifndef PACKAGE_H
#define PACKAGE_H

#include <stdbool.h>

#include "cve.h"
#include "jsonbuf.h"
#include "jsonread.h"

#define PACKAGECHECK_ECOSYSTEM_MAX_LEN  16
#define PACKAGECHECK_NAME_MAX_LEN      256
#define PACKAGECHECK_VERSION_MAX_LEN   128
#define PACKAGECHECK_MAX_LIMIT          50

#define PACKAGECHECK_JSON_MAX_LEN  (1024 * 1024)

typedef struct {
  char ma_ecosystem[PACKAGECHECK_ECOSYSTEM_MAX_LEN + 1];
  char ma_packageName[PACKAGECHECK_NAME_MAX_LEN + 1];
  char ma_version[PACKAGECHECK_VERSION_MAX_LEN + 1];
  int  m_limit;
  int  m_offset;
} PACKAGECHECKParams_t;

#define PACKAGECHECKBULK_MAX_ITEMS  500

#define PACKAGECHECKBULK_WEIGHT_BUDGET               100000
#define PACKAGECHECKBULK_ITEM_BASE_WEIGHT            100
#define PACKAGECHECKBULK_LISTED_VERSIONS_PER_WEIGHT  20

#define PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE  (64 * 1024)

#define PACKAGECHECKBULK_ADVISORY_MAX_ROWS  10

#define PACKAGECHECKBULK_JSON_MAX_LEN  JSONBUF_DEFAULT_CEILING

typedef struct {
  char ma_ecosystem[PACKAGECHECK_ECOSYSTEM_MAX_LEN + 1];
  char ma_packageName[PACKAGECHECK_NAME_MAX_LEN + 1];
  char ma_version[PACKAGECHECK_VERSION_MAX_LEN + 1];
} PACKAGECHECKBULKItem_t;

typedef enum {
  PACKAGE_ELEMENT_PROBLEM_NONE = 0,
  PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT,
  PACKAGE_ELEMENT_PROBLEM_MEMBER_UNKNOWN,
  PACKAGE_ELEMENT_PROBLEM_MEMBER_REPEATED,
  PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_NOT_TEXT,
  PACKAGE_ELEMENT_PROBLEM_NAME_NOT_TEXT,
  PACKAGE_ELEMENT_PROBLEM_VERSION_NOT_TEXT,
  PACKAGE_ELEMENT_PROBLEM_ECOSYSTEM_UNKNOWN,
  PACKAGE_ELEMENT_PROBLEM_NAME_EMPTY,
  PACKAGE_ELEMENT_PROBLEM_NAME_CONTROL_CHAR,
  PACKAGE_ELEMENT_PROBLEM_NAME_SPACE,
  PACKAGE_ELEMENT_PROBLEM_VERSION_INVALID,
  PACKAGE_ELEMENT_PROBLEM_REPEATED,
  PACKAGE_ELEMENT_PROBLEM_NORMALIZED_REPEAT,
} PackageElementProblem_t;

typedef struct {
  JsonReadSpan_t  m_itemArraySpan;
  int             m_itemCount;
  int             m_skippedItemCount;
  int             m_notProcessedItemCount;
} PACKAGECHECKBULKParams_t;

typedef struct {
  int                             m_total;
  int                             m_processed;
  int                             m_successful;
  int                             m_skipped;
  int                             m_failed;
  bool                            m_isAdvisoryFeedLoaded;
  char*                           mp_results;
  char*                           mp_attribution;
  const PACKAGECHECKBULKItem_t*   mp_notProcessedItems;
  int                             m_notProcessedCount;
} PACKAGECHECKBULKResult_t;

typedef struct {
  bool                  m_isAdvisoryFeedLoaded;
  bool                  m_hasAdvisoryData;
  int                   m_resultCount;
  char                  ma_fixedVersion[PACKAGECHECK_VERSION_MAX_LEN + 1];
  char*                 mp_malicious;
  char*                 mp_results;
  char*                 mp_attribution;
  PRODUCTEXPOSUREEol_t  m_eol;
} PACKAGECHECKResult_t;

#endif
