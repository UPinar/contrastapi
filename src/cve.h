#ifndef CVE_H
#define CVE_H

#include <stdbool.h>
#include <stddef.h>

#include "bulk.h"
#include "ssvc.h"

#define CVELOOKUP_ID_MAX_LEN            24

#define CVELOOKUP_ID_TAG_LEN             4
#define CVELOOKUP_ID_YEAR_DIGITS         4
#define CVELOOKUP_ID_PREFIX_LEN         (CVELOOKUP_ID_TAG_LEN + CVELOOKUP_ID_YEAR_DIGITS + 1)
#define CVELOOKUP_ID_SEQ_MIN_DIGITS      4
#define CVELOOKUP_ID_SEQ_MAX_DIGITS     (CVELOOKUP_ID_MAX_LEN - CVELOOKUP_ID_PREFIX_LEN)
#define CVELOOKUP_DESC_MAX_LEN        8192
#define CVELOOKUP_SEVERITY_LEN          16
#define CVELOOKUP_V3_VECTOR_LEN         64
#define CVELOOKUP_V4_VECTOR_LEN        192
#define CVELOOKUP_PUBLISHED_LEN         31
#define CVELOOKUP_CWE_ID_LEN            16
#define CVELOOKUP_STATUS_LEN            32
#define CVELOOKUP_EPSS_TREND_MAX_ROWS   30
#define CVELOOKUP_EPSS_TREND_MAX_LEN  8192
#define CVELOOKUP_RANSOMWARE_LEN        32
#define CVELOOKUP_SSVC_VALUE_LEN        16
#define CVELOOKUP_SOURCE_LEN             8

#define CVELOOKUP_NUCLEI_TEMPLATE_MAX_ROWS     5
#define CVELOOKUP_NUCLEI_TEMPLATES_MAX_LEN 16384

#define CVELOOKUP_PRODUCT_MAX_ROWS            20
#define CVELOOKUP_VENDOR_MAX_ROWS             10
#define CVELOOKUP_REF_MAX_ROWS                20

#define CVELOOKUP_GHSA_PACKAGE_MAX_ROWS 32
#define CVELOOKUP_GHSA_MAX_LEN          (1024 * 1024)

typedef struct {
  char                   ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  char                   ma_description[CVELOOKUP_DESC_MAX_LEN + 1];
  char                   ma_severity[CVELOOKUP_SEVERITY_LEN + 1];
  double                 m_cvssV3;
  char                   ma_cvssV3Vector[CVELOOKUP_V3_VECTOR_LEN + 1];
  char                   ma_cvssV3Source[CVELOOKUP_SOURCE_LEN + 1];
  double                 m_cvssV4;
  char                   ma_cvssV4Vector[CVELOOKUP_V4_VECTOR_LEN + 1];
  char                   ma_cvssV4Source[CVELOOKUP_SOURCE_LEN + 1];
  char                   ma_publishedTime[CVELOOKUP_PUBLISHED_LEN + 1];
  double                 m_epssScore;
  double                 m_epssPercentile;
  char                   ma_cweId[CVELOOKUP_CWE_ID_LEN + 1];
  char                   ma_cweSource[CVELOOKUP_SOURCE_LEN + 1];
  char*                  mp_cwes;
  bool                   m_inKev;
  char                   ma_kevDateAdded[CVELOOKUP_PUBLISHED_LEN + 1];
  char                   ma_vulnerabilityStatus[CVELOOKUP_STATUS_LEN + 1];
  char*                  mp_affectedProducts;
  int                    m_affectedProductCount;
  char*                  mp_productCountByVendor;
  char*                  mp_refs;
  int                    m_refCount;
  int                    m_pocCount;
  int                    m_vendorAdvisoryCount;
  char*                  mp_epssTrend;
  char*                  mp_cveTags;
  char                   ma_ransomwareCampaign[CVELOOKUP_RANSOMWARE_LEN + 1];
  char                   ma_ssvcExploitation[CVELOOKUP_SSVC_VALUE_LEN + 1];
  char                   ma_ssvcAutomatable[CVELOOKUP_SSVC_VALUE_LEN + 1];
  char                   ma_ssvcTechnicalImpact[CVELOOKUP_SSVC_VALUE_LEN + 1];
  char                   ma_ssvcVersion[CVELOOKUP_SSVC_VALUE_LEN + 1];
  char                   ma_ssvcScoredAt[CVELOOKUP_PUBLISHED_LEN + 1];
  SsvcResult_t           m_ssvcResult;
  int                    m_metasploitModuleCount;
  bool                   m_isMetasploitFeedLoaded;
  int                    m_nucleiTemplateCount;
  bool                   m_isNucleiTemplateFeedLoaded;
  char*                  mp_nucleiTemplates;
  bool                   m_isGhsaAsked;
  bool                   m_ghsaUnavailable;
  bool                   m_isGhsaFeedLoaded;
  char*                  mp_ghsa;
} CVELOOKUPRecord_t;

typedef struct {
  bool m_isGhsaIncluded;
  char ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
} CVELOOKUPParams_t;

typedef struct {
  char ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
} CveIdParams_t;

#define CVESEARCH_VENDOR_LEN  128
#define CVESEARCH_PRODUCT_LEN 128
#define CVESEARCH_SORT_LEN    16
#define CVE_LIST_DEFAULT_LIMIT      20
#define CVE_LIST_MAX_LIMIT         100
#define CVE_LIST_RANKED_MAX_LIMIT   50
#define CVE_LIST_MAX_OFFSET       10000

typedef enum {
  CVE_KEV_FILTER_ANY = 0,
  CVE_KEV_FILTER_ONLY_IN_KEV,
  CVE_KEV_FILTER_NOT_IN_KEV,
} CveKevFilter_t;

typedef struct {
  char           ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char           ma_product[CVESEARCH_PRODUCT_LEN + 1];
  char           ma_severity[CVELOOKUP_SEVERITY_LEN + 1];
  double         m_minCvss;
  double         m_minEpss;
  CveKevFilter_t m_kevFilter;
  bool           m_knownRansomware;
  bool           m_hasNucleiTemplate;
  char           ma_cweId[CVELOOKUP_CWE_ID_LEN + 1];
  char           ma_publishedAfter[CVELOOKUP_PUBLISHED_LEN + 1];
  char           ma_publishedBefore[CVELOOKUP_PUBLISHED_LEN + 1];
  bool           m_isRejectedIncluded;
  char           ma_sort[CVESEARCH_SORT_LEN];
  int            m_limit;
  int            m_offset;
} CVESEARCHParams_t;

typedef struct {
  char           ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char           ma_product[CVESEARCH_PRODUCT_LEN + 1];
  double         m_minEpss;
  CveKevFilter_t m_kevFilter;
  bool           m_knownRansomware;
  bool           m_hasNucleiTemplate;
  bool           m_isRejectedIncluded;
  int            m_limit;
} CVELEADINGParams_t;

typedef struct {
  char   ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  char   ma_severity[CVELOOKUP_SEVERITY_LEN + 1];
  double m_cvssV3;
  bool   m_hasCvssV3;
  char   ma_cvssV3Source[CVELOOKUP_SOURCE_LEN + 1];
  double m_cvssV4;
  bool   m_hasCvssV4;
  char   ma_cvssV4Source[CVELOOKUP_SOURCE_LEN + 1];
  double m_epssScore;
  double m_epssPercentile;
  bool   m_inKev;
  char   ma_publishedTime[CVELOOKUP_PUBLISHED_LEN + 1];
  char   ma_cweId[CVELOOKUP_CWE_ID_LEN + 1];
  char   ma_cweSource[CVELOOKUP_SOURCE_LEN + 1];
} CveListItem_t;

typedef struct {
  int            m_total;
  int            m_count;
  CveListItem_t* mp_items;
} CveListResult_t;

#define KEVLOOKUP_VENDOR_LEN           128
#define KEVLOOKUP_PRODUCT_LEN          512
#define KEVLOOKUP_REQUIRED_ACTION_LEN 1024
#define KEVLOOKUP_VULN_NAME_LEN        256
#define KEVLOOKUP_SHORT_DESC_LEN      2048
#define KEVLOOKUP_DATE_REMOVED_LEN      64
#define KEVLOOKUP_CWES_MAX_LEN        4096

typedef struct {
  char  ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  bool  m_inKev;
  char  ma_dateAdded[CVELOOKUP_PUBLISHED_LEN + 1];
  char  ma_vendorProject[KEVLOOKUP_VENDOR_LEN + 1];
  char  ma_product[KEVLOOKUP_PRODUCT_LEN + 1];
  char  ma_patchDeadline[CVELOOKUP_PUBLISHED_LEN + 1];
  char  ma_requiredAction[KEVLOOKUP_REQUIRED_ACTION_LEN + 1];
  bool  m_knownRansomwareUse;
  char  ma_vulnerabilityName[KEVLOOKUP_VULN_NAME_LEN + 1];
  char  ma_shortDescription[KEVLOOKUP_SHORT_DESC_LEN + 1];
  char  ma_dateRemoved[KEVLOOKUP_DATE_REMOVED_LEN + 1];
  char* mp_cwes;
  char* mp_notes;
} KEVLOOKUPRecord_t;

#define CWELOOKUP_ID_MAX_LEN              16

#define CWELOOKUP_ID_TAG_LEN               4
#define CWELOOKUP_ID_MIN_DIGITS            1
#define CWELOOKUP_ID_MAX_DIGITS            5
#define CWELOOKUP_NAME_LEN               256
#define CWELOOKUP_DESC_MAX_LEN          2048
#define CWELOOKUP_LIKELIHOOD_LEN          32
#define CWELOOKUP_PARENT_CWE_LEN          16
#define CWELOOKUP_UPDATED_AT_LEN          64
#define CWELOOKUP_MITIGATIONS_MAX_LEN  12288
#define CWELOOKUP_EXTENDED_DESC_MAX_LEN 4096
#define CWELOOKUP_EXAMPLES_MAX_LEN      8192

#define CWELOOKUP_ABSTRACTION_LEN         16
#define CWELOOKUP_STATUS_LEN              16

typedef struct {
  char    ma_cweId[CWELOOKUP_ID_MAX_LEN + 1];
  char    ma_name[CWELOOKUP_NAME_LEN + 1];
  char    ma_abstraction[CWELOOKUP_ABSTRACTION_LEN + 1];
  char    ma_status[CWELOOKUP_STATUS_LEN + 1];
  char    ma_description[CWELOOKUP_DESC_MAX_LEN + 1];
  char    ma_likelihood[CWELOOKUP_LIKELIHOOD_LEN + 1];
  char    ma_parentCwe[CWELOOKUP_PARENT_CWE_LEN + 1];
  char    ma_updatedAt[CWELOOKUP_UPDATED_AT_LEN + 1];
  char*   mp_mitigations;
  char*   mp_extendedDescription;
  char*   mp_examples;
  int     m_cveCount;
  int     m_kevCount;
  double  m_avgCvss;
  double  m_avgEpss;
} CWELOOKUPRecord_t;

typedef struct {
  char ma_cweId[CWELOOKUP_ID_MAX_LEN + 1];
} CWELOOKUPParams_t;

#define CVELOOKUPBULK_MAX_IDS  50

typedef struct {
  int                m_total;
  int                m_processed;
  int                m_successful;
  int                m_skipped;
  int                m_failed;
  CVELOOKUPRecord_t* mp_items;
  const char       (*mp_notProcessedIds)[BULK_ID_MAX_LEN + 1];
  int                m_notProcessedCount;
} CVELOOKUPBULKResult_t;

#define CVERISKSCORE_LABEL_LEN   16

typedef struct {
  double  m_score;
  char    ma_label[CVERISKSCORE_LABEL_LEN + 1];
  bool    m_hasPublicPoc;
  double  m_exploitabilityComponent;
  double  m_impactComponent;
  double  m_evidenceComponent;
} CVERISKSCORERecord_t;

#define CVETRIAGEBULK_MAX_IDS  50

typedef struct {
  char   ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char   ma_product[CVESEARCH_PRODUCT_LEN + 1];
  double m_minRiskScore;
  bool   m_isRejectedIncluded;
  int    m_limit;
  int    m_offset;
} CVETRIAGEParams_t;

typedef struct {
  char   ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  double m_riskScore;
  char   ma_label[CVERISKSCORE_LABEL_LEN + 1];
} CVETRIAGEItem_t;

typedef struct {
  int              m_total;
  int              m_count;
  CVETRIAGEItem_t* mp_items;
} CVETRIAGEResult_t;

typedef struct {
  int              m_total;
  int              m_processed;
  int              m_successful;
  int              m_skipped;
  int              m_failed;
  CVETRIAGEItem_t* mp_items;
  const char     (*mp_notProcessedIds)[BULK_ID_MAX_LEN + 1];
  int              m_notProcessedCount;
} CVETRIAGEBULKResult_t;

#define PRODUCTEXPOSURE_TOP_N 10

#define PRODUCTEXPOSURE_VERSION_MAX_LEN 128

#define PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN         64
#define PRODUCTEXPOSURE_EOL_URL_MAX_LEN             256
#define PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN      100
#define PRODUCTEXPOSURE_EOL_LATEST_VERSION_MAX_LEN  100
#define PRODUCTEXPOSURE_EOL_DATE_LEN                10

#define PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX     8
#define PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX 10

typedef struct {
  char  ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char  ma_product[CVESEARCH_PRODUCT_LEN + 1];
  char  ma_version[PRODUCTEXPOSURE_VERSION_MAX_LEN + 1];
  bool  m_isRejectedIncluded;
} PRODUCTEXPOSUREParams_t;

typedef struct {
  char  ma_name[PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN + 1];
  char  ma_eolDate[PRODUCTEXPOSURE_EOL_DATE_LEN + 1];
  bool  m_isEol;
  bool  m_isMaintained;
  bool  m_isLts;
  char  ma_latestVersion[PRODUCTEXPOSURE_EOL_LATEST_VERSION_MAX_LEN + 1];
} PRODUCTEXPOSUREEolCycle_t;

typedef struct {
  bool                      m_hasEol;
  char                      ma_eolProduct[PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN + 1];
  char                      ma_eolUrl[PRODUCTEXPOSURE_EOL_URL_MAX_LEN + 1];
  int                       m_eolSeriesCycleCount;
  PRODUCTEXPOSUREEolCycle_t ma_eolSeriesCycles[PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX];
  int                       m_eolMaintainedCycleCount;
  PRODUCTEXPOSUREEolCycle_t ma_eolMaintainedCycles[PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX];
  bool                      m_hasMoreEolMaintainedCycles;
} PRODUCTEXPOSUREEol_t;

typedef struct {
  char                  ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char                  ma_product[CVESEARCH_PRODUCT_LEN + 1];
  int                   m_totalCveCount;
  int                   m_criticalCount;
  int                   m_highCount;
  int                   m_mediumCount;
  int                   m_lowCount;
  int                   m_kevCount;
  double                m_maxCvss;
  double                m_avgCvss;
  double                m_maxEpss;
  int                   m_pocBackedCount;
  double                m_worstRiskScore;
  char                  ma_mostRecentPublished[CVELOOKUP_PUBLISHED_LEN + 1];
  PRODUCTEXPOSUREEol_t  m_eol;
  int                   m_topCveCount;
  CVETRIAGEItem_t       ma_topCves[PRODUCTEXPOSURE_TOP_N];
} PRODUCTEXPOSURERecord_t;

#define CPESEARCH_SEARCH_MAX_LEN  128
#define CPESEARCH_MAX_LIMIT        50

typedef struct {
  char ma_search[CPESEARCH_SEARCH_MAX_LEN + 1];
  int  m_limit;
  int  m_offset;
} CPESEARCHParams_t;

typedef struct {
  char  ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char  ma_product[CVESEARCH_PRODUCT_LEN + 1];
  int   m_vulnerableCveCount;
  char* mp_productNamedBy;
} CPESEARCHItem_t;

typedef struct {
  int              m_total;
  int              m_count;
  CPESEARCHItem_t* mp_items;
} CPESEARCHResult_t;

#define CVEPRODUCTS_MAX_LIMIT  50

typedef struct {
  char ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  char ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char ma_product[CVESEARCH_PRODUCT_LEN + 1];
  int  m_limit;
  int  m_offset;
} CVEPRODUCTSParams_t;

typedef struct {
  int   m_affectedProductCount;
  int   m_listedProductCount;
  char* mp_affectedProducts;
} CVEPRODUCTSResult_t;

#define CVEEXPLOIT_REPO_URL_LEN           256
#define CVEEXPLOIT_REPO_NAME_LEN          128
#define CVEEXPLOIT_MAX_GITHUB_REPOS         3
#define CVEEXPLOIT_METASPLOIT_MODULE_LEN  128
#define CVEEXPLOIT_METASPLOIT_TYPE_LEN     16
#define CVEEXPLOIT_METASPLOIT_MAX_MODULES   5
#define CVEEXPLOIT_NVD_REF_URL_LEN        256
#define CVEEXPLOIT_NVD_MAX_REFS             5
#define CVEEXPLOIT_EXPLOITDB_MAX_ENTRIES    5
#define CVEEXPLOIT_EXPLOITDB_TYPE_LEN      16
#define CVEEXPLOIT_EXPLOITDB_PLATFORM_LEN  32
#define CVEEXPLOIT_EXPLOITDB_DATE_LEN      10
#define CVEEXPLOIT_EXPLOITDB_URL_LEN       46

typedef struct {
  char ma_url[CVEEXPLOIT_REPO_URL_LEN + 1];
  char ma_name[CVEEXPLOIT_REPO_NAME_LEN + 1];
  int  m_starCount;
} CVEEXPLOITGithubRepo_t;

typedef struct {
  char ma_name[CVEEXPLOIT_METASPLOIT_MODULE_LEN + 1];
  char ma_type[CVEEXPLOIT_METASPLOIT_TYPE_LEN + 1];
} CVEEXPLOITMetasploitModule_t;

typedef struct {
  char ma_url[CVEEXPLOIT_NVD_REF_URL_LEN + 1];
} CVEEXPLOITNvdRef_t;

typedef struct {
  int   m_edbId;
  char  ma_type[CVEEXPLOIT_EXPLOITDB_TYPE_LEN + 1];
  char  ma_platform[CVEEXPLOIT_EXPLOITDB_PLATFORM_LEN + 1];
  char  ma_datePublished[CVEEXPLOIT_EXPLOITDB_DATE_LEN + 1];
  bool  m_isVerified;
  char  ma_url[CVEEXPLOIT_EXPLOITDB_URL_LEN + 1];
} CVEEXPLOITExploitdbEntry_t;

typedef struct {
  char                          ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  bool                          m_githubAvailable;
  bool                          m_isGithubTableEmpty;
  int                           m_githubPocRepoTotal;
  int                           m_githubTopStarredRepoCount;
  CVEEXPLOITGithubRepo_t        ma_githubTopStarredRepos[CVEEXPLOIT_MAX_GITHUB_REPOS];
  bool                          m_metasploitAvailable;
  bool                          m_isMetasploitTableEmpty;
  int                           m_metasploitModuleTotal;
  int                           m_metasploitModuleCount;
  CVEEXPLOITMetasploitModule_t  ma_metasploitModules[CVEEXPLOIT_METASPLOIT_MAX_MODULES];
  bool                          m_nvdAvailable;
  bool                          m_cveNotInLocalDatabase;
  bool                          m_inKev;
  int                           m_nvdExploitRefTotal;
  int                           m_nvdExploitRefCount;
  CVEEXPLOITNvdRef_t            ma_nvdExploitRefs[CVEEXPLOIT_NVD_MAX_REFS];
  bool                          m_exploitdbAvailable;
  bool                          m_isExploitdbTableEmpty;
  int                           m_exploitdbEntryTotal;
  int                           m_exploitdbEntryCount;
  CVEEXPLOITExploitdbEntry_t    ma_exploitdbEntries[CVEEXPLOIT_EXPLOITDB_MAX_ENTRIES];
} CVEEXPLOITRecord_t;

#endif
