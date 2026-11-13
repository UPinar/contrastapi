#ifndef WATCHLIST_H
#define WATCHLIST_H

#include <stdbool.h>

#include "cve.h"
#include "package.h"
#include "request.h"
#include "validate.h"

#include "watchlist/endpoint/watchlist_cert_search_types.h"
#include "watchlist/endpoint/watchlist_cve_exploit.h"
#include "watchlist/endpoint/watchlist_cve_lookup.h"
#include "watchlist/endpoint/watchlist_cve_search.h"
#include "watchlist/endpoint/watchlist_dns_lookup_types.h"
#include "watchlist/endpoint/watchlist_headers_check_types.h"
#include "watchlist/endpoint/watchlist_ip_lookup_types.h"
#include "watchlist/endpoint/watchlist_kev_lookup.h"
#include "watchlist/endpoint/watchlist_package_check.h"
#include "watchlist/endpoint/watchlist_product_exposure.h"
#include "watchlist/endpoint/watchlist_ssl_check_types.h"
#include "watchlist/endpoint/watchlist_whois_lookup_types.h"

#define WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY 100

#define WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY 500

#define WATCHLIST_DOMAIN_NAME_MAX_COUNT_PER_REGISTERED_DOMAIN 20

#define WATCHLIST_CURSOR_MAX_LEN 18

#define WATCHLIST_IP_VALUE_MAX_LEN 4096

#define WATCHLIST_SCAN_EVENT_MAX_COUNT 10000

#define WATCHLIST_ANSWER_PAIR_MAX_COUNT (WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY + WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY)

#define WATCHLIST_ACTION_MAX_LEN     8
#define WATCHLIST_ENDPOINT_MAX_LEN   16
#define WATCHLIST_EVENT_TYPE_MAX_LEN 32

typedef struct {
  const RequestCreditBudget_t* mp_creditBudget;
  char                         ma_action[WATCHLIST_ACTION_MAX_LEN + 1];
  char                         ma_endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 1];
  char                         ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  char                         ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char                         ma_product[CVESEARCH_PRODUCT_LEN + 1];
  char                         ma_severity[CVELOOKUP_SEVERITY_LEN + 1];
  char                         ma_cweId[CVELOOKUP_CWE_ID_LEN + 1];
  double                       m_minCvss;
  double                       m_minEpss;
  CveKevFilter_t               m_inKev;
  bool                         m_knownRansomware;
  bool                         m_hasNucleiTemplate;
  char                         ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char                         ma_ecosystem[PACKAGECHECK_ECOSYSTEM_MAX_LEN + 1];
  char                         ma_packageName[PACKAGECHECK_NAME_MAX_LEN + 1];
  char                         ma_version[PACKAGECHECK_VERSION_MAX_LEN + 1];
  char                         ma_ipAddress[INET6_ADDRSTRLEN];
  bool                         m_isWatchlistCleared;
  PACKAGECHECKBULKParams_t     m_packages;
} WATCHLISTEDITParams_t;

typedef struct {
  const RequestCreditBudget_t* mp_creditBudget;
  char                         ma_cursor[WATCHLIST_CURSOR_MAX_LEN + 1];
  int                          m_limit;
  bool                         m_isRepeat;
} WATCHLISTEVENTSParams_t;

typedef enum {
  WATCHLIST_ITEM_CVE_LOOKUP = 0,
  WATCHLIST_ITEM_KEV_LOOKUP,
  WATCHLIST_ITEM_CVE_EXPLOIT,
  WATCHLIST_ITEM_PRODUCT_EXPOSURE,
  WATCHLIST_ITEM_CVE_SEARCH,
  WATCHLIST_ITEM_DNS_LOOKUP,
  WATCHLIST_ITEM_SSL_CHECK,
  WATCHLIST_ITEM_WHOIS_LOOKUP,
  WATCHLIST_ITEM_HEADERS_CHECK,
  WATCHLIST_ITEM_CERT_SEARCH,
  WATCHLIST_ITEM_PACKAGE_CHECK,
  WATCHLIST_ITEM_IP_LOOKUP,
} WatchlistItemKind_t;

#define WATCHLIST_ITEM_KIND_COUNT 12

typedef enum {
  WATCHLIST_ADD_REQUIRES_NOTHING = 0,
  WATCHLIST_ADD_REQUIRES_DOMAIN_NAME_NOT_NXDOMAIN,
  WATCHLIST_ADD_REQUIRES_REGISTERED_DOMAIN_WITH_REGISTRY_SERVER,
} WatchlistAddRequirement_t;

typedef struct {
  WatchlistItemKind_t m_itemKind;
  union {
    WATCHLISTCVELOOKUPItem_t       m_cveLookup;
    WATCHLISTKEVLOOKUPItem_t       m_kevLookup;
    WATCHLISTCVEEXPLOITItem_t      m_cveExploit;
    WATCHLISTPRODUCTEXPOSUREItem_t m_productExposure;
    WATCHLISTCVESEARCHItem_t       m_cveSearch;
    WATCHLISTDNSLOOKUPItem_t       m_dnsLookup;
    WATCHLISTSSLCHECKItem_t        m_sslCheck;
    WATCHLISTWHOISLOOKUPItem_t     m_whoisLookup;
    WATCHLISTHEADERSCHECKItem_t    m_headersCheck;
    WATCHLISTCERTSEARCHItem_t      m_certSearch;
    WATCHLISTPACKAGECHECKItem_t    m_packageCheck;
    WATCHLISTIPLOOKUPItem_t        m_ipLookup;
  };
} WatchlistItem_t;

typedef enum {
  WATCHLISTEDIT_ACTION_LIST = 0,
  WATCHLISTEDIT_ACTION_CLEAR,
  WATCHLISTEDIT_ACTION_ADD,
  WATCHLISTEDIT_ACTION_REMOVE,
} WATCHLISTEDITAction_t;

typedef struct {
  PACKAGECHECKBULKItem_t   m_package;
  bool                     m_hasEcosystem;
  bool                     m_hasName;
  bool                     m_hasVersion;
  PackageElementProblem_t  m_problem;
  int                      m_earlierIndex;
} WATCHLISTEDITPackageElement_t;

typedef struct {
  const RequestCreditBudget_t* mp_creditBudget;
  WATCHLISTEDITAction_t        m_action;
  WatchlistItem_t              m_item;
} WATCHLISTEDITItemsDbParams_t;

typedef struct {
  const RequestCreditBudget_t*         mp_creditBudget;
  WATCHLISTEDITAction_t                m_action;
  const WATCHLISTEDITPackageElement_t* mp_elements;
  int                                  m_elementCount;
} WATCHLISTEDITPackageListDbParams_t;

typedef enum {
  WATCHLISTEDIT_OK = 0,
  WATCHLISTEDIT_OVER_LIMIT,
  WATCHLISTEDIT_OVER_DOMAIN_LIMIT,
  WATCHLISTEDIT_OVER_PACKAGE_LIMIT,
  WATCHLISTEDIT_OVER_PACKAGE_WEIGHT,
  WATCHLISTEDIT_UNKNOWN_KEY,
  WATCHLISTEDIT_PACKAGE_PROBLEM,
} WATCHLISTEDITStatus_t;

typedef struct {
  int  m_currentIndex;
  int  m_earlierIndex;
} WATCHLISTEDITPackageRepeat_t;

typedef struct {
  WATCHLISTEDITStatus_t  m_status;
  WatchlistItem_t*       mp_items;
  int                    m_itemCount;
  int                    m_itemCountForCurrentApiKey;
  int                    m_packageItemCountForCurrentApiKey;
} WATCHLISTEDITItemsResult_t;

typedef struct {
  WATCHLISTEDITStatus_t          m_status;
  WATCHLISTEDITAction_t          m_action;
  int                            m_addedCount;
  int                            m_removedCount;
  int                            m_unchangedCount;
  WATCHLISTEDITPackageRepeat_t*  mp_repeatedPackages;
  int                            m_repeatedCount;
  int                            m_packageItemCountForCurrentApiKey;
} WATCHLISTEDITPackageListResult_t;

typedef struct {
  char   ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  bool   m_hasPreviousValue;
  double m_previousValue;
  bool   m_hasCurrentValue;
  double m_currentValue;
  bool   m_hasProductPair;
  char   ma_vendor[CVESEARCH_VENDOR_LEN + 1];
  char   ma_product[CVESEARCH_PRODUCT_LEN + 1];
} WATCHLISTEVENTSCveChange_t;

typedef enum {
  WATCHLIST_EVENT_CVE = 0,
  WATCHLIST_EVENT_DNS_LOOKUP,
  WATCHLIST_EVENT_SSL_CHECK,
  WATCHLIST_EVENT_WHOIS_LOOKUP,
  WATCHLIST_EVENT_HEADERS_CHECK,
  WATCHLIST_EVENT_CERT_SEARCH,
  WATCHLIST_EVENT_PACKAGE_CHECK,
  WATCHLIST_EVENT_IP_LOOKUP,
  WATCHLIST_EVENT_PRODUCT_EXPOSURE,
} WatchlistEventKind_t;

typedef struct {
  char                 ma_eventType[WATCHLIST_EVENT_TYPE_MAX_LEN + 1];
  char                 ma_changedAt[CVELOOKUP_PUBLISHED_LEN + 1];
  WatchlistEventKind_t m_eventKind;
  union {
    WATCHLISTEVENTSCveChange_t       m_cveChange;
    WATCHLISTDNSLOOKUPChange_t       m_dnsLookupChange;
    WATCHLISTSSLCHECKChange_t        m_sslCheckChange;
    WATCHLISTWHOISLOOKUPChange_t     m_whoisLookupChange;
    WATCHLISTHEADERSCHECKChange_t    m_headersCheckChange;
    WATCHLISTCERTSEARCHChange_t      m_certSearchChange;
    WATCHLISTPACKAGECHECKChange_t    m_packageCheckChange;
    WATCHLISTIPLOOKUPChange_t        m_ipLookupChange;
    WATCHLISTPRODUCTEXPOSUREChange_t m_productExposureChange;
  };
} WATCHLISTEVENTSEvent_t;

typedef struct {
  WatchlistItem_t m_item;
  int             m_firstPairIndex;
  int             m_pairCount;
} WATCHLISTEVENTSAnswerItem_t;

typedef struct {
  char    ma_cveId[CVELOOKUP_ID_MAX_LEN + 1];
  double  m_riskScore;
  char    ma_riskLabel[CVERISKSCORE_LABEL_LEN + 1];
  bool    m_isInKev;
  bool    m_hasKev;
  char    ma_kevPatchDeadline[CVELOOKUP_PUBLISHED_LEN + 1];
  bool    m_kevKnownRansomware;
  bool    m_hasMetasploit;
  int     m_pocCount;
} WATCHLISTEVENTSCveFacts_t;

typedef enum {
  WATCHLISTEVENTS_OK = 0,
  WATCHLISTEVENTS_CURSOR_INVALID,
  WATCHLISTEVENTS_NO_POSITION,
  WATCHLISTEVENTS_UNKNOWN_KEY,
} WATCHLISTEVENTSStatus_t;

typedef struct {
  char                      ma_domainName[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char                      ma_registeredDomain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  WATCHLISTDNSLOOKUPFacts_t m_dnsFacts;
} WATCHLISTEVENTSDomainFacts_t;

typedef struct {
  WATCHLISTEVENTSStatus_t          m_status;
  char                             ma_nextCursor[WATCHLIST_CURSOR_MAX_LEN + 1];
  bool                             m_hasMore;
  WATCHLISTEVENTSEvent_t*          mp_events;
  int                              m_eventCount;
  WATCHLISTEVENTSAnswerItem_t*     mp_answerItems;
  int                              m_answerItemCount;
  int*                             mp_pairEventIndexes;
  bool*                            mp_pairIsVersionAffected;
  int                              m_pairCount;
  WATCHLISTEVENTSCveFacts_t*       mp_cveFacts;
  int                              m_cveFactCount;
  WATCHLISTEVENTSDomainFacts_t*    mp_domainFacts;
  int                              m_domainFactCount;
  WATCHLISTPACKAGECHECKAdvisory_t* mp_advisories;
  int                              m_advisoryCount;
  char*                            mp_attribution;
} WATCHLISTEVENTSResult_t;

bool                      watchlist_findItemKind        (const char* endpoint, WatchlistItemKind_t* kind_out);
const char*               watchlist_findEndpointName    (WatchlistItemKind_t kind);
bool                      watchlist_isDomainItemKind    (WatchlistItemKind_t kind);
bool                      watchlist_findDomainEventKind (WatchlistItemKind_t kind, WatchlistEventKind_t* kind_out);
const char*               watchlist_findDomainName      (const WatchlistItem_t* item);
WatchlistAddRequirement_t watchlist_findAddRequirement  (WatchlistItemKind_t kind);

#endif
