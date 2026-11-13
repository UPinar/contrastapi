#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>

#include "db.h"
#include "dbhelper.h"
#include "cve.h"
#include "emailcheck.h"
#include "jsonread.h"
#include "macro.h"
#include "package.h"
#include "validate.h"
#include "watchlist/watchlist.h"
#include "watchlist/watchlist_domain.h"

#define DB_WATCHLISTEDIT_ITEM_COLUMN(X, SUFFIX, name)   X(WATCHLISTEDIT_COLUMN_##SUFFIX, #name)
#define DB_WATCHLISTEVENTS_ITEM_COLUMN(X, SUFFIX, name) X(WATCHLISTEVENTS_COLUMN_ITEM_##SUFFIX, MACRO_STR(item_##name))

#define WATCHLIST_ENDPOINT_NAME_COLUMNS(X, C)    C(X, ENDPOINT_NAME, endpoint_name)
#define WATCHLIST_CVE_ID_COLUMNS(X, C)           C(X, CVE_ID, cve_id)
#define WATCHLIST_PRODUCT_PAIR_COLUMNS(X, C)     C(X, VENDOR, vendor) C(X, PRODUCT, product)
#define WATCHLIST_CVE_FILTER_COLUMNS(X, C)       \
  C(X, SEVERITY,            severity)            \
  C(X, CWE_ID,              cwe_id)              \
  C(X, MIN_CVSS,            min_cvss)            \
  C(X, MIN_EPSS,            min_epss)            \
  C(X, IN_KEV,              in_kev)              \
  C(X, KNOWN_RANSOMWARE,    known_ransomware)    \
  C(X, HAS_NUCLEI_TEMPLATE, has_nuclei_template)
#define WATCHLIST_PRODUCT_HAS_CVES_COLUMNS(X, C) C(X, PRODUCT_HAS_CVES, product_has_cves)
#define WATCHLIST_DOMAIN_COLUMNS(X, C)           C(X, DOMAIN_NAME, domain_name)
#define WATCHLIST_PACKAGE_COLUMNS(X, C) \
  C(X, ECOSYSTEM,    ecosystem)         \
  C(X, PACKAGE_NAME, package_name)
#define WATCHLIST_VERSION_COLUMNS(X, C)          C(X, VERSION, version)
#define WATCHLIST_IP_COLUMNS(X, C)               C(X, IP_ADDRESS, ip_address)

#define WATCHLIST_ITEM_COLUMNS(X, C)       \
  WATCHLIST_ENDPOINT_NAME_COLUMNS(X, C)    \
  WATCHLIST_CVE_ID_COLUMNS(X, C)           \
  WATCHLIST_PRODUCT_PAIR_COLUMNS(X, C)     \
  WATCHLIST_CVE_FILTER_COLUMNS(X, C)       \
  WATCHLIST_PRODUCT_HAS_CVES_COLUMNS(X, C) \
  WATCHLIST_DOMAIN_COLUMNS(X, C)           \
  WATCHLIST_PACKAGE_COLUMNS(X, C)          \
  WATCHLIST_VERSION_COLUMNS(X, C)          \
  WATCHLIST_IP_COLUMNS(X, C)

#define WATCHLISTEDIT_STATUS_COLUMNS(X, C)    C(X, EDIT_STATUS, edit_status)
#define WATCHLISTEDIT_KEY_COUNT_COLUMNS(X, C) \
  C(X, ITEM_COUNT,         item_count)        \
  C(X, PACKAGE_ITEM_COUNT, package_item_count)
#define WATCHLISTEDIT_COLUMNS(X)                                \
  WATCHLISTEDIT_STATUS_COLUMNS(X, DB_WATCHLISTEDIT_ITEM_COLUMN) \
  WATCHLIST_ITEM_COLUMNS(X, DB_WATCHLISTEDIT_ITEM_COLUMN)       \
  WATCHLISTEDIT_KEY_COUNT_COLUMNS(X, DB_WATCHLISTEDIT_ITEM_COLUMN)
enum { WATCHLISTEDIT_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEDIT_COLUMN_NAMES[] = { WATCHLISTEDIT_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_WATCHLISTEDIT_CVE_ID_COLUMN(X, SUFFIX, name)           X(WATCHLISTEDIT_CVE_ID_COLUMN_##SUFFIX, #name)
#define DB_WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN(X, SUFFIX, name) X(WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_##SUFFIX, #name)
#define DB_WATCHLISTEDIT_CVE_SEARCH_COLUMN(X, SUFFIX, name)       X(WATCHLISTEDIT_CVE_SEARCH_COLUMN_##SUFFIX, #name)
#define DB_WATCHLISTEDIT_DOMAIN_COLUMN(X, SUFFIX, name)           X(WATCHLISTEDIT_DOMAIN_COLUMN_##SUFFIX, #name)
#define DB_WATCHLISTEDIT_PACKAGE_COLUMN(X, SUFFIX, name)          X(WATCHLISTEDIT_PACKAGE_COLUMN_##SUFFIX, #name)
#define DB_WATCHLISTEDIT_IP_COLUMN(X, SUFFIX, name)               X(WATCHLISTEDIT_IP_COLUMN_##SUFFIX, #name)
#define DB_WATCHLISTEDIT_PACKAGE_LIST_COLUMN(X, SUFFIX, name)     X(WATCHLISTEDIT_PACKAGE_LIST_COLUMN_##SUFFIX, #name)

#define WATCHLISTEDIT_CVE_ID_COLUMNS(X)                              \
  WATCHLISTEDIT_STATUS_COLUMNS(X, DB_WATCHLISTEDIT_CVE_ID_COLUMN)    \
  WATCHLIST_ENDPOINT_NAME_COLUMNS(X, DB_WATCHLISTEDIT_CVE_ID_COLUMN) \
  WATCHLIST_CVE_ID_COLUMNS(X, DB_WATCHLISTEDIT_CVE_ID_COLUMN)        \
  WATCHLISTEDIT_KEY_COUNT_COLUMNS(X, DB_WATCHLISTEDIT_CVE_ID_COLUMN)
enum { WATCHLISTEDIT_CVE_ID_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEDIT_CVE_ID_COLUMN_NAMES[] = { WATCHLISTEDIT_CVE_ID_COLUMNS(DBHELPER_COLUMN_NAME) };

#define WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMNS(X)                                 \
  WATCHLISTEDIT_STATUS_COLUMNS(X, DB_WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN)       \
  WATCHLIST_ENDPOINT_NAME_COLUMNS(X, DB_WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN)    \
  WATCHLIST_PRODUCT_PAIR_COLUMNS(X, DB_WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN)     \
  WATCHLIST_PRODUCT_HAS_CVES_COLUMNS(X, DB_WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN) \
  WATCHLIST_VERSION_COLUMNS(X, DB_WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN)          \
  WATCHLISTEDIT_KEY_COUNT_COLUMNS(X, DB_WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN)
enum { WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_NAMES[] = { WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define WATCHLISTEDIT_CVE_SEARCH_COLUMNS(X)                              \
  WATCHLISTEDIT_STATUS_COLUMNS(X, DB_WATCHLISTEDIT_CVE_SEARCH_COLUMN)    \
  WATCHLIST_ENDPOINT_NAME_COLUMNS(X, DB_WATCHLISTEDIT_CVE_SEARCH_COLUMN) \
  WATCHLIST_PRODUCT_PAIR_COLUMNS(X, DB_WATCHLISTEDIT_CVE_SEARCH_COLUMN)  \
  WATCHLIST_CVE_FILTER_COLUMNS(X, DB_WATCHLISTEDIT_CVE_SEARCH_COLUMN)    \
  WATCHLISTEDIT_KEY_COUNT_COLUMNS(X, DB_WATCHLISTEDIT_CVE_SEARCH_COLUMN)
enum { WATCHLISTEDIT_CVE_SEARCH_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEDIT_CVE_SEARCH_COLUMN_NAMES[] = { WATCHLISTEDIT_CVE_SEARCH_COLUMNS(DBHELPER_COLUMN_NAME) };

#define WATCHLISTEDIT_DOMAIN_COLUMNS(X)                              \
  WATCHLISTEDIT_STATUS_COLUMNS(X, DB_WATCHLISTEDIT_DOMAIN_COLUMN)    \
  WATCHLIST_ENDPOINT_NAME_COLUMNS(X, DB_WATCHLISTEDIT_DOMAIN_COLUMN) \
  WATCHLIST_DOMAIN_COLUMNS(X, DB_WATCHLISTEDIT_DOMAIN_COLUMN)        \
  WATCHLISTEDIT_KEY_COUNT_COLUMNS(X, DB_WATCHLISTEDIT_DOMAIN_COLUMN)
enum { WATCHLISTEDIT_DOMAIN_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEDIT_DOMAIN_COLUMN_NAMES[] = { WATCHLISTEDIT_DOMAIN_COLUMNS(DBHELPER_COLUMN_NAME) };

#define WATCHLISTEDIT_PACKAGE_COLUMNS(X)                              \
  WATCHLISTEDIT_STATUS_COLUMNS(X, DB_WATCHLISTEDIT_PACKAGE_COLUMN)    \
  WATCHLIST_ENDPOINT_NAME_COLUMNS(X, DB_WATCHLISTEDIT_PACKAGE_COLUMN) \
  WATCHLIST_PACKAGE_COLUMNS(X, DB_WATCHLISTEDIT_PACKAGE_COLUMN)       \
  WATCHLIST_VERSION_COLUMNS(X, DB_WATCHLISTEDIT_PACKAGE_COLUMN)       \
  WATCHLISTEDIT_KEY_COUNT_COLUMNS(X, DB_WATCHLISTEDIT_PACKAGE_COLUMN)
enum { WATCHLISTEDIT_PACKAGE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEDIT_PACKAGE_COLUMN_NAMES[] = { WATCHLISTEDIT_PACKAGE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define WATCHLISTEDIT_IP_COLUMNS(X)                              \
  WATCHLISTEDIT_STATUS_COLUMNS(X, DB_WATCHLISTEDIT_IP_COLUMN)    \
  WATCHLIST_ENDPOINT_NAME_COLUMNS(X, DB_WATCHLISTEDIT_IP_COLUMN) \
  WATCHLIST_IP_COLUMNS(X, DB_WATCHLISTEDIT_IP_COLUMN)            \
  WATCHLISTEDIT_KEY_COUNT_COLUMNS(X, DB_WATCHLISTEDIT_IP_COLUMN)
enum { WATCHLISTEDIT_IP_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEDIT_IP_COLUMN_NAMES[] = { WATCHLISTEDIT_IP_COLUMNS(DBHELPER_COLUMN_NAME) };

#define WATCHLISTEDIT_PACKAGE_LIST_COLUMNS(X)                                                  \
  WATCHLISTEDIT_STATUS_COLUMNS(X, DB_WATCHLISTEDIT_PACKAGE_LIST_COLUMN)                         \
  DB_WATCHLISTEDIT_PACKAGE_LIST_COLUMN(X, PACKAGE_INDEX,         package_index)                 \
  DB_WATCHLISTEDIT_PACKAGE_LIST_COLUMN(X, EARLIER_PACKAGE_INDEX, earlier_package_index)         \
  DB_WATCHLISTEDIT_PACKAGE_LIST_COLUMN(X, ADDED_COUNT,           added_count)                   \
  DB_WATCHLISTEDIT_PACKAGE_LIST_COLUMN(X, REMOVED_COUNT,         removed_count)                 \
  DB_WATCHLISTEDIT_PACKAGE_LIST_COLUMN(X, UNCHANGED_COUNT,       unchanged_count)               \
  DB_WATCHLISTEDIT_PACKAGE_LIST_COLUMN(X, PACKAGE_ITEM_COUNT,    package_item_count)
enum { WATCHLISTEDIT_PACKAGE_LIST_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEDIT_PACKAGE_LIST_COLUMN_NAMES[] = { WATCHLISTEDIT_PACKAGE_LIST_COLUMNS(DBHELPER_COLUMN_NAME) };

#define WATCHLISTEVENTS_HEAD_COLUMNS(X)                    \
  X(WATCHLISTEVENTS_COLUMN_EVENTS_STATUS, "events_status") \
  X(WATCHLISTEVENTS_COLUMN_NEXT_CURSOR,   "next_cursor")   \
  X(WATCHLISTEVENTS_COLUMN_HAS_MORE,      "has_more")      \
  X(WATCHLISTEVENTS_COLUMN_ITEM_ID,       "item_id")
#define WATCHLISTEVENTS_EVENT_COLUMNS(X)                                                   \
  X(WATCHLISTEVENTS_COLUMN_EVENT_RANK,                    "event_rank")                    \
  X(WATCHLISTEVENTS_COLUMN_IS_FIRST_ROW_OF_EVENT,         "is_first_row_of_event")         \
  X(WATCHLISTEVENTS_COLUMN_EVENT_TYPE,                    "event_type")                    \
  X(WATCHLISTEVENTS_COLUMN_CHANGED_AT,                    "changed_at")                    \
  X(WATCHLISTEVENTS_COLUMN_CVE_ID,                        "cve_id")                        \
  X(WATCHLISTEVENTS_COLUMN_PREVIOUS_VALUE,                "previous_value")                \
  X(WATCHLISTEVENTS_COLUMN_CURRENT_VALUE,                 "current_value")                 \
  X(WATCHLISTEVENTS_COLUMN_VENDOR,                        "vendor")                        \
  X(WATCHLISTEVENTS_COLUMN_PRODUCT,                       "product")                       \
  X(WATCHLISTEVENTS_COLUMN_DEGRADED_EMAIL_CHECK_ID,       "degraded_email_check_id")       \
  X(WATCHLISTEVENTS_COLUMN_PREVIOUS_DOMAIN_VALUE,         "previous_domain_value")         \
  X(WATCHLISTEVENTS_COLUMN_CURRENT_DOMAIN_VALUE,          "current_domain_value")          \
  X(WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_CVE,         "is_first_event_of_cve")         \
  X(WATCHLISTEVENTS_COLUMN_RISK_SCORE,                    "risk_score")                    \
  X(WATCHLISTEVENTS_COLUMN_RISK_LABEL,                    "risk_label")                    \
  X(WATCHLISTEVENTS_COLUMN_IN_KEV,                        "in_kev")                        \
  X(WATCHLISTEVENTS_COLUMN_KEV_PATCH_DEADLINE,            "kev_patch_deadline")            \
  X(WATCHLISTEVENTS_COLUMN_KEV_KNOWN_RANSOMWARE,          "kev_known_ransomware")          \
  X(WATCHLISTEVENTS_COLUMN_HAS_METASPLOIT,                "has_metasploit")                \
  X(WATCHLISTEVENTS_COLUMN_POC_COUNT,                     "poc_count")                     \
  X(WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_DOMAIN,      "is_first_event_of_domain")      \
  X(WATCHLISTEVENTS_COLUMN_REGISTERED_DOMAIN,             "registered_domain")             \
  X(WATCHLISTEVENTS_COLUMN_DNS_PRESENCE_VALUE,            "dns_presence_value")            \
  X(WATCHLISTEVENTS_COLUMN_NS_VALUE,                      "ns_value")                      \
  X(WATCHLISTEVENTS_COLUMN_MX_VALUE,                      "mx_value")                      \
  X(WATCHLISTEVENTS_COLUMN_IP_ADDRESS_REACHABILITY_VALUE, "ip_address_reachability_value") \
  X(WATCHLISTEVENTS_COLUMN_CNAME_TAKEOVER_VALUE,          "cname_takeover_value")          \
  X(WATCHLISTEVENTS_COLUMN_EMAIL_AUTH_VALUE,              "email_auth_value")              \
  X(WATCHLISTEVENTS_COLUMN_ADVISORY_ID,                   "advisory_id")                   \
  X(WATCHLISTEVENTS_COLUMN_FIXED_VERSION,                 "fixed_version")                 \
  X(WATCHLISTEVENTS_COLUMN_PREVIOUS_IP_VALUE,             "previous_ip_value")             \
  X(WATCHLISTEVENTS_COLUMN_CURRENT_IP_VALUE,              "current_ip_value")              \
  X(WATCHLISTEVENTS_COLUMN_DROP_LIST_TIME,                "drop_list_time")                \
  X(WATCHLISTEVENTS_COLUMN_DROP_COPYRIGHT,                "drop_copyright")                \
  X(WATCHLISTEVENTS_COLUMN_EOL_PRODUCT,                   "eol_product")                   \
  X(WATCHLISTEVENTS_COLUMN_EOL_CYCLE,                     "eol_cycle")                     \
  X(WATCHLISTEVENTS_COLUMN_EOL_DATE,                      "eol_date")                      \
  X(WATCHLISTEVENTS_COLUMN_PREVIOUS_EOL_DATE,             "previous_eol_date")             \
  X(WATCHLISTEVENTS_COLUMN_AFFECTS_VERSION,               "affects_version")               \
  X(WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_ADVISORY,    "is_first_event_of_advisory")    \
  X(WATCHLISTEVENTS_COLUMN_ADVISORY_SOURCE,               "advisory_source")               \
  X(WATCHLISTEVENTS_COLUMN_ADVISORY_ALIASES,              "advisory_aliases")              \
  X(WATCHLISTEVENTS_COLUMN_ADVISORY_CVE_FACTS,            "advisory_cve_facts")            \
  X(WATCHLISTEVENTS_COLUMN_ATTRIBUTION,                   "attribution")
#define WATCHLISTEVENTS_COLUMNS(X)                          \
  WATCHLISTEVENTS_HEAD_COLUMNS(X)                           \
  WATCHLIST_ITEM_COLUMNS(X, DB_WATCHLISTEVENTS_ITEM_COLUMN) \
  WATCHLISTEVENTS_EVENT_COLUMNS(X)
enum { WATCHLISTEVENTS_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const WATCHLISTEVENTS_COLUMN_NAMES[] = { WATCHLISTEVENTS_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_WATCHLIST_STATUS_COLUMN 0
_Static_assert(WATCHLISTEDIT_COLUMN_EDIT_STATUS == DB_WATCHLIST_STATUS_COLUMN
            && WATCHLISTEDIT_CVE_ID_COLUMN_EDIT_STATUS == DB_WATCHLIST_STATUS_COLUMN
            && WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_EDIT_STATUS == DB_WATCHLIST_STATUS_COLUMN
            && WATCHLISTEDIT_CVE_SEARCH_COLUMN_EDIT_STATUS == DB_WATCHLIST_STATUS_COLUMN
            && WATCHLISTEDIT_DOMAIN_COLUMN_EDIT_STATUS == DB_WATCHLIST_STATUS_COLUMN
            && WATCHLISTEDIT_PACKAGE_COLUMN_EDIT_STATUS == DB_WATCHLIST_STATUS_COLUMN
            && WATCHLISTEDIT_IP_COLUMN_EDIT_STATUS == DB_WATCHLIST_STATUS_COLUMN
            && WATCHLISTEDIT_PACKAGE_LIST_COLUMN_EDIT_STATUS == DB_WATCHLIST_STATUS_COLUMN
            && WATCHLISTEVENTS_COLUMN_EVENTS_STATUS == DB_WATCHLIST_STATUS_COLUMN,
               "every watchlist answer must start with its status");

#define DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT (WATCHLISTEVENTS_COLUMN_ITEM_ENDPOINT_NAME - WATCHLISTEDIT_COLUMN_ENDPOINT_NAME)
_Static_assert(WATCHLISTEVENTS_COLUMN_ITEM_CVE_ID              - WATCHLISTEDIT_COLUMN_CVE_ID              == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_VENDOR              - WATCHLISTEDIT_COLUMN_VENDOR              == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_PRODUCT             - WATCHLISTEDIT_COLUMN_PRODUCT             == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_SEVERITY            - WATCHLISTEDIT_COLUMN_SEVERITY            == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_CWE_ID              - WATCHLISTEDIT_COLUMN_CWE_ID              == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_MIN_CVSS            - WATCHLISTEDIT_COLUMN_MIN_CVSS            == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_MIN_EPSS            - WATCHLISTEDIT_COLUMN_MIN_EPSS            == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_IN_KEV              - WATCHLISTEDIT_COLUMN_IN_KEV              == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_KNOWN_RANSOMWARE    - WATCHLISTEDIT_COLUMN_KNOWN_RANSOMWARE    == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_HAS_NUCLEI_TEMPLATE - WATCHLISTEDIT_COLUMN_HAS_NUCLEI_TEMPLATE == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_PRODUCT_HAS_CVES    - WATCHLISTEDIT_COLUMN_PRODUCT_HAS_CVES    == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_DOMAIN_NAME         - WATCHLISTEDIT_COLUMN_DOMAIN_NAME         == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_ECOSYSTEM           - WATCHLISTEDIT_COLUMN_ECOSYSTEM           == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_PACKAGE_NAME        - WATCHLISTEDIT_COLUMN_PACKAGE_NAME        == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_VERSION             - WATCHLISTEDIT_COLUMN_VERSION             == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT
            && WATCHLISTEVENTS_COLUMN_ITEM_IP_ADDRESS          - WATCHLISTEDIT_COLUMN_IP_ADDRESS          == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT,
               "each item_ column of an events row must stand at one distance from its edit twin");

typedef struct {
  int  m_eventRank;
  bool m_isFirstRowOfEvent;
  bool m_isFirstEventOfCve;
  bool m_isFirstEventOfDomain;
  bool m_isFirstEventOfAdvisory;
} DbWatchlistEventsRowFlags_t;

typedef struct {
  int m_rowCount;
  int m_eventCount;
  int m_cveFactCount;
  int m_domainFactCount;
  int m_advisoryCount;
  int m_cveFactCapacity;
} DbWatchlistEventsEntryCounts_t;

typedef struct {
  char                         ma_lastItemId[WATCHLIST_CURSOR_MAX_LEN + 1];
  bool*                        mp_isEventFilled;
  DbWatchlistEventsRowFlags_t* mp_rowFlags;
  int                          m_filledDomainCount;
  int                          m_filledAdvisoryCount;
} DbWatchlistEventsReadState_t;

#define DB_DOMAIN_WATCH_CLAIM_COLUMNS(X)                         \
  X(DB_DOMAIN_WATCH_CLAIM_COLUMN_DOMAIN_NAME,   "domain_name")   \
  X(DB_DOMAIN_WATCH_CLAIM_COLUMN_CLAIMED_UNTIL, "claimed_until")
enum { DB_DOMAIN_WATCH_CLAIM_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_DOMAIN_WATCH_CLAIM_COLUMN_NAMES[] = { DB_DOMAIN_WATCH_CLAIM_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_DOMAIN_WATCH_RECORD_COLUMNS(X)                                     \
  X(DB_DOMAIN_WATCH_RECORD_COLUMN_WRITTEN_EVENT_COUNT, "written_event_count")
enum { DB_DOMAIN_WATCH_RECORD_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES[] = { DB_DOMAIN_WATCH_RECORD_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_WATCHLIST_STATUS_MAX_LEN 19

static bool         static_tryReadStatusText                        (PGresult* res, char* status_out, size_t status_size);
static bool         static_isIdText                                 (const char* text);
static bool         static_tryReadTextOrEmpty                       (PGresult* res, int row, int column, char* field, size_t max_len);
static bool         static_tryReadNumberOrUnset                     (PGresult* res, int row, int column, double* value_out);
static const char*  static_WATCHLISTEDITActionText                  (WATCHLISTEDITAction_t action);
static bool         static_WATCHLISTEDITReadStatus                  (PGresult* res, WATCHLISTEDITStatus_t* status_out);
static bool         static_WATCHLISTEDITIsItemEndpoint              (const char* endpoint, WatchlistItemKind_t kind);
static bool         static_WATCHLISTEDITTryStoreItem                (WATCHLISTEDITItemsResult_t* result_out, const WatchlistItem_t* item);
static DbStatus_t   static_WATCHLISTEDITReadList                    (PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out);
static DbStatus_t   static_WATCHLISTEDITChangeCveIdItem             (PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out);
static DbStatus_t   static_WATCHLISTEDITChangeProductExposureItem   (PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out);
static DbStatus_t   static_WATCHLISTEDITChangeCveSearchItem         (PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out);
static DbStatus_t   static_WATCHLISTEDITChangeDomainItem            (PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, const char* registered_domain, WATCHLISTEDITItemsResult_t* result_out);
static DbStatus_t   static_WATCHLISTEDITChangePackageItem           (PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out);
static DbStatus_t   static_WATCHLISTEDITChangeIpItem                (PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out);
static bool         static_WATCHLISTEDITTryReadPackageListCounts    (PGresult* res, WATCHLISTEDITPackageListResult_t* result_out);
static bool         static_WATCHLISTEDITTryReadPackageRepeats       (PGresult* res, WATCHLISTEDITPackageListResult_t* result_out);
static bool         static_WATCHLISTEDITFillItem                    (PGresult* res, int row_index, int column_shift, WatchlistItem_t* item);
static bool         static_WATCHLISTEDITFillCveId                   (PGresult* res, int row_index, int column_shift, char* cve_id);
static bool         static_WATCHLISTEDITFillProductExposure         (PGresult* res, int row_index, int column_shift, WATCHLISTPRODUCTEXPOSUREItem_t* product);
static bool         static_WATCHLISTEDITFillCveSearch               (PGresult* res, int row_index, int column_shift, WATCHLISTCVESEARCHItem_t* filter);
static bool         static_WATCHLISTEDITFillDomainName              (PGresult* res, int row_index, int column_shift, char* domain_name);
static bool         static_WATCHLISTEDITFillPackageCheck            (PGresult* res, int row_index, int column_shift, WATCHLISTPACKAGECHECKItem_t* package);
static bool         static_WATCHLISTEDITFillIpAddress               (PGresult* res, int row_index, int column_shift, char* ip_address);
static int          static_compareIdText                            (const char* left, const char* right);
static bool         static_WATCHLISTEVENTSReadRowFlags              (PGresult* res, int row_index, DbWatchlistEventsRowFlags_t* flags);
static bool         static_WATCHLISTEVENTSCountEntries              (PGresult* res, DbWatchlistEventsRowFlags_t* row_flags, DbWatchlistEventsEntryCounts_t* counts);
static bool         static_WATCHLISTEVENTSAllocateArrays            (const DbWatchlistEventsEntryCounts_t* counts, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state);
static bool         static_WATCHLISTEVENTSReadAttribution           (PGresult* res, WATCHLISTEVENTSResult_t* result);
static bool         static_WATCHLISTEVENTSOpenItemOnNewId           (PGresult* res, int row_index, const char* item_id, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state);
static bool         static_WATCHLISTEVENTSAddCveFacts               (PGresult* res, int row_index, WATCHLISTEVENTSResult_t* result);
static bool         static_WATCHLISTEVENTSAddDomainFacts            (PGresult* res, int row_index, const WatchlistItem_t* item, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state);
static bool         static_WATCHLISTEVENTSIsAdvisoryAdded           (const WATCHLISTEVENTSResult_t* result, int added_count, const char* advisory_id);
static bool         static_WATCHLISTEVENTSAddAdvisory               (PGresult* res, int row_index, const DbWatchlistEventsRowFlags_t* flags, const WATCHLISTEVENTSEvent_t* event, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state);
static bool         static_WATCHLISTEVENTSReadPairRow               (PGresult* res, int row_index, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state);
static bool         static_WATCHLISTEVENTSIsEveryEventFilled        (const WATCHLISTEVENTSResult_t* result, const DbWatchlistEventsReadState_t* state);
static bool         static_WATCHLISTEVENTSReadRows                  (PGresult* res, WATCHLISTEVENTSResult_t* result);
static bool         static_WATCHLISTEVENTSFillEvent                 (PGresult* res, int row_index, const WatchlistItem_t* item, WATCHLISTEVENTSEvent_t* event);
static bool         static_WATCHLISTEVENTSFillCveChange             (PGresult* res, int row_index, WATCHLISTEVENTSCveChange_t* change);
static bool         static_WATCHLISTEVENTSFillIpLookupChange        (PGresult* res, int row_index, WATCHLISTIPLOOKUPChange_t* change);
static bool         static_WATCHLISTEVENTSFillDnsLookupChange       (PGresult* res, int row_index, WATCHLISTDNSLOOKUPChange_t* change);
static bool         static_WATCHLISTEVENTSFillSslCheckChange        (PGresult* res, int row_index, WATCHLISTSSLCHECKChange_t* change);
static bool         static_WATCHLISTEVENTSFillWhoisLookupChange     (PGresult* res, int row_index, WATCHLISTWHOISLOOKUPChange_t* change);
static bool         static_WATCHLISTEVENTSFillHeadersCheckChange    (PGresult* res, int row_index, WATCHLISTHEADERSCHECKChange_t* change);
static bool         static_WATCHLISTEVENTSFillCertSearchChange      (PGresult* res, int row_index, WATCHLISTCERTSEARCHChange_t* change);
static bool         static_WATCHLISTEVENTSIsDomainValueWithinLength (PGresult* res, int row_index);
static void         static_WATCHLISTEVENTSFreeEventTexts            (WATCHLISTEVENTSEvent_t* event);
static bool         static_WATCHLISTEVENTSFillPackageChange         (PGresult* res, int row_index, WATCHLISTPACKAGECHECKChange_t* change);
static bool         static_WATCHLISTEVENTSFillProductExposureChange (PGresult* res, int row_index, const char* event_type, WATCHLISTPRODUCTEXPOSUREChange_t* change);
static bool         static_WATCHLISTEVENTSFillAdvisory              (PGresult* res, int row_index, const WATCHLISTEVENTSEvent_t* event, WATCHLISTPACKAGECHECKAdvisory_t* advisory);
static bool         static_WATCHLISTEVENTSAppendAliasFacts          (PGresult* res, int row_index, WATCHLISTEVENTSResult_t* result);
static bool         static_WATCHLISTEVENTSReadAliasFact             (JsonReadSpan_t object_span, WATCHLISTEVENTSCveFacts_t* facts);
static bool         static_WATCHLISTEVENTSHasCveFacts               (const WATCHLISTEVENTSResult_t* result, const char* cve_id);
static bool         static_WATCHLISTEVENTSFillCveFacts              (PGresult* res, int row_index, WATCHLISTEVENTSCveFacts_t* facts);
static bool         static_WATCHLISTEVENTSFillDomainFacts           (PGresult* res, int row_index, const WatchlistItem_t* item, WATCHLISTEVENTSDomainFacts_t* facts);
static bool         static_WATCHLISTEVENTSFillDomainDnsFacts        (PGresult* res, int row_index, WATCHLISTDNSLOOKUPFacts_t* dns_facts);
static bool         static_tryFillDomainScanClaim                   (PGresult* res, int row, WatchlistDomainScanClaim_t* claim);
static const char*  static_valueTextOrNull                          (const WatchlistDomainValue_t* value);
static const char*  static_valueSha256OrNull                        (const WatchlistDomainValue_t* value);
static bool         static_tryReadWrittenEventCount                 (PGresult* res);

bool db_purgeExpiredCveChangeEvents(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_cve_change_event_purge($1) AS purged_event_count",
                               "purged_event_count",
                               DB_CVE_CHANGE_PURGE_BATCH_EVENT_COUNT);
}

bool db_purgeExpiredWatchlists(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_watchlist_purge($1) AS cleared_key_count",
                               "cleared_key_count",
                               DB_WATCHLIST_PURGE_BATCH_KEY_COUNT);
}

bool db_purgeExpiredDomainChangeEvents(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_domain_change_event_purge($1) AS purged_event_count",
                               "purged_event_count",
                               DB_DOMAIN_CHANGE_PURGE_BATCH_EVENT_COUNT);
}

bool db_purgeExpiredEolChangeEvents(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_eol_change_event_purge($1) AS purged_event_count",
                               "purged_event_count",
                               DB_EOL_CHANGE_PURGE_BATCH_EVENT_COUNT);
}

bool db_purgeExpiredPackageAdvisoryChangeEvents(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_package_advisory_change_event_purge($1) AS purged_event_count",
                               "purged_event_count",
                               DB_PACKAGE_ADVISORY_CHANGE_PURGE_BATCH_EVENT_COUNT);
}

bool db_purgeUnwatchedDomains(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_domain_watch_purge_unwatched($1) AS purged_domain_count",
                               "purged_domain_count",
                               DB_DOMAIN_WATCH_PURGE_BATCH_DOMAIN_COUNT);
}

bool db_writeWatchedIpValues(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_ip_watch_write_values($1) AS evaluated_item_count",
                               "evaluated_item_count",
                               DB_IP_WATCH_WRITE_BATCH_ITEM_COUNT);
}

bool db_purgeExpiredIpChangeEvents(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_ip_change_event_purge($1) AS purged_event_count",
                               "purged_event_count",
                               DB_IP_CHANGE_PURGE_BATCH_EVENT_COUNT);
}

DbStatus_t db_claimDomainLaneScans(PGconn* conn, const char* lane_name, WatchlistDomainScanClaim_t* claims_out, int* claim_count_out)
{
  assert(lane_name       != NULL);
  assert(claims_out      != NULL);
  assert(claim_count_out != NULL);

  *claim_count_out = 0;
  char domain_row_count_str[DBHELPER_INT_PARAM_BUF_SIZE];
  char lease_seconds_str[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    lane_name,
    dbhelper_intParam(domain_row_count_str, sizeof(domain_row_count_str), DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT),
    dbhelper_intParam(lease_seconds_str,    sizeof(lease_seconds_str),    DB_DOMAIN_SCAN_LEASE_SECONDS),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_domain_watch_claim($1, $2, $3)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  int  row_count = PQntuples(res);
  bool is_read   = dbhelper_isColumnListEqual(res, DB_DOMAIN_WATCH_CLAIM_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_DOMAIN_WATCH_CLAIM_COLUMN_NAMES))
                && row_count <= DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT;
  for (int row = 0; is_read && row < row_count; row++)
    is_read = static_tryFillDomainScanClaim(res, row, &claims_out[row]);
  PQclear(res);

  if (!is_read)
    return DB_ERROR;
  *claim_count_out = row_count;
  return DB_OK;
}

DbStatus_t db_recordDnsScan(PGconn* conn, const DbDnsScanRecord_t* scan)
{
  assert(scan                  != NULL);
  assert(scan->mp_domain       != NULL);
  assert(scan->mp_claimedUntil != NULL);

  char question_count_str[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    scan->mp_domain,
    scan->mp_claimedUntil,
    static_valueTextOrNull(scan->mp_dnsPresenceValue),
    static_valueSha256OrNull(scan->mp_dnsPresenceValue),
    static_valueTextOrNull(scan->mp_nsValue),
    static_valueSha256OrNull(scan->mp_nsValue),
    static_valueTextOrNull(scan->mp_mxValue),
    static_valueSha256OrNull(scan->mp_mxValue),
    static_valueTextOrNull(scan->mp_ipAddressReachabilityValue),
    static_valueSha256OrNull(scan->mp_ipAddressReachabilityValue),
    static_valueTextOrNull(scan->mp_cnameTakeoverValue),
    static_valueSha256OrNull(scan->mp_cnameTakeoverValue),
    static_valueTextOrNull(scan->mp_emailAuthValue),
    static_valueSha256OrNull(scan->mp_emailAuthValue),
    scan->mp_emailCheckIds,
    scan->mp_hostingIpAddresses,
    dbhelper_intParam(question_count_str, sizeof(question_count_str), scan->m_questionCount),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_domain_watch_record_dns($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) AS written_event_count",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_read = dbhelper_isColumnListEqual(res, DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES))
              && static_tryReadWrittenEventCount(res);
  PQclear(res);

  if (!is_read)
    return DB_ERROR;
  return DB_OK;
}

DbStatus_t db_recordTlsScan(PGconn* conn, const DbTlsScanRecord_t* scan)
{
  assert(scan                  != NULL);
  assert(scan->mp_domain       != NULL);
  assert(scan->mp_claimedUntil != NULL);

  const char* param_values[] = {
    scan->mp_domain,
    scan->mp_claimedUntil,
    static_valueTextOrNull(scan->mp_certificateExpiryValue),
    static_valueSha256OrNull(scan->mp_certificateExpiryValue),
    static_valueTextOrNull(scan->mp_certificateValidityValue),
    static_valueSha256OrNull(scan->mp_certificateValidityValue),
    static_valueTextOrNull(scan->mp_certificateListingValue),
    static_valueSha256OrNull(scan->mp_certificateListingValue),
    static_valueTextOrNull(scan->mp_tlsProtocolValue),
    static_valueSha256OrNull(scan->mp_tlsProtocolValue),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_domain_watch_record_tls($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) AS written_event_count",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_read = dbhelper_isColumnListEqual(res, DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES))
              && static_tryReadWrittenEventCount(res);
  PQclear(res);

  if (!is_read)
    return DB_ERROR;
  return DB_OK;
}

DbStatus_t db_recordRdapWhoisScan(PGconn* conn, const DbRdapWhoisScanRecord_t* scan)
{
  assert(scan                  != NULL);
  assert(scan->mp_domain       != NULL);
  assert(scan->mp_claimedUntil != NULL);
  assert(scan->m_retryAfterSeconds == 0 || (scan->mp_registrationExpiryValue == NULL && scan->mp_registrarValue == NULL && scan->mp_transferLockValue == NULL && scan->mp_dnssecDelegationValue == NULL));

  char retry_after_text[DBHELPER_UINT_STR_BUF_SIZE] = "";
  if (scan->m_retryAfterSeconds > 0)
    snprintf(retry_after_text, sizeof(retry_after_text), "%u", scan->m_retryAfterSeconds);

  const char* param_values[] = {
    scan->mp_domain,
    scan->mp_claimedUntil,
    static_valueTextOrNull(scan->mp_registrationExpiryValue),
    static_valueSha256OrNull(scan->mp_registrationExpiryValue),
    static_valueTextOrNull(scan->mp_registrarValue),
    static_valueSha256OrNull(scan->mp_registrarValue),
    static_valueTextOrNull(scan->mp_transferLockValue),
    static_valueSha256OrNull(scan->mp_transferLockValue),
    static_valueTextOrNull(scan->mp_dnssecDelegationValue),
    static_valueSha256OrNull(scan->mp_dnssecDelegationValue),
    scan->m_retryAfterSeconds > 0 ? retry_after_text : NULL,
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_domain_watch_record_rdap_whois($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) AS written_event_count",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_read = dbhelper_isColumnListEqual(res, DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES))
              && static_tryReadWrittenEventCount(res);
  PQclear(res);

  if (!is_read)
    return DB_ERROR;
  return DB_OK;
}

DbStatus_t db_recordHeadersScan(PGconn* conn, const DbHeadersScanRecord_t* scan)
{
  assert(scan                  != NULL);
  assert(scan->mp_domain       != NULL);
  assert(scan->mp_claimedUntil != NULL);
  assert(scan->m_retryAfterSeconds == 0 || scan->mp_securityHeadersValue == NULL);

  char retry_after_text[DBHELPER_UINT_STR_BUF_SIZE] = "";
  if (scan->m_retryAfterSeconds > 0)
    snprintf(retry_after_text, sizeof(retry_after_text), "%u", scan->m_retryAfterSeconds);

  const char* param_values[] = {
    scan->mp_domain,
    scan->mp_claimedUntil,
    static_valueTextOrNull(scan->mp_securityHeadersValue),
    static_valueSha256OrNull(scan->mp_securityHeadersValue),
    scan->m_retryAfterSeconds > 0 ? retry_after_text : NULL,
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_domain_watch_record_headers($1, $2, $3, $4, $5) AS written_event_count",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_read = dbhelper_isColumnListEqual(res, DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES))
              && static_tryReadWrittenEventCount(res);
  PQclear(res);

  if (!is_read)
    return DB_ERROR;
  return DB_OK;
}

DbStatus_t db_recordCtScan(PGconn* conn, const DbCtScanRecord_t* scan)
{
  assert(scan                  != NULL);
  assert(scan->mp_domain       != NULL);
  assert(scan->mp_claimedUntil != NULL);
  assert(scan->m_retryAfterSeconds == 0 || scan->mp_certIssuersValue == NULL);

  char retry_after_text[DBHELPER_UINT_STR_BUF_SIZE] = "";
  if (scan->m_retryAfterSeconds > 0)
    snprintf(retry_after_text, sizeof(retry_after_text), "%u", scan->m_retryAfterSeconds);

  const char* param_values[] = {
    scan->mp_domain,
    scan->mp_claimedUntil,
    static_valueTextOrNull(scan->mp_certIssuersValue),
    static_valueSha256OrNull(scan->mp_certIssuersValue),
    scan->m_retryAfterSeconds > 0 ? retry_after_text : NULL,
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_domain_watch_record_ct($1, $2, $3, $4, $5) AS written_event_count",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_read = dbhelper_isColumnListEqual(res, DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_DOMAIN_WATCH_RECORD_COLUMN_NAMES))
              && static_tryReadWrittenEventCount(res);
  PQclear(res);

  if (!is_read)
    return DB_ERROR;
  return DB_OK;
}

DbStatus_t db_WATCHLISTEDITItems(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, const char* registered_domain, WATCHLISTEDITItemsResult_t* result_out)
{
  assert(params != NULL);
  assert(params->mp_creditBudget != NULL);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));
  result_out->m_status = WATCHLISTEDIT_OK;

  if (params->m_action == WATCHLISTEDIT_ACTION_LIST || params->m_action == WATCHLISTEDIT_ACTION_CLEAR)
    return static_WATCHLISTEDITReadList(conn, params, result_out);

  assert(params->m_action == WATCHLISTEDIT_ACTION_ADD || params->m_action == WATCHLISTEDIT_ACTION_REMOVE);
  switch (params->m_item.m_itemKind)
  {
    case WATCHLIST_ITEM_CVE_LOOKUP:
    case WATCHLIST_ITEM_KEV_LOOKUP:
    case WATCHLIST_ITEM_CVE_EXPLOIT:
      return static_WATCHLISTEDITChangeCveIdItem(conn, params, result_out);
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
      return static_WATCHLISTEDITChangeProductExposureItem(conn, params, result_out);
    case WATCHLIST_ITEM_CVE_SEARCH:
      return static_WATCHLISTEDITChangeCveSearchItem(conn, params, result_out);
    case WATCHLIST_ITEM_DNS_LOOKUP:
    case WATCHLIST_ITEM_SSL_CHECK:
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
    case WATCHLIST_ITEM_HEADERS_CHECK:
    case WATCHLIST_ITEM_CERT_SEARCH:
      return static_WATCHLISTEDITChangeDomainItem(conn, params, registered_domain, result_out);
    case WATCHLIST_ITEM_PACKAGE_CHECK:
      return static_WATCHLISTEDITChangePackageItem(conn, params, result_out);
    case WATCHLIST_ITEM_IP_LOOKUP:
      return static_WATCHLISTEDITChangeIpItem(conn, params, result_out);
  }
  return DB_ERROR;
}

void db_WATCHLISTEDITItemsResultFree(WATCHLISTEDITItemsResult_t* result)
{
  if (!result)
    return;

  free(result->mp_items);
  result->mp_items    = NULL;
  result->m_itemCount = 0;
}

DbStatus_t db_WATCHLISTEDITPackageList(PGconn* conn, const WATCHLISTEDITPackageListDbParams_t* params, WATCHLISTEDITPackageListResult_t* result_out)
{
  assert(params != NULL);
  assert(params->mp_creditBudget != NULL);
  assert(result_out != NULL);
  assert(params->m_action == WATCHLISTEDIT_ACTION_ADD || params->m_action == WATCHLISTEDIT_ACTION_REMOVE);
  assert(params->m_elementCount >= 1 && params->m_elementCount <= WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY);
  assert(params->mp_elements != NULL);

  memset(result_out, 0, sizeof(*result_out));
  result_out->m_status = WATCHLISTEDIT_OK;

  const char* ecosystems[WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY];
  const char* package_names[WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY];
  const char* versions[WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY];
  for (int i = 0; i < params->m_elementCount; i++)
  {
    const WATCHLISTEDITPackageElement_t* element = &params->mp_elements[i];
    bool is_package   = element->m_problem == PACKAGE_ELEMENT_PROBLEM_NONE;
    ecosystems[i]     = is_package ? element->m_package.ma_ecosystem   : "";
    package_names[i]  = is_package ? element->m_package.ma_packageName : "";
    versions[i]       = is_package ? element->m_package.ma_version     : "";
  }

  char* ecosystem_array    = dbhelper_buildTextArrayLiteral(ecosystems, params->m_elementCount);
  char* package_name_array = dbhelper_buildTextArrayLiteral(package_names, params->m_elementCount);
  char* version_array      = dbhelper_buildTextArrayLiteral(versions, params->m_elementCount);
  if (!ecosystem_array || !package_name_array || !version_array)
  {
    free(ecosystem_array);
    free(package_name_array);
    free(version_array);
    return DB_ERROR;
  }

  char package_item_max_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char package_item_base_weight[DBHELPER_INT_PARAM_BUF_SIZE];
  char package_weight_budget[DBHELPER_INT_PARAM_BUF_SIZE];
  char listed_versions_per_weight[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    params->mp_creditBudget->ma_budgetHash,
    static_WATCHLISTEDITActionText(params->m_action),
    ecosystem_array,
    package_name_array,
    version_array,
    dbhelper_intParam(package_item_max_count, sizeof(package_item_max_count), WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY),
    dbhelper_intParam(package_item_base_weight, sizeof(package_item_base_weight), PACKAGECHECKBULK_ITEM_BASE_WEIGHT),
    dbhelper_intParam(package_weight_budget, sizeof(package_weight_budget), PACKAGECHECKBULK_WEIGHT_BUDGET),
    dbhelper_intParam(listed_versions_per_weight, sizeof(listed_versions_per_weight), PACKAGECHECKBULK_LISTED_VERSIONS_PER_WEIGHT),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_watchlist_package_list_edit($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  free(ecosystem_array);
  free(package_name_array);
  free(version_array);
  if (!res)
    return DB_ERROR;

  result_out->m_action = params->m_action;
  DbStatus_t db_status = DB_ERROR;
  if (!dbhelper_isColumnListEqual(res, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_PACKAGE_LIST_COLUMN_NAMES))
      || PQntuples(res) > params->m_elementCount
      || !static_WATCHLISTEDITReadStatus(res, &result_out->m_status))
  {
    goto done;
  }

  if (result_out->m_status == WATCHLISTEDIT_UNKNOWN_KEY)
    db_status = DB_OK;
  else if (result_out->m_status == WATCHLISTEDIT_PACKAGE_PROBLEM)
    db_status = static_WATCHLISTEDITTryReadPackageRepeats(res, result_out) ? DB_OK : DB_ERROR;
  else
    db_status = static_WATCHLISTEDITTryReadPackageListCounts(res, result_out) ? DB_OK : DB_ERROR;

done:
  PQclear(res);
  return db_status;
}

void db_WATCHLISTEDITPackageListResultFree(WATCHLISTEDITPackageListResult_t* result)
{
  if (!result)
    return;

  free(result->mp_repeatedPackages);
  result->mp_repeatedPackages = NULL;
  result->m_repeatedCount     = 0;
}

DbStatus_t db_WATCHLISTEVENTS(PGconn* conn, const WATCHLISTEVENTSParams_t* params, int event_row_count, WATCHLISTEVENTSResult_t* result_out)
{
  assert(params != NULL);
  assert(params->mp_creditBudget != NULL);
  assert(result_out != NULL);

  memset(result_out, 0, sizeof(*result_out));

  char row_count_text[DBHELPER_INT_PARAM_BUF_SIZE];
  char scan_count_text[DBHELPER_INT_PARAM_BUF_SIZE];
  char pair_count_text[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    params->mp_creditBudget->ma_budgetHash,
    dbhelper_textOrNull(params->ma_cursor),
    params->m_isRepeat ? "true" : "false",
    dbhelper_intParam(row_count_text,  sizeof(row_count_text),  event_row_count),
    dbhelper_intParam(scan_count_text, sizeof(scan_count_text), WATCHLIST_SCAN_EVENT_MAX_COUNT),
    dbhelper_intParam(pair_count_text, sizeof(pair_count_text), WATCHLIST_ANSWER_PAIR_MAX_COUNT),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_watchlist_events($1, $2, $3, $4, $5, $6)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  DbStatus_t db_status = DB_ERROR;
  char status_text[DB_WATCHLIST_STATUS_MAX_LEN + 1];
  if (!dbhelper_isColumnListEqual(res, WATCHLISTEVENTS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEVENTS_COLUMN_NAMES)))
    goto done;
  if (!static_tryReadStatusText(res, status_text, sizeof(status_text)))
    goto done;

  if (strcmp(status_text, "ok") == 0)
    result_out->m_status = WATCHLISTEVENTS_OK;
  else if (strcmp(status_text, "cursor_invalid") == 0)
    result_out->m_status = WATCHLISTEVENTS_CURSOR_INVALID;
  else if (strcmp(status_text, "no_position") == 0)
    result_out->m_status = WATCHLISTEVENTS_NO_POSITION;
  else if (strcmp(status_text, "unknown_key") == 0)
    result_out->m_status = WATCHLISTEVENTS_UNKNOWN_KEY;
  else
    goto done;

  if (PQgetisnull(res, 0, WATCHLISTEVENTS_COLUMN_HAS_MORE) || !dbhelper_fetchColBool(res, 0, WATCHLISTEVENTS_COLUMN_HAS_MORE, &result_out->m_hasMore))
    goto done;
  if (result_out->m_status == WATCHLISTEVENTS_OK)
  {
    if (PQgetisnull(res, 0, WATCHLISTEVENTS_COLUMN_NEXT_CURSOR))
      goto done;
    if (!dbhelper_fetchColStr(res, 0, WATCHLISTEVENTS_COLUMN_NEXT_CURSOR, result_out->ma_nextCursor, WATCHLIST_CURSOR_MAX_LEN))
      goto done;
    if (!static_isIdText(result_out->ma_nextCursor))
      goto done;
  }

  if (PQgetisnull(res, 0, WATCHLISTEVENTS_COLUMN_ITEM_ID))
  {
    if (PQntuples(res) == 1)
      db_status = DB_OK;
    goto done;
  }
  if (!static_WATCHLISTEVENTSReadRows(res, result_out))
  {
    db_WATCHLISTEVENTSResultFree(result_out);
    goto done;
  }
  db_status = DB_OK;

done:
  if (db_status != DB_OK)
    result_out->ma_nextCursor[0] = '\0';
  PQclear(res);

  return db_status;
}

void db_WATCHLISTEVENTSResultFree(WATCHLISTEVENTSResult_t* result)
{
  if (!result)
    return;
  for (int i = 0; result->mp_events != NULL && i < result->m_eventCount; i++)
    static_WATCHLISTEVENTSFreeEventTexts(&result->mp_events[i]);
  for (int i = 0; result->mp_domainFacts != NULL && i < result->m_domainFactCount; i++)
  {
    WATCHLISTDNSLOOKUPFacts_t* dns_facts = &result->mp_domainFacts[i].m_dnsFacts;
    free(dns_facts->mp_dnsPresenceValue);
    free(dns_facts->mp_nsValue);
    free(dns_facts->mp_mxValue);
    free(dns_facts->mp_ipAddressReachabilityValue);
    free(dns_facts->mp_cnameTakeoverValue);
    free(dns_facts->mp_emailAuthValue);
  }
  for (int i = 0; result->mp_advisories != NULL && i < result->m_advisoryCount; i++)
    free(result->mp_advisories[i].mp_aliases);
  free(result->mp_events);
  free(result->mp_answerItems);
  free(result->mp_pairEventIndexes);
  free(result->mp_pairIsVersionAffected);
  free(result->mp_cveFacts);
  free(result->mp_domainFacts);
  free(result->mp_advisories);
  free(result->mp_attribution);
  result->mp_events                = NULL;
  result->m_eventCount             = 0;
  result->mp_answerItems           = NULL;
  result->m_answerItemCount        = 0;
  result->mp_pairEventIndexes      = NULL;
  result->mp_pairIsVersionAffected = NULL;
  result->m_pairCount              = 0;
  result->mp_cveFacts              = NULL;
  result->m_cveFactCount           = 0;
  result->mp_domainFacts           = NULL;
  result->m_domainFactCount        = 0;
  result->mp_advisories            = NULL;
  result->m_advisoryCount          = 0;
  result->mp_attribution           = NULL;
}

static bool static_tryFillDomainScanClaim(PGresult* res, int row, WatchlistDomainScanClaim_t* claim)
{
  memset(claim, 0, sizeof(*claim));

  if (PQgetisnull(res, row, DB_DOMAIN_WATCH_CLAIM_COLUMN_DOMAIN_NAME) || PQgetisnull(res, row, DB_DOMAIN_WATCH_CLAIM_COLUMN_CLAIMED_UNTIL))
    return false;

  return dbhelper_fetchColStr(res, row, DB_DOMAIN_WATCH_CLAIM_COLUMN_DOMAIN_NAME, claim->ma_domain, VALIDATE_DOMAIN_NAME_MAX_LEN)
      && dbhelper_fetchColStr(res, row, DB_DOMAIN_WATCH_CLAIM_COLUMN_CLAIMED_UNTIL, claim->ma_claimedUntil, WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN);
}

static const char* static_valueTextOrNull(const WatchlistDomainValue_t* value)
{
  return value != NULL ? value->ma_text : NULL;
}

static const char* static_valueSha256OrNull(const WatchlistDomainValue_t* value)
{
  return value != NULL ? value->ma_sha256Hex : NULL;
}

static bool static_tryReadWrittenEventCount(PGresult* res)
{
  int written_event_count = 0;
  return PQntuples(res) == 1
      && !PQgetisnull(res, 0, DB_DOMAIN_WATCH_RECORD_COLUMN_WRITTEN_EVENT_COUNT)
      && dbhelper_fetchColInt(res, 0, DB_DOMAIN_WATCH_RECORD_COLUMN_WRITTEN_EVENT_COUNT, 0, &written_event_count)
      && written_event_count >= 0;
}

static bool static_tryReadStatusText(PGresult* res, char* status_out, size_t status_size)
{
  assert(res != NULL);
  assert(status_out != NULL);
  assert(status_size == DB_WATCHLIST_STATUS_MAX_LEN + 1);

  if (PQntuples(res) < 1 || PQgetisnull(res, 0, DB_WATCHLIST_STATUS_COLUMN))
    return false;

  return dbhelper_fetchColStr(res, 0, DB_WATCHLIST_STATUS_COLUMN, status_out, status_size - 1);
}

static bool static_isIdText(const char* text)
{
  assert(text != NULL);

  size_t text_len = strlen(text);
  if (text_len == 0)
    return false;
  if (text[0] == '0')
    return text_len == 1;

  for (size_t i = 0; i < text_len; i++)
  {
    if (!isdigit((unsigned char)text[i]))
      return false;
  }
  return true;
}

static bool static_tryReadTextOrEmpty(PGresult* res, int row, int column, char* field, size_t max_len)
{
  if (PQgetisnull(res, row, column))
  {
    field[0] = '\0';
    return true;
  }

  return dbhelper_fetchColStr(res, row, column, field, max_len);
}

static bool static_tryReadNumberOrUnset(PGresult* res, int row, int column, double* value_out)
{
  if (PQgetisnull(res, row, column))
  {
    *value_out = -1.0;
    return true;
  }
  return dbhelper_fetchColDouble(res, row, column, 0.0, value_out);
}

static const char* static_WATCHLISTEDITActionText(WATCHLISTEDITAction_t action)
{
  assert(action == WATCHLISTEDIT_ACTION_ADD || action == WATCHLISTEDIT_ACTION_REMOVE);
  return action == WATCHLISTEDIT_ACTION_ADD ? "add" : "remove";
}

static bool static_WATCHLISTEDITReadStatus(PGresult* res, WATCHLISTEDITStatus_t* status_out)
{
  assert(res != NULL);
  assert(status_out != NULL);

  char status_text[DB_WATCHLIST_STATUS_MAX_LEN + 1];
  if (!static_tryReadStatusText(res, status_text, sizeof(status_text)))
    return false;

  if (strcmp(status_text, "ok") == 0)
    *status_out = WATCHLISTEDIT_OK;
  else if (strcmp(status_text, "over_limit") == 0)
    *status_out = WATCHLISTEDIT_OVER_LIMIT;
  else if (strcmp(status_text, "over_domain_limit") == 0)
    *status_out = WATCHLISTEDIT_OVER_DOMAIN_LIMIT;
  else if (strcmp(status_text, "over_package_limit") == 0)
    *status_out = WATCHLISTEDIT_OVER_PACKAGE_LIMIT;
  else if (strcmp(status_text, "over_package_weight") == 0)
    *status_out = WATCHLISTEDIT_OVER_PACKAGE_WEIGHT;
  else if (strcmp(status_text, "unknown_key") == 0)
    *status_out = WATCHLISTEDIT_UNKNOWN_KEY;
  else if (strcmp(status_text, "package_problem") == 0)
    *status_out = WATCHLISTEDIT_PACKAGE_PROBLEM;
  else
    return false;
  return true;
}

static bool static_WATCHLISTEDITIsItemEndpoint(const char* endpoint, WatchlistItemKind_t kind)
{
  assert(endpoint != NULL);

  const char* kind_endpoint = watchlist_findEndpointName(kind);
  return kind_endpoint != NULL && strcmp(endpoint, kind_endpoint) == 0;
}

static bool static_WATCHLISTEDITTryStoreItem(WATCHLISTEDITItemsResult_t* result_out, const WatchlistItem_t* item)
{
  assert(result_out != NULL);
  assert(result_out->mp_items == NULL);
  assert(item != NULL);

  result_out->mp_items = calloc(1, sizeof(WatchlistItem_t));
  if (!result_out->mp_items)
    return false;
  result_out->mp_items[0] = *item;
  result_out->m_itemCount = 1;
  return true;
}

static DbStatus_t static_WATCHLISTEDITReadList(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out)
{
  assert(params->m_action == WATCHLISTEDIT_ACTION_LIST || params->m_action == WATCHLISTEDIT_ACTION_CLEAR);

  const char* param_values[] = { params->mp_creditBudget->ma_budgetHash };
  PGresult*   res            = NULL;
  bool        is_named       = false;
  if (params->m_action == WATCHLISTEDIT_ACTION_CLEAR)
  {
    res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_clear($1)", DBHELPER_PARAM_COUNT(param_values), param_values);
    is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_COLUMN_NAMES));
  }
  else
  {
    res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_list($1)", DBHELPER_PARAM_COUNT(param_values), param_values);
    is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_COLUMN_NAMES));
  }
  if (!res)
    return DB_ERROR;

  DbStatus_t db_status = DB_ERROR;
  if (!is_named || !static_WATCHLISTEDITReadStatus(res, &result_out->m_status))
    goto done;

  if (result_out->m_status == WATCHLISTEDIT_UNKNOWN_KEY)
  {
    db_status = DB_OK;
    goto done;
  }

  if (PQgetisnull(res, 0, WATCHLISTEDIT_COLUMN_ITEM_COUNT)
      || PQgetisnull(res, 0, WATCHLISTEDIT_COLUMN_PACKAGE_ITEM_COUNT)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_COLUMN_ITEM_COUNT, 0, &result_out->m_itemCountForCurrentApiKey)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_COLUMN_PACKAGE_ITEM_COUNT, 0, &result_out->m_packageItemCountForCurrentApiKey))
  {
    goto done;
  }

  int row_count = PQntuples(res);
  if (PQgetisnull(res, 0, WATCHLISTEDIT_COLUMN_ENDPOINT_NAME))
  {
    db_status = DB_OK;
    goto done;
  }

  result_out->mp_items = calloc((size_t)row_count, sizeof(WatchlistItem_t));
  if (!result_out->mp_items)
    goto done;

  for (int row_index = 0; row_index < row_count; row_index++)
  {
    if (!static_WATCHLISTEDITFillItem(res, row_index, 0, &result_out->mp_items[row_index]))
    {
      free(result_out->mp_items);
      result_out->mp_items = NULL;
      goto done;
    }
  }

  result_out->m_itemCount = row_count;
  db_status = DB_OK;

done:
  PQclear(res);
  return db_status;
}

static DbStatus_t static_WATCHLISTEDITChangeCveIdItem(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out)
{
  WatchlistItem_t answered;
  memset(&answered, 0, sizeof(answered));
  answered.m_itemKind = params->m_item.m_itemKind;
  const char* sent_cve_id     = NULL;
  char*       answered_cve_id = NULL;
  switch (params->m_item.m_itemKind)
  {
    case WATCHLIST_ITEM_CVE_LOOKUP:
      sent_cve_id     = params->m_item.m_cveLookup.ma_cveId;
      answered_cve_id = answered.m_cveLookup.ma_cveId;
      break;
    case WATCHLIST_ITEM_KEV_LOOKUP:
      sent_cve_id     = params->m_item.m_kevLookup.ma_cveId;
      answered_cve_id = answered.m_kevLookup.ma_cveId;
      break;
    case WATCHLIST_ITEM_CVE_EXPLOIT:
      sent_cve_id     = params->m_item.m_cveExploit.ma_cveId;
      answered_cve_id = answered.m_cveExploit.ma_cveId;
      break;
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
    case WATCHLIST_ITEM_CVE_SEARCH:
    case WATCHLIST_ITEM_DNS_LOOKUP:
    case WATCHLIST_ITEM_SSL_CHECK:
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
    case WATCHLIST_ITEM_HEADERS_CHECK:
    case WATCHLIST_ITEM_CERT_SEARCH:
    case WATCHLIST_ITEM_PACKAGE_CHECK:
    case WATCHLIST_ITEM_IP_LOOKUP:
      return DB_ERROR;
  }

  char item_max_count[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    params->mp_creditBudget->ma_budgetHash,
    static_WATCHLISTEDITActionText(params->m_action),
    dbhelper_textOrNull(sent_cve_id),
    dbhelper_intParam(item_max_count, sizeof(item_max_count), WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY),
  };
  PGresult* res      = NULL;
  bool      is_named = false;
  switch (params->m_item.m_itemKind)
  {
    case WATCHLIST_ITEM_CVE_LOOKUP:
      res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_edit_cve_lookup($1, $2, $3, $4)", DBHELPER_PARAM_COUNT(param_values), param_values);
      is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_CVE_ID_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_CVE_ID_COLUMN_NAMES));
      break;
    case WATCHLIST_ITEM_KEV_LOOKUP:
      res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_edit_kev_lookup($1, $2, $3, $4)", DBHELPER_PARAM_COUNT(param_values), param_values);
      is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_CVE_ID_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_CVE_ID_COLUMN_NAMES));
      break;
    case WATCHLIST_ITEM_CVE_EXPLOIT:
      res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_edit_cve_exploit($1, $2, $3, $4)", DBHELPER_PARAM_COUNT(param_values), param_values);
      is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_CVE_ID_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_CVE_ID_COLUMN_NAMES));
      break;
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
    case WATCHLIST_ITEM_CVE_SEARCH:
    case WATCHLIST_ITEM_DNS_LOOKUP:
    case WATCHLIST_ITEM_SSL_CHECK:
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
    case WATCHLIST_ITEM_HEADERS_CHECK:
    case WATCHLIST_ITEM_CERT_SEARCH:
    case WATCHLIST_ITEM_PACKAGE_CHECK:
    case WATCHLIST_ITEM_IP_LOOKUP:
      return DB_ERROR;
  }
  if (!res)
    return DB_ERROR;

  DbStatus_t db_status = DB_ERROR;
  char endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 1];
  if (!is_named || PQntuples(res) != 1 || !static_WATCHLISTEDITReadStatus(res, &result_out->m_status))
    goto done;
  if (result_out->m_status == WATCHLISTEDIT_UNKNOWN_KEY)
  {
    db_status = DB_OK;
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_CVE_ID_COLUMN_ITEM_COUNT)
      || PQgetisnull(res, 0, WATCHLISTEDIT_CVE_ID_COLUMN_PACKAGE_ITEM_COUNT)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_CVE_ID_COLUMN_ITEM_COUNT, 0, &result_out->m_itemCountForCurrentApiKey)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_CVE_ID_COLUMN_PACKAGE_ITEM_COUNT, 0, &result_out->m_packageItemCountForCurrentApiKey))
  {
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_CVE_ID_COLUMN_ENDPOINT_NAME))
  {
    db_status = DB_OK;
    goto done;
  }

  if (!dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_CVE_ID_COLUMN_ENDPOINT_NAME, endpoint, WATCHLIST_ENDPOINT_MAX_LEN)
      || !static_WATCHLISTEDITIsItemEndpoint(endpoint, answered.m_itemKind)
      || PQgetisnull(res, 0, WATCHLISTEDIT_CVE_ID_COLUMN_CVE_ID)
      || !dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_CVE_ID_COLUMN_CVE_ID, answered_cve_id, CVELOOKUP_ID_MAX_LEN))
  {
    goto done;
  }
  if (static_WATCHLISTEDITTryStoreItem(result_out, &answered))
    db_status = DB_OK;

done:
  PQclear(res);
  return db_status;
}

static DbStatus_t static_WATCHLISTEDITChangeProductExposureItem(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out)
{
  assert(params->m_item.m_itemKind == WATCHLIST_ITEM_PRODUCT_EXPOSURE);

  const WATCHLISTPRODUCTEXPOSUREItem_t* sent = &params->m_item.m_productExposure;
  char item_max_count[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    params->mp_creditBudget->ma_budgetHash,
    static_WATCHLISTEDITActionText(params->m_action),
    dbhelper_textOrNull(sent->ma_vendor),
    dbhelper_textOrNull(sent->ma_product),
    dbhelper_textOrNull(sent->ma_version),
    dbhelper_intParam(item_max_count, sizeof(item_max_count), WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_watchlist_edit_product_exposure($1, $2, $3, $4, $5, $6)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  DbStatus_t db_status = DB_ERROR;
  WatchlistItem_t answered;
  memset(&answered, 0, sizeof(answered));
  answered.m_itemKind = WATCHLIST_ITEM_PRODUCT_EXPOSURE;
  WATCHLISTPRODUCTEXPOSUREItem_t* product = &answered.m_productExposure;
  char endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 1];
  if (!dbhelper_isColumnListEqual(res, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_NAMES))
      || PQntuples(res) != 1
      || !static_WATCHLISTEDITReadStatus(res, &result_out->m_status))
  {
    goto done;
  }
  if (result_out->m_status == WATCHLISTEDIT_UNKNOWN_KEY)
  {
    db_status = DB_OK;
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_ITEM_COUNT)
      || PQgetisnull(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_PACKAGE_ITEM_COUNT)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_ITEM_COUNT, 0, &result_out->m_itemCountForCurrentApiKey)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_PACKAGE_ITEM_COUNT, 0, &result_out->m_packageItemCountForCurrentApiKey))
  {
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_ENDPOINT_NAME))
  {
    db_status = DB_OK;
    goto done;
  }

  if (!dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_ENDPOINT_NAME, endpoint, WATCHLIST_ENDPOINT_MAX_LEN)
      || !static_WATCHLISTEDITIsItemEndpoint(endpoint, answered.m_itemKind)
      || PQgetisnull(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_VENDOR)
      || PQgetisnull(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_PRODUCT)
      || PQgetisnull(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_PRODUCT_HAS_CVES)
      || !dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_VENDOR,  product->ma_vendor,  CVESEARCH_VENDOR_LEN)
      || !dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_PRODUCT, product->ma_product, CVESEARCH_PRODUCT_LEN)
      || !dbhelper_fetchColBool(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_PRODUCT_HAS_CVES, &product->m_hasCves)
      || !static_tryReadTextOrEmpty(res, 0, WATCHLISTEDIT_PRODUCT_EXPOSURE_COLUMN_VERSION, product->ma_version, PACKAGECHECK_VERSION_MAX_LEN))
  {
    goto done;
  }
  if (static_WATCHLISTEDITTryStoreItem(result_out, &answered))
    db_status = DB_OK;

done:
  PQclear(res);
  return db_status;
}

static DbStatus_t static_WATCHLISTEDITChangeCveSearchItem(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out)
{
  assert(params->m_item.m_itemKind == WATCHLIST_ITEM_CVE_SEARCH);

  const WATCHLISTCVESEARCHItem_t* sent = &params->m_item.m_cveSearch;
  char min_cvss[DBHELPER_NUMERIC_PARAM_BUF_SIZE];
  char min_epss[DBHELPER_NUMERIC_PARAM_BUF_SIZE];
  char item_max_count[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    params->mp_creditBudget->ma_budgetHash,
    static_WATCHLISTEDITActionText(params->m_action),
    dbhelper_textOrNull(sent->ma_vendor),
    dbhelper_textOrNull(sent->ma_product),
    dbhelper_textOrNull(sent->ma_severity),
    dbhelper_textOrNull(sent->ma_cweId),
    dbhelper_numberOrNull(min_cvss, sizeof(min_cvss), 2, sent->m_minCvss),
    dbhelper_numberOrNull(min_epss, sizeof(min_epss), 6, sent->m_minEpss),
    dbhelper_kevFilterValue(sent->m_kevFilter),
    sent->m_knownRansomware ? "true" : NULL,
    sent->m_hasNucleiTemplate ? "true" : NULL,
    dbhelper_intParam(item_max_count, sizeof(item_max_count), WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_watchlist_edit_cve_search($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  DbStatus_t db_status = DB_ERROR;
  WatchlistItem_t answered;
  memset(&answered, 0, sizeof(answered));
  answered.m_itemKind = WATCHLIST_ITEM_CVE_SEARCH;
  WATCHLISTCVESEARCHItem_t* filter = &answered.m_cveSearch;
  char endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 1];
  bool in_kev = false;
  if (!dbhelper_isColumnListEqual(res, WATCHLISTEDIT_CVE_SEARCH_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_CVE_SEARCH_COLUMN_NAMES))
      || PQntuples(res) != 1
      || !static_WATCHLISTEDITReadStatus(res, &result_out->m_status))
  {
    goto done;
  }
  if (result_out->m_status == WATCHLISTEDIT_UNKNOWN_KEY)
  {
    db_status = DB_OK;
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_ITEM_COUNT)
      || PQgetisnull(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_PACKAGE_ITEM_COUNT)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_ITEM_COUNT, 0, &result_out->m_itemCountForCurrentApiKey)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_PACKAGE_ITEM_COUNT, 0, &result_out->m_packageItemCountForCurrentApiKey))
  {
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_ENDPOINT_NAME))
  {
    db_status = DB_OK;
    goto done;
  }

  if (!dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_ENDPOINT_NAME, endpoint, WATCHLIST_ENDPOINT_MAX_LEN)
      || !static_WATCHLISTEDITIsItemEndpoint(endpoint, answered.m_itemKind)
      || !static_tryReadTextOrEmpty(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_VENDOR,   filter->ma_vendor,   CVESEARCH_VENDOR_LEN)
      || !static_tryReadTextOrEmpty(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_PRODUCT,  filter->ma_product,  CVESEARCH_PRODUCT_LEN)
      || !static_tryReadTextOrEmpty(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_SEVERITY, filter->ma_severity, CVELOOKUP_SEVERITY_LEN)
      || !static_tryReadTextOrEmpty(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_CWE_ID,   filter->ma_cweId,    CVELOOKUP_CWE_ID_LEN)
      || !static_tryReadNumberOrUnset(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_MIN_CVSS, &filter->m_minCvss)
      || !static_tryReadNumberOrUnset(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_MIN_EPSS, &filter->m_minEpss))
  {
    goto done;
  }

  if (PQgetisnull(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_IN_KEV))
    filter->m_kevFilter = CVE_KEV_FILTER_ANY;
  else if (!dbhelper_fetchColBool(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_IN_KEV, &in_kev))
    goto done;
  else
    filter->m_kevFilter = in_kev ? CVE_KEV_FILTER_ONLY_IN_KEV : CVE_KEV_FILTER_NOT_IN_KEV;

  if (!PQgetisnull(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_KNOWN_RANSOMWARE)
      && !dbhelper_fetchColBool(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_KNOWN_RANSOMWARE, &filter->m_knownRansomware))
    goto done;

  if (!PQgetisnull(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_HAS_NUCLEI_TEMPLATE)
      && !dbhelper_fetchColBool(res, 0, WATCHLISTEDIT_CVE_SEARCH_COLUMN_HAS_NUCLEI_TEMPLATE, &filter->m_hasNucleiTemplate))
    goto done;

  if (static_WATCHLISTEDITTryStoreItem(result_out, &answered))
    db_status = DB_OK;

done:
  PQclear(res);
  return db_status;
}

static DbStatus_t static_WATCHLISTEDITChangeDomainItem(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, const char* registered_domain, WATCHLISTEDITItemsResult_t* result_out)
{
  WatchlistItem_t answered;
  memset(&answered, 0, sizeof(answered));
  answered.m_itemKind = params->m_item.m_itemKind;
  char item_max_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char domain_name_max_count[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    params->mp_creditBudget->ma_budgetHash,
    static_WATCHLISTEDITActionText(params->m_action),
    dbhelper_textOrNull(watchlist_findDomainName(&params->m_item)),
    registered_domain,
    dbhelper_intParam(item_max_count, sizeof(item_max_count), WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY),
    dbhelper_intParam(domain_name_max_count, sizeof(domain_name_max_count), WATCHLIST_DOMAIN_NAME_MAX_COUNT_PER_REGISTERED_DOMAIN),
  };
  char*     answered_domain_name = NULL;
  PGresult* res                  = NULL;
  bool      is_named             = false;
  switch (params->m_item.m_itemKind)
  {
    case WATCHLIST_ITEM_DNS_LOOKUP:
      answered_domain_name = answered.m_dnsLookup.ma_domainName;
      res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_edit_dns_lookup($1, $2, $3, $4, $5, $6)", DBHELPER_PARAM_COUNT(param_values), param_values);
      is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_DOMAIN_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_DOMAIN_COLUMN_NAMES));
      break;
    case WATCHLIST_ITEM_SSL_CHECK:
      answered_domain_name = answered.m_sslCheck.ma_domainName;
      res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_edit_ssl_check($1, $2, $3, $4, $5, $6)", DBHELPER_PARAM_COUNT(param_values), param_values);
      is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_DOMAIN_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_DOMAIN_COLUMN_NAMES));
      break;
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
      answered_domain_name = answered.m_whoisLookup.ma_domainName;
      res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_edit_whois_lookup($1, $2, $3, $4, $5, $6)", DBHELPER_PARAM_COUNT(param_values), param_values);
      is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_DOMAIN_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_DOMAIN_COLUMN_NAMES));
      break;
    case WATCHLIST_ITEM_HEADERS_CHECK:
      answered_domain_name = answered.m_headersCheck.ma_domainName;
      res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_edit_headers_check($1, $2, $3, $4, $5, $6)", DBHELPER_PARAM_COUNT(param_values), param_values);
      is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_DOMAIN_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_DOMAIN_COLUMN_NAMES));
      break;
    case WATCHLIST_ITEM_CERT_SEARCH:
      answered_domain_name = answered.m_certSearch.ma_domainName;
      res      = dbhelper_executeQuery(conn, "SELECT * FROM api.fn_watchlist_edit_cert_search($1, $2, $3, $4, $5, $6)", DBHELPER_PARAM_COUNT(param_values), param_values);
      is_named = res && dbhelper_isColumnListEqual(res, WATCHLISTEDIT_DOMAIN_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_DOMAIN_COLUMN_NAMES));
      break;
    case WATCHLIST_ITEM_CVE_LOOKUP:
    case WATCHLIST_ITEM_KEV_LOOKUP:
    case WATCHLIST_ITEM_CVE_EXPLOIT:
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
    case WATCHLIST_ITEM_CVE_SEARCH:
    case WATCHLIST_ITEM_PACKAGE_CHECK:
    case WATCHLIST_ITEM_IP_LOOKUP:
      return DB_ERROR;
  }
  if (!res)
    return DB_ERROR;

  DbStatus_t db_status = DB_ERROR;
  char endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 1];
  if (!is_named || PQntuples(res) != 1 || !static_WATCHLISTEDITReadStatus(res, &result_out->m_status))
    goto done;
  if (result_out->m_status == WATCHLISTEDIT_UNKNOWN_KEY)
  {
    db_status = DB_OK;
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_DOMAIN_COLUMN_ITEM_COUNT)
      || PQgetisnull(res, 0, WATCHLISTEDIT_DOMAIN_COLUMN_PACKAGE_ITEM_COUNT)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_DOMAIN_COLUMN_ITEM_COUNT, 0, &result_out->m_itemCountForCurrentApiKey)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_DOMAIN_COLUMN_PACKAGE_ITEM_COUNT, 0, &result_out->m_packageItemCountForCurrentApiKey))
  {
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_DOMAIN_COLUMN_ENDPOINT_NAME))
  {
    db_status = DB_OK;
    goto done;
  }

  if (!dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_DOMAIN_COLUMN_ENDPOINT_NAME, endpoint, WATCHLIST_ENDPOINT_MAX_LEN)
      || !static_WATCHLISTEDITIsItemEndpoint(endpoint, answered.m_itemKind)
      || PQgetisnull(res, 0, WATCHLISTEDIT_DOMAIN_COLUMN_DOMAIN_NAME)
      || !dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_DOMAIN_COLUMN_DOMAIN_NAME, answered_domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN))
  {
    goto done;
  }
  if (static_WATCHLISTEDITTryStoreItem(result_out, &answered))
    db_status = DB_OK;

done:
  PQclear(res);
  return db_status;
}

static DbStatus_t static_WATCHLISTEDITChangePackageItem(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out)
{
  assert(params->m_item.m_itemKind == WATCHLIST_ITEM_PACKAGE_CHECK);

  const WATCHLISTPACKAGECHECKItem_t* sent = &params->m_item.m_packageCheck;
  char package_item_max_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char package_item_base_weight[DBHELPER_INT_PARAM_BUF_SIZE];
  char package_weight_budget[DBHELPER_INT_PARAM_BUF_SIZE];
  char listed_versions_per_weight[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    params->mp_creditBudget->ma_budgetHash,
    static_WATCHLISTEDITActionText(params->m_action),
    dbhelper_textOrNull(sent->ma_ecosystem),
    dbhelper_textOrNull(sent->ma_name),
    dbhelper_textOrNull(sent->ma_version),
    dbhelper_intParam(package_item_max_count, sizeof(package_item_max_count), WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY),
    dbhelper_intParam(package_item_base_weight, sizeof(package_item_base_weight), PACKAGECHECKBULK_ITEM_BASE_WEIGHT),
    dbhelper_intParam(package_weight_budget, sizeof(package_weight_budget), PACKAGECHECKBULK_WEIGHT_BUDGET),
    dbhelper_intParam(listed_versions_per_weight, sizeof(listed_versions_per_weight), PACKAGECHECKBULK_LISTED_VERSIONS_PER_WEIGHT),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_watchlist_edit_package_check($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  DbStatus_t db_status = DB_ERROR;
  WatchlistItem_t answered;
  memset(&answered, 0, sizeof(answered));
  answered.m_itemKind = WATCHLIST_ITEM_PACKAGE_CHECK;
  WATCHLISTPACKAGECHECKItem_t* package = &answered.m_packageCheck;
  char endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 1];
  if (!dbhelper_isColumnListEqual(res, WATCHLISTEDIT_PACKAGE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_PACKAGE_COLUMN_NAMES))
      || PQntuples(res) != 1
      || !static_WATCHLISTEDITReadStatus(res, &result_out->m_status))
  {
    goto done;
  }
  if (result_out->m_status == WATCHLISTEDIT_UNKNOWN_KEY)
  {
    db_status = DB_OK;
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_ITEM_COUNT)
      || PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_PACKAGE_ITEM_COUNT)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_ITEM_COUNT, 0, &result_out->m_itemCountForCurrentApiKey)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_PACKAGE_ITEM_COUNT, 0, &result_out->m_packageItemCountForCurrentApiKey))
  {
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_ENDPOINT_NAME))
  {
    db_status = DB_OK;
    goto done;
  }

  if (!dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_ENDPOINT_NAME, endpoint, WATCHLIST_ENDPOINT_MAX_LEN)
      || !static_WATCHLISTEDITIsItemEndpoint(endpoint, answered.m_itemKind)
      || PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_ECOSYSTEM)
      || !dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_ECOSYSTEM, package->ma_ecosystem, PACKAGECHECK_ECOSYSTEM_MAX_LEN)
      || PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_PACKAGE_NAME)
      || !dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_PACKAGE_NAME, package->ma_name, PACKAGECHECK_NAME_MAX_LEN)
      || !static_tryReadTextOrEmpty(res, 0, WATCHLISTEDIT_PACKAGE_COLUMN_VERSION, package->ma_version, PACKAGECHECK_VERSION_MAX_LEN))
  {
    goto done;
  }
  if (static_WATCHLISTEDITTryStoreItem(result_out, &answered))
    db_status = DB_OK;

done:
  PQclear(res);
  return db_status;
}

static DbStatus_t static_WATCHLISTEDITChangeIpItem(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, WATCHLISTEDITItemsResult_t* result_out)
{
  assert(params->m_item.m_itemKind == WATCHLIST_ITEM_IP_LOOKUP);

  char item_max_count[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    params->mp_creditBudget->ma_budgetHash,
    static_WATCHLISTEDITActionText(params->m_action),
    dbhelper_textOrNull(params->m_item.m_ipLookup.ma_ipAddress),
    dbhelper_intParam(item_max_count, sizeof(item_max_count), WATCHLIST_ITEM_MAX_COUNT_PER_API_KEY),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_watchlist_edit_ip_lookup($1, $2, $3, $4)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  DbStatus_t db_status = DB_ERROR;
  WatchlistItem_t answered;
  memset(&answered, 0, sizeof(answered));
  answered.m_itemKind = WATCHLIST_ITEM_IP_LOOKUP;
  char endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 1];
  if (!dbhelper_isColumnListEqual(res, WATCHLISTEDIT_IP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(WATCHLISTEDIT_IP_COLUMN_NAMES))
      || PQntuples(res) != 1
      || !static_WATCHLISTEDITReadStatus(res, &result_out->m_status))
  {
    goto done;
  }
  if (result_out->m_status == WATCHLISTEDIT_UNKNOWN_KEY)
  {
    db_status = DB_OK;
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_IP_COLUMN_ITEM_COUNT)
      || PQgetisnull(res, 0, WATCHLISTEDIT_IP_COLUMN_PACKAGE_ITEM_COUNT)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_IP_COLUMN_ITEM_COUNT, 0, &result_out->m_itemCountForCurrentApiKey)
      || !dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_IP_COLUMN_PACKAGE_ITEM_COUNT, 0, &result_out->m_packageItemCountForCurrentApiKey))
  {
    goto done;
  }
  if (PQgetisnull(res, 0, WATCHLISTEDIT_IP_COLUMN_ENDPOINT_NAME))
  {
    db_status = DB_OK;
    goto done;
  }

  if (!dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_IP_COLUMN_ENDPOINT_NAME, endpoint, WATCHLIST_ENDPOINT_MAX_LEN)
      || !static_WATCHLISTEDITIsItemEndpoint(endpoint, answered.m_itemKind)
      || PQgetisnull(res, 0, WATCHLISTEDIT_IP_COLUMN_IP_ADDRESS)
      || !dbhelper_fetchColStr(res, 0, WATCHLISTEDIT_IP_COLUMN_IP_ADDRESS, answered.m_ipLookup.ma_ipAddress, INET6_ADDRSTRLEN - 1))
  {
    goto done;
  }
  if (static_WATCHLISTEDITTryStoreItem(result_out, &answered))
    db_status = DB_OK;

done:
  PQclear(res);
  return db_status;
}

static bool static_WATCHLISTEDITTryReadPackageListCounts(PGresult* res, WATCHLISTEDITPackageListResult_t* result_out)
{
  return PQntuples(res) == 1
      && !PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_ADDED_COUNT)
      && !PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_REMOVED_COUNT)
      && !PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_UNCHANGED_COUNT)
      && !PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_PACKAGE_ITEM_COUNT)
      && dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_ADDED_COUNT, 0, &result_out->m_addedCount)
      && dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_REMOVED_COUNT, 0, &result_out->m_removedCount)
      && dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_UNCHANGED_COUNT, 0, &result_out->m_unchangedCount)
      && dbhelper_fetchColInt(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_PACKAGE_ITEM_COUNT, 0, &result_out->m_packageItemCountForCurrentApiKey);
}

static bool static_WATCHLISTEDITTryReadPackageRepeats(PGresult* res, WATCHLISTEDITPackageListResult_t* result_out)
{
  assert(result_out->mp_repeatedPackages == NULL);

  int row_count = PQntuples(res);
  if (PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_PACKAGE_INDEX))
    return row_count == 1 && PQgetisnull(res, 0, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_EARLIER_PACKAGE_INDEX);

  WATCHLISTEDITPackageRepeat_t* repeats = calloc((size_t)row_count, sizeof(WATCHLISTEDITPackageRepeat_t));
  if (!repeats)
    return false;
  for (int row_index = 0; row_index < row_count; row_index++)
  {
    if (PQgetisnull(res, row_index, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_PACKAGE_INDEX)
        || PQgetisnull(res, row_index, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_EARLIER_PACKAGE_INDEX)
        || !dbhelper_fetchColInt(res, row_index, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_PACKAGE_INDEX, 0, &repeats[row_index].m_currentIndex)
        || !dbhelper_fetchColInt(res, row_index, WATCHLISTEDIT_PACKAGE_LIST_COLUMN_EARLIER_PACKAGE_INDEX, 0, &repeats[row_index].m_earlierIndex))
    {
      free(repeats);
      return false;
    }
  }
  result_out->mp_repeatedPackages = repeats;
  result_out->m_repeatedCount     = row_count;
  return true;
}

static bool static_WATCHLISTEDITFillItem(PGresult* res, int row_index, int column_shift, WatchlistItem_t* item)
{
  assert(res  != NULL);
  assert(item != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));
  assert(column_shift == 0 || column_shift == DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT);

  memset(item, 0, sizeof(*item));
  char endpoint[WATCHLIST_ENDPOINT_MAX_LEN + 1];
  if (PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_ENDPOINT_NAME + column_shift)
      || !dbhelper_fetchColStr(res, row_index, WATCHLISTEDIT_COLUMN_ENDPOINT_NAME + column_shift, endpoint, WATCHLIST_ENDPOINT_MAX_LEN)
      || !watchlist_findItemKind(endpoint, &item->m_itemKind))
  {
    return false;
  }

  switch (item->m_itemKind)
  {
    case WATCHLIST_ITEM_CVE_LOOKUP:
      return static_WATCHLISTEDITFillCveId(res, row_index, column_shift, item->m_cveLookup.ma_cveId);
    case WATCHLIST_ITEM_KEV_LOOKUP:
      return static_WATCHLISTEDITFillCveId(res, row_index, column_shift, item->m_kevLookup.ma_cveId);
    case WATCHLIST_ITEM_CVE_EXPLOIT:
      return static_WATCHLISTEDITFillCveId(res, row_index, column_shift, item->m_cveExploit.ma_cveId);
    case WATCHLIST_ITEM_PRODUCT_EXPOSURE:
      return static_WATCHLISTEDITFillProductExposure(res, row_index, column_shift, &item->m_productExposure);
    case WATCHLIST_ITEM_CVE_SEARCH:
      return static_WATCHLISTEDITFillCveSearch(res, row_index, column_shift, &item->m_cveSearch);
    case WATCHLIST_ITEM_DNS_LOOKUP:
      return static_WATCHLISTEDITFillDomainName(res, row_index, column_shift, item->m_dnsLookup.ma_domainName);
    case WATCHLIST_ITEM_SSL_CHECK:
      return static_WATCHLISTEDITFillDomainName(res, row_index, column_shift, item->m_sslCheck.ma_domainName);
    case WATCHLIST_ITEM_WHOIS_LOOKUP:
      return static_WATCHLISTEDITFillDomainName(res, row_index, column_shift, item->m_whoisLookup.ma_domainName);
    case WATCHLIST_ITEM_HEADERS_CHECK:
      return static_WATCHLISTEDITFillDomainName(res, row_index, column_shift, item->m_headersCheck.ma_domainName);
    case WATCHLIST_ITEM_CERT_SEARCH:
      return static_WATCHLISTEDITFillDomainName(res, row_index, column_shift, item->m_certSearch.ma_domainName);
    case WATCHLIST_ITEM_PACKAGE_CHECK:
      return static_WATCHLISTEDITFillPackageCheck(res, row_index, column_shift, &item->m_packageCheck);
    case WATCHLIST_ITEM_IP_LOOKUP:
      return static_WATCHLISTEDITFillIpAddress(res, row_index, column_shift, item->m_ipLookup.ma_ipAddress);
  }
  return false;
}

static bool static_WATCHLISTEDITFillCveId(PGresult* res, int row_index, int column_shift, char* cve_id)
{
  return !PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_CVE_ID + column_shift)
      && dbhelper_fetchColStr(res, row_index, WATCHLISTEDIT_COLUMN_CVE_ID + column_shift, cve_id, CVELOOKUP_ID_MAX_LEN);
}

static bool static_WATCHLISTEDITFillDomainName(PGresult* res, int row_index, int column_shift, char* domain_name)
{
  return !PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_DOMAIN_NAME + column_shift)
      && dbhelper_fetchColStr(res, row_index, WATCHLISTEDIT_COLUMN_DOMAIN_NAME + column_shift, domain_name, VALIDATE_DOMAIN_NAME_MAX_LEN);
}

static bool static_WATCHLISTEDITFillPackageCheck(PGresult* res, int row_index, int column_shift, WATCHLISTPACKAGECHECKItem_t* package)
{
  return !PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_ECOSYSTEM + column_shift)
      && dbhelper_fetchColStr(res, row_index, WATCHLISTEDIT_COLUMN_ECOSYSTEM + column_shift, package->ma_ecosystem, PACKAGECHECK_ECOSYSTEM_MAX_LEN)
      && !PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_PACKAGE_NAME + column_shift)
      && dbhelper_fetchColStr(res, row_index, WATCHLISTEDIT_COLUMN_PACKAGE_NAME + column_shift, package->ma_name, PACKAGECHECK_NAME_MAX_LEN)
      && static_tryReadTextOrEmpty(res, row_index, WATCHLISTEDIT_COLUMN_VERSION + column_shift, package->ma_version, PACKAGECHECK_VERSION_MAX_LEN);
}

static bool static_WATCHLISTEDITFillIpAddress(PGresult* res, int row_index, int column_shift, char* ip_address)
{
  return !PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_IP_ADDRESS + column_shift)
      && dbhelper_fetchColStr(res, row_index, WATCHLISTEDIT_COLUMN_IP_ADDRESS + column_shift, ip_address, INET6_ADDRSTRLEN - 1);
}

static bool static_WATCHLISTEDITFillProductExposure(PGresult* res, int row_index, int column_shift, WATCHLISTPRODUCTEXPOSUREItem_t* product)
{
  if (PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_VENDOR + column_shift)
      || PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_PRODUCT + column_shift)
      || PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_PRODUCT_HAS_CVES + column_shift))
  {
    return false;
  }

  return dbhelper_fetchColStr(res, row_index, WATCHLISTEDIT_COLUMN_VENDOR + column_shift,  product->ma_vendor,  CVESEARCH_VENDOR_LEN)
      && dbhelper_fetchColStr(res, row_index, WATCHLISTEDIT_COLUMN_PRODUCT + column_shift, product->ma_product, CVESEARCH_PRODUCT_LEN)
      && dbhelper_fetchColBool(res, row_index, WATCHLISTEDIT_COLUMN_PRODUCT_HAS_CVES + column_shift, &product->m_hasCves)
      && static_tryReadTextOrEmpty(res, row_index, WATCHLISTEDIT_COLUMN_VERSION + column_shift, product->ma_version, PACKAGECHECK_VERSION_MAX_LEN);
}

static bool static_WATCHLISTEDITFillCveSearch(PGresult* res, int row_index, int column_shift, WATCHLISTCVESEARCHItem_t* filter)
{
  bool in_kev = false;
  if (!static_tryReadTextOrEmpty(res, row_index, WATCHLISTEDIT_COLUMN_VENDOR + column_shift,   filter->ma_vendor,   CVESEARCH_VENDOR_LEN)
      || !static_tryReadTextOrEmpty(res, row_index, WATCHLISTEDIT_COLUMN_PRODUCT + column_shift,  filter->ma_product,  CVESEARCH_PRODUCT_LEN)
      || !static_tryReadTextOrEmpty(res, row_index, WATCHLISTEDIT_COLUMN_SEVERITY + column_shift, filter->ma_severity, CVELOOKUP_SEVERITY_LEN)
      || !static_tryReadTextOrEmpty(res, row_index, WATCHLISTEDIT_COLUMN_CWE_ID + column_shift,   filter->ma_cweId,    CVELOOKUP_CWE_ID_LEN)
      || !static_tryReadNumberOrUnset(res, row_index, WATCHLISTEDIT_COLUMN_MIN_CVSS + column_shift, &filter->m_minCvss)
      || !static_tryReadNumberOrUnset(res, row_index, WATCHLISTEDIT_COLUMN_MIN_EPSS + column_shift, &filter->m_minEpss))
  {
    return false;
  }

  if (PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_IN_KEV + column_shift))
    filter->m_kevFilter = CVE_KEV_FILTER_ANY;
  else if (!dbhelper_fetchColBool(res, row_index, WATCHLISTEDIT_COLUMN_IN_KEV + column_shift, &in_kev))
    return false;
  else
    filter->m_kevFilter = in_kev ? CVE_KEV_FILTER_ONLY_IN_KEV : CVE_KEV_FILTER_NOT_IN_KEV;

  if (!PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_KNOWN_RANSOMWARE + column_shift)
      && !dbhelper_fetchColBool(res, row_index, WATCHLISTEDIT_COLUMN_KNOWN_RANSOMWARE + column_shift, &filter->m_knownRansomware))
    return false;

  if (!PQgetisnull(res, row_index, WATCHLISTEDIT_COLUMN_HAS_NUCLEI_TEMPLATE + column_shift)
      && !dbhelper_fetchColBool(res, row_index, WATCHLISTEDIT_COLUMN_HAS_NUCLEI_TEMPLATE + column_shift, &filter->m_hasNucleiTemplate))
    return false;

  return true;
}

static int static_compareIdText(const char* left, const char* right)
{
  assert(left  != NULL);
  assert(right != NULL);

  size_t left_len  = strlen(left);
  size_t right_len = strlen(right);
  if (left_len != right_len)
    return left_len < right_len ? -1 : 1;
  return strcmp(left, right);
}

static bool static_WATCHLISTEVENTSReadRowFlags(PGresult* res, int row_index, DbWatchlistEventsRowFlags_t* flags)
{
  assert(res   != NULL);
  assert(flags != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  memset(flags, 0, sizeof(*flags));
  if (PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_EVENT_RANK)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_IS_FIRST_ROW_OF_EVENT)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_CVE)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_DOMAIN)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_ADVISORY))
  {
    return false;
  }
  if (!dbhelper_fetchColInt(res, row_index, WATCHLISTEVENTS_COLUMN_EVENT_RANK, 0, &flags->m_eventRank)
      || !dbhelper_fetchColBool(res, row_index, WATCHLISTEVENTS_COLUMN_IS_FIRST_ROW_OF_EVENT,      &flags->m_isFirstRowOfEvent)
      || !dbhelper_fetchColBool(res, row_index, WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_CVE,      &flags->m_isFirstEventOfCve)
      || !dbhelper_fetchColBool(res, row_index, WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_DOMAIN,   &flags->m_isFirstEventOfDomain)
      || !dbhelper_fetchColBool(res, row_index, WATCHLISTEVENTS_COLUMN_IS_FIRST_EVENT_OF_ADVISORY, &flags->m_isFirstEventOfAdvisory))
  {
    return false;
  }
  return flags->m_eventRank >= 1 && flags->m_eventRank <= PQntuples(res);
}

static bool static_WATCHLISTEVENTSCountEntries(PGresult* res, DbWatchlistEventsRowFlags_t* row_flags, DbWatchlistEventsEntryCounts_t* counts)
{
  assert(res       != NULL);
  assert(row_flags != NULL);
  assert(counts    != NULL);

  memset(counts, 0, sizeof(*counts));
  counts->m_rowCount = PQntuples(res);
  for (int row_index = 0; row_index < counts->m_rowCount; row_index++)
  {
    DbWatchlistEventsRowFlags_t* flags = &row_flags[row_index];
    if (!static_WATCHLISTEVENTSReadRowFlags(res, row_index, flags))
      return false;

    if (flags->m_eventRank > counts->m_eventCount)
      counts->m_eventCount = flags->m_eventRank;

    counts->m_cveFactCount    += flags->m_isFirstEventOfCve ? 1 : 0;
    counts->m_domainFactCount += flags->m_isFirstEventOfDomain ? 1 : 0;
    counts->m_advisoryCount   += flags->m_isFirstEventOfAdvisory ? 1 : 0;
  }
  counts->m_cveFactCapacity = counts->m_cveFactCount + counts->m_advisoryCount * WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT;
  return true;
}

static bool static_WATCHLISTEVENTSAllocateArrays(const DbWatchlistEventsEntryCounts_t* counts, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state)
{
  assert(counts != NULL);
  assert(result != NULL);
  assert(state  != NULL);

  result->mp_events                 = calloc((size_t)counts->m_eventCount, sizeof(WATCHLISTEVENTSEvent_t));
  result->m_eventCount              = counts->m_eventCount;
  result->mp_answerItems            = calloc((size_t)counts->m_rowCount, sizeof(WATCHLISTEVENTSAnswerItem_t));
  result->mp_pairEventIndexes       = calloc((size_t)counts->m_rowCount, sizeof(int));
  result->mp_pairIsVersionAffected  = calloc((size_t)counts->m_rowCount, sizeof(bool));
  result->m_pairCount               = counts->m_rowCount;
  if (counts->m_cveFactCapacity > 0)
    result->mp_cveFacts = calloc((size_t)counts->m_cveFactCapacity, sizeof(WATCHLISTEVENTSCveFacts_t));
  if (counts->m_domainFactCount > 0)
    result->mp_domainFacts = calloc((size_t)counts->m_domainFactCount, sizeof(WATCHLISTEVENTSDomainFacts_t));
  result->m_domainFactCount = counts->m_domainFactCount;
  if (counts->m_advisoryCount > 0)
    result->mp_advisories = calloc((size_t)counts->m_advisoryCount, sizeof(WATCHLISTPACKAGECHECKAdvisory_t));
  result->m_advisoryCount = counts->m_advisoryCount;
  state->mp_isEventFilled = calloc((size_t)counts->m_eventCount, sizeof(bool));

  return result->mp_events != NULL && result->mp_answerItems != NULL && result->mp_pairEventIndexes != NULL
      && result->mp_pairIsVersionAffected != NULL && state->mp_isEventFilled != NULL
      && (counts->m_cveFactCapacity == 0 || result->mp_cveFacts != NULL)
      && (counts->m_domainFactCount == 0 || result->mp_domainFacts != NULL)
      && (counts->m_advisoryCount == 0 || result->mp_advisories != NULL);
}

static bool static_WATCHLISTEVENTSReadAttribution(PGresult* res, WATCHLISTEVENTSResult_t* result)
{
  assert(res    != NULL);
  assert(result != NULL);

  return !PQgetisnull(res, 0, WATCHLISTEVENTS_COLUMN_ATTRIBUTION)
      && dbhelper_isColWithinLength(res, 0, WATCHLISTEVENTS_COLUMN_ATTRIBUTION, WATCHLIST_PACKAGE_CHECK_ATTRIBUTION_JSON_MAX_LEN)
      && dbhelper_fetchColStrdup(res, 0, WATCHLISTEVENTS_COLUMN_ATTRIBUTION, &result->mp_attribution);
}

static bool static_WATCHLISTEVENTSOpenItemOnNewId(PGresult* res, int row_index, const char* item_id, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state)
{
  assert(res     != NULL);
  assert(item_id != NULL);
  assert(result  != NULL);
  assert(state   != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  int order = (row_index == 0) ? 1 : static_compareIdText(item_id, state->ma_lastItemId);
  if (order < 0)
    return false;
  if (order == 0)
    return true;

  WATCHLISTEVENTSAnswerItem_t* opened = &result->mp_answerItems[result->m_answerItemCount++];
  opened->m_firstPairIndex = row_index;
  if (!static_WATCHLISTEDITFillItem(res, row_index, DB_WATCHLISTEVENTS_ITEM_COLUMN_SHIFT, &opened->m_item))
    return false;

  assert(strlen(item_id) <= WATCHLIST_CURSOR_MAX_LEN);
  snprintf(state->ma_lastItemId, sizeof(state->ma_lastItemId), "%s", item_id);
  return true;
}

static bool static_WATCHLISTEVENTSAddCveFacts(PGresult* res, int row_index, WATCHLISTEVENTSResult_t* result)
{
  assert(res    != NULL);
  assert(result != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  WATCHLISTEVENTSCveFacts_t* facts = &result->mp_cveFacts[result->m_cveFactCount];
  if (!static_WATCHLISTEVENTSFillCveFacts(res, row_index, facts)
      || static_WATCHLISTEVENTSHasCveFacts(result, facts->ma_cveId))
  {
    return false;
  }
  result->m_cveFactCount++;
  return true;
}

static bool static_WATCHLISTEVENTSAddDomainFacts(PGresult* res, int row_index, const WatchlistItem_t* item, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state)
{
  assert(res    != NULL);
  assert(item   != NULL);
  assert(result != NULL);
  assert(state  != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  WATCHLISTEVENTSDomainFacts_t* facts = &result->mp_domainFacts[state->m_filledDomainCount];
  if (!static_WATCHLISTEVENTSFillDomainFacts(res, row_index, item, facts))
    return false;
  for (int k = 0; k < state->m_filledDomainCount; k++)
  {
    if (strcmp(result->mp_domainFacts[k].ma_domainName, facts->ma_domainName) == 0)
      return false;
  }
  state->m_filledDomainCount++;
  return true;
}

static bool static_WATCHLISTEVENTSIsAdvisoryAdded(const WATCHLISTEVENTSResult_t* result, int added_count, const char* advisory_id)
{
  assert(result      != NULL);
  assert(advisory_id != NULL);

  for (int k = 0; k < added_count; k++)
  {
    if (strcmp(result->mp_advisories[k].ma_advisoryId, advisory_id) == 0)
      return true;
  }
  return false;
}

static bool static_WATCHLISTEVENTSAddAdvisory(PGresult* res, int row_index, const DbWatchlistEventsRowFlags_t* flags, const WATCHLISTEVENTSEvent_t* event, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state)
{
  assert(res    != NULL);
  assert(flags  != NULL);
  assert(event  != NULL);
  assert(result != NULL);
  assert(state  != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  if (!flags->m_isFirstRowOfEvent
      || event->m_eventKind != WATCHLIST_EVENT_PACKAGE_CHECK
      || static_WATCHLISTEVENTSIsAdvisoryAdded(result, state->m_filledAdvisoryCount, event->m_packageCheckChange.ma_advisoryId))
  {
    return false;
  }
  WATCHLISTPACKAGECHECKAdvisory_t* advisory = &result->mp_advisories[state->m_filledAdvisoryCount];
  state->m_filledAdvisoryCount++;
  return static_WATCHLISTEVENTSFillAdvisory(res, row_index, event, advisory)
      && static_WATCHLISTEVENTSAppendAliasFacts(res, row_index, result);
}

static bool static_WATCHLISTEVENTSReadPairRow(PGresult* res, int row_index, WATCHLISTEVENTSResult_t* result, DbWatchlistEventsReadState_t* state)
{
  assert(res    != NULL);
  assert(result != NULL);
  assert(state  != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  const DbWatchlistEventsRowFlags_t* flags = &state->mp_rowFlags[row_index];
  char item_id[WATCHLIST_CURSOR_MAX_LEN + 1];
  if (PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_ITEM_ID)
      || !dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_ITEM_ID, item_id, WATCHLIST_CURSOR_MAX_LEN)
      || !static_isIdText(item_id)
      || !static_WATCHLISTEVENTSOpenItemOnNewId(res, row_index, item_id, result, state))
  {
    return false;
  }
  assert(result->m_answerItemCount > 0);
  WATCHLISTEVENTSAnswerItem_t* answer_item = &result->mp_answerItems[result->m_answerItemCount - 1];
  answer_item->m_pairCount++;

  int event_index = flags->m_eventRank - 1;
  result->mp_pairEventIndexes[row_index] = event_index;
  bool is_version_affected = false;
  if (!PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_AFFECTS_VERSION)
      && (!dbhelper_fetchColBool(res, row_index, WATCHLISTEVENTS_COLUMN_AFFECTS_VERSION, &is_version_affected) || !is_version_affected))
  {
    return false;
  }
  result->mp_pairIsVersionAffected[row_index] = is_version_affected;

  WATCHLISTEVENTSEvent_t* event = &result->mp_events[event_index];
  if (flags->m_isFirstRowOfEvent)
  {
    if (state->mp_isEventFilled[event_index])
      return false;
    state->mp_isEventFilled[event_index] = true;
    if (!static_WATCHLISTEVENTSFillEvent(res, row_index, &answer_item->m_item, event))
      return false;
  }
  if (flags->m_isFirstEventOfCve && !static_WATCHLISTEVENTSAddCveFacts(res, row_index, result))
    return false;
  if (flags->m_isFirstEventOfDomain && !static_WATCHLISTEVENTSAddDomainFacts(res, row_index, &answer_item->m_item, result, state))
    return false;
  if (flags->m_isFirstEventOfAdvisory && !static_WATCHLISTEVENTSAddAdvisory(res, row_index, flags, event, result, state))
    return false;
  return true;
}

static bool static_WATCHLISTEVENTSIsEveryEventFilled(const WATCHLISTEVENTSResult_t* result, const DbWatchlistEventsReadState_t* state)
{
  assert(result != NULL);
  assert(state  != NULL);

  for (int e = 0; e < result->m_eventCount; e++)
  {
    const WATCHLISTEVENTSEvent_t* event = &result->mp_events[e];
    if (!state->mp_isEventFilled[e])
      return false;
    if (event->m_eventKind == WATCHLIST_EVENT_PACKAGE_CHECK
        && !static_WATCHLISTEVENTSIsAdvisoryAdded(result, state->m_filledAdvisoryCount, event->m_packageCheckChange.ma_advisoryId))
    {
      return false;
    }
  }
  return true;
}

static bool static_WATCHLISTEVENTSReadRows(PGresult* res, WATCHLISTEVENTSResult_t* result)
{
  assert(res    != NULL);
  assert(result != NULL);

  int row_count = PQntuples(res);
  if (row_count < 1)
    return false;

  DbWatchlistEventsReadState_t   state = { 0 };
  DbWatchlistEventsEntryCounts_t counts;
  state.mp_rowFlags = calloc((size_t)row_count, sizeof(DbWatchlistEventsRowFlags_t));
  bool is_read = state.mp_rowFlags != NULL
              && static_WATCHLISTEVENTSCountEntries(res, state.mp_rowFlags, &counts)
              && static_WATCHLISTEVENTSAllocateArrays(&counts, result, &state)
              && static_WATCHLISTEVENTSReadAttribution(res, result);
  for (int row_index = 0; is_read && row_index < row_count; row_index++)
    is_read = static_WATCHLISTEVENTSReadPairRow(res, row_index, result, &state);
  is_read = is_read && static_WATCHLISTEVENTSIsEveryEventFilled(result, &state);

  free(state.mp_isEventFilled);
  free(state.mp_rowFlags);
  return is_read;
}

static bool static_WATCHLISTEVENTSFillEvent(PGresult* res, int row_index, const WatchlistItem_t* item, WATCHLISTEVENTSEvent_t* event)
{
  assert(res   != NULL);
  assert(item  != NULL);
  assert(event != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  memset(event, 0, sizeof(*event));
  if (PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_EVENT_TYPE)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_CHANGED_AT)
      || !dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_EVENT_TYPE, event->ma_eventType, WATCHLIST_EVENT_TYPE_MAX_LEN)
      || !dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_CHANGED_AT, event->ma_changedAt, CVELOOKUP_PUBLISHED_LEN))
  {
    return false;
  }

  if (!PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_ID))
    event->m_eventKind = WATCHLIST_EVENT_PACKAGE_CHECK;
  else if (item->m_itemKind == WATCHLIST_ITEM_IP_LOOKUP)
    event->m_eventKind = WATCHLIST_EVENT_IP_LOOKUP;
  else if (!PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_EOL_PRODUCT))
    event->m_eventKind = WATCHLIST_EVENT_PRODUCT_EXPOSURE;
  else if (!watchlist_findDomainEventKind(item->m_itemKind, &event->m_eventKind))
    event->m_eventKind = WATCHLIST_EVENT_CVE;
  switch (event->m_eventKind)
  {
    case WATCHLIST_EVENT_CVE:
      return static_WATCHLISTEVENTSFillCveChange(res, row_index, &event->m_cveChange);
    case WATCHLIST_EVENT_DNS_LOOKUP:
      return static_WATCHLISTEVENTSFillDnsLookupChange(res, row_index, &event->m_dnsLookupChange);
    case WATCHLIST_EVENT_SSL_CHECK:
      return static_WATCHLISTEVENTSFillSslCheckChange(res, row_index, &event->m_sslCheckChange);
    case WATCHLIST_EVENT_WHOIS_LOOKUP:
      return static_WATCHLISTEVENTSFillWhoisLookupChange(res, row_index, &event->m_whoisLookupChange);
    case WATCHLIST_EVENT_HEADERS_CHECK:
      return static_WATCHLISTEVENTSFillHeadersCheckChange(res, row_index, &event->m_headersCheckChange);
    case WATCHLIST_EVENT_CERT_SEARCH:
      return static_WATCHLISTEVENTSFillCertSearchChange(res, row_index, &event->m_certSearchChange);
    case WATCHLIST_EVENT_PACKAGE_CHECK:
      return static_WATCHLISTEVENTSFillPackageChange(res, row_index, &event->m_packageCheckChange);
    case WATCHLIST_EVENT_IP_LOOKUP:
      return static_WATCHLISTEVENTSFillIpLookupChange(res, row_index, &event->m_ipLookupChange);
    case WATCHLIST_EVENT_PRODUCT_EXPOSURE:
      return static_WATCHLISTEVENTSFillProductExposureChange(res, row_index, event->ma_eventType, &event->m_productExposureChange);
  }
  return false;
}

static bool static_WATCHLISTEVENTSFillCveChange(PGresult* res, int row_index, WATCHLISTEVENTSCveChange_t* change)
{
  if (PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_CVE_ID)
      || !dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_CVE_ID, change->ma_cveId, CVELOOKUP_ID_MAX_LEN))
  {
    return false;
  }

  change->m_hasPreviousValue = !PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_VALUE);
  if (change->m_hasPreviousValue && !dbhelper_fetchColDouble(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_VALUE, 0.0, &change->m_previousValue))
    return false;

  change->m_hasCurrentValue = !PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_VALUE);
  if (change->m_hasCurrentValue && !dbhelper_fetchColDouble(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_VALUE, 0.0, &change->m_currentValue))
    return false;

  bool has_vendor  = !PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_VENDOR);
  bool has_product = !PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_PRODUCT);
  if (has_vendor != has_product)
    return false;
  change->m_hasProductPair = has_vendor;
  if (change->m_hasProductPair
      && (!dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_VENDOR,  change->ma_vendor,  CVESEARCH_VENDOR_LEN)
    || !dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_PRODUCT, change->ma_product, CVESEARCH_PRODUCT_LEN)))
    return false;

  return true;
}

static bool static_WATCHLISTEVENTSIsDomainValueWithinLength(PGresult* res, int row_index)
{
  return dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_DOMAIN_VALUE, WATCHLIST_DOMAIN_VALUE_MAX_LEN)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_DOMAIN_VALUE,  WATCHLIST_DOMAIN_VALUE_MAX_LEN);
}

static bool static_WATCHLISTEVENTSFillDnsLookupChange(PGresult* res, int row_index, WATCHLISTDNSLOOKUPChange_t* change)
{
  if (!static_tryReadTextOrEmpty(res, row_index, WATCHLISTEVENTS_COLUMN_DEGRADED_EMAIL_CHECK_ID, change->ma_degradedEmailCheckId, EMAILCHECK_KIND_ID_MAX_LEN))
    return false;

  return static_WATCHLISTEVENTSIsDomainValueWithinLength(res, row_index)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_DOMAIN_VALUE, &change->mp_previousValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_DOMAIN_VALUE, &change->mp_currentValue);
}

static bool static_WATCHLISTEVENTSFillSslCheckChange(PGresult* res, int row_index, WATCHLISTSSLCHECKChange_t* change)
{
  return static_WATCHLISTEVENTSIsDomainValueWithinLength(res, row_index)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_DOMAIN_VALUE, &change->mp_previousValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_DOMAIN_VALUE, &change->mp_currentValue);
}

static bool static_WATCHLISTEVENTSFillWhoisLookupChange(PGresult* res, int row_index, WATCHLISTWHOISLOOKUPChange_t* change)
{
  return static_WATCHLISTEVENTSIsDomainValueWithinLength(res, row_index)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_DOMAIN_VALUE, &change->mp_previousValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_DOMAIN_VALUE, &change->mp_currentValue);
}

static bool static_WATCHLISTEVENTSFillHeadersCheckChange(PGresult* res, int row_index, WATCHLISTHEADERSCHECKChange_t* change)
{
  return static_WATCHLISTEVENTSIsDomainValueWithinLength(res, row_index)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_DOMAIN_VALUE, &change->mp_previousValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_DOMAIN_VALUE, &change->mp_currentValue);
}

static bool static_WATCHLISTEVENTSFillCertSearchChange(PGresult* res, int row_index, WATCHLISTCERTSEARCHChange_t* change)
{
  return static_WATCHLISTEVENTSIsDomainValueWithinLength(res, row_index)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_DOMAIN_VALUE, &change->mp_previousValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_DOMAIN_VALUE, &change->mp_currentValue);
}

static bool static_WATCHLISTEVENTSFillIpLookupChange(PGresult* res, int row_index, WATCHLISTIPLOOKUPChange_t* change)
{
  return static_tryReadTextOrEmpty(res, row_index, WATCHLISTEVENTS_COLUMN_DROP_LIST_TIME, change->ma_dropListTime, CVELOOKUP_PUBLISHED_LEN)
      && static_tryReadTextOrEmpty(res, row_index, WATCHLISTEVENTS_COLUMN_DROP_COPYRIGHT, change->ma_dropCopyright, WATCHLIST_IP_DROP_COPYRIGHT_MAX_LEN)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_IP_VALUE, WATCHLIST_IP_VALUE_MAX_LEN)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_IP_VALUE,  WATCHLIST_IP_VALUE_MAX_LEN)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_IP_VALUE, &change->mp_previousValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_CURRENT_IP_VALUE, &change->mp_currentValue);
}

static void static_WATCHLISTEVENTSFreeEventTexts(WATCHLISTEVENTSEvent_t* event)
{
  char** previous = NULL;
  char** current  = NULL;
  switch (event->m_eventKind)
  {
    case WATCHLIST_EVENT_DNS_LOOKUP:
      previous = &event->m_dnsLookupChange.mp_previousValue;
      current  = &event->m_dnsLookupChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_SSL_CHECK:
      previous = &event->m_sslCheckChange.mp_previousValue;
      current  = &event->m_sslCheckChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_WHOIS_LOOKUP:
      previous = &event->m_whoisLookupChange.mp_previousValue;
      current  = &event->m_whoisLookupChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_HEADERS_CHECK:
      previous = &event->m_headersCheckChange.mp_previousValue;
      current  = &event->m_headersCheckChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_CERT_SEARCH:
      previous = &event->m_certSearchChange.mp_previousValue;
      current  = &event->m_certSearchChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_IP_LOOKUP:
      previous = &event->m_ipLookupChange.mp_previousValue;
      current  = &event->m_ipLookupChange.mp_currentValue;
      break;
    case WATCHLIST_EVENT_CVE:
    case WATCHLIST_EVENT_PACKAGE_CHECK:
    case WATCHLIST_EVENT_PRODUCT_EXPOSURE:
      break;
  }
  if (previous == NULL || current == NULL)
    return;
  free(*previous);
  free(*current);
  *previous = NULL;
  *current  = NULL;
}

static bool static_WATCHLISTEVENTSFillPackageChange(PGresult* res, int row_index, WATCHLISTPACKAGECHECKChange_t* change)
{
  return dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_ID, change->ma_advisoryId, WATCHLIST_PACKAGE_CHECK_ADVISORY_ID_MAX_LEN)
      && static_tryReadTextOrEmpty(res, row_index, WATCHLISTEVENTS_COLUMN_FIXED_VERSION, change->ma_fixedVersion, PACKAGECHECK_VERSION_MAX_LEN);
}

static bool static_WATCHLISTEVENTSFillProductExposureChange(PGresult* res, int row_index, const char* event_type, WATCHLISTPRODUCTEXPOSUREChange_t* change)
{
  assert(event_type != NULL);

  const bool is_reached      = strcmp(event_type, "eol_reached") == 0;
  const bool is_date_changed = strcmp(event_type, "eol_date_changed") == 0;
  if (!is_reached && !is_date_changed && strcmp(event_type, "eol_approaching") != 0)
    return false;
  if (PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_EOL_CYCLE)
      || (!is_reached && PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_EOL_DATE))
      || is_date_changed == PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_EOL_DATE))
  {
    return false;
  }
  return dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_EOL_PRODUCT, change->ma_eolProduct, PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN)
      && dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_EOL_CYCLE, change->ma_cycle, PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN)
      && static_tryReadTextOrEmpty(res, row_index, WATCHLISTEVENTS_COLUMN_EOL_DATE, change->ma_eolDate, PRODUCTEXPOSURE_EOL_DATE_LEN)
      && static_tryReadTextOrEmpty(res, row_index, WATCHLISTEVENTS_COLUMN_PREVIOUS_EOL_DATE, change->ma_previousEolDate, PRODUCTEXPOSURE_EOL_DATE_LEN);
}

static bool static_WATCHLISTEVENTSFillAdvisory(PGresult* res, int row_index, const WATCHLISTEVENTSEvent_t* event, WATCHLISTPACKAGECHECKAdvisory_t* advisory)
{
  assert(res      != NULL);
  assert(event    != NULL);
  assert(advisory != NULL);
  assert(event->m_eventKind == WATCHLIST_EVENT_PACKAGE_CHECK);

  memcpy(advisory->ma_advisoryId, event->m_packageCheckChange.ma_advisoryId, sizeof(advisory->ma_advisoryId));
  return static_tryReadTextOrEmpty(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_SOURCE, advisory->ma_source, WATCHLIST_PACKAGE_CHECK_ADVISORY_SOURCE_MAX_LEN)
      && !PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_ALIASES)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_ALIASES, WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIASES_JSON_MAX_LEN)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_ALIASES, &advisory->mp_aliases);
}

static bool static_WATCHLISTEVENTSHasCveFacts(const WATCHLISTEVENTSResult_t* result, const char* cve_id)
{
  assert(result != NULL);
  assert(cve_id != NULL);

  for (int k = 0; k < result->m_cveFactCount; k++)
  {
    if (strcmp(result->mp_cveFacts[k].ma_cveId, cve_id) == 0)
      return true;
  }
  return false;
}

static bool static_WATCHLISTEVENTSReadAliasFact(JsonReadSpan_t object_span, WATCHLISTEVENTSCveFacts_t* facts)
{
  assert(facts != NULL);

  memset(facts, 0, sizeof(*facts));
  JsonReadSpan_t cve_id_span;
  JsonReadSpan_t risk_score_span;
  JsonReadSpan_t risk_label_span;
  JsonReadSpan_t in_kev_span;
  JsonReadSpan_t kev_patch_deadline_span;
  JsonReadSpan_t kev_known_ransomware_span;
  JsonReadSpan_t has_metasploit_span;
  JsonReadSpan_t poc_count_span;
  if (jsonread_objectKey(object_span, "cve_id", &cve_id_span)                             != JSONREAD_OK
      || jsonread_objectKey(object_span, "risk_score", &risk_score_span)                     != JSONREAD_OK
      || jsonread_objectKey(object_span, "risk_label", &risk_label_span)                     != JSONREAD_OK
      || jsonread_objectKey(object_span, "in_kev", &in_kev_span)                             != JSONREAD_OK
      || jsonread_objectKey(object_span, "kev_patch_deadline", &kev_patch_deadline_span)     != JSONREAD_OK
      || jsonread_objectKey(object_span, "kev_known_ransomware", &kev_known_ransomware_span) != JSONREAD_OK
      || jsonread_objectKey(object_span, "has_metasploit", &has_metasploit_span)             != JSONREAD_OK
      || jsonread_objectKey(object_span, "poc_count", &poc_count_span)                       != JSONREAD_OK)
  {
    return false;
  }

  long poc_count_value = 0;
  if (jsonread_spanToStrStatus(cve_id_span, facts->ma_cveId, sizeof(facts->ma_cveId))             != JSONREAD_OK
      || jsonread_spanToDoubleStatus(risk_score_span, &facts->m_riskScore)                           != JSONREAD_OK
      || jsonread_spanToStrStatus(risk_label_span, facts->ma_riskLabel, sizeof(facts->ma_riskLabel)) != JSONREAD_OK
      || jsonread_spanToBoolStatus(in_kev_span, &facts->m_isInKev)                                   != JSONREAD_OK
      || jsonread_spanToBoolStatus(kev_known_ransomware_span, &facts->m_kevKnownRansomware)          != JSONREAD_OK
      || jsonread_spanToBoolStatus(has_metasploit_span, &facts->m_hasMetasploit)                     != JSONREAD_OK
      || jsonread_spanToLongStatus(poc_count_span, &poc_count_value)                                 != JSONREAD_OK
      || poc_count_value < 0 || poc_count_value > INT_MAX)
  {
    return false;
  }
  facts->m_pocCount = (int)poc_count_value;

  facts->m_hasKev = !jsonread_isSpanEqual(kev_patch_deadline_span, "null");
  if (!facts->m_hasKev)
    return true;
  return jsonread_spanToStrStatus(kev_patch_deadline_span, facts->ma_kevPatchDeadline, sizeof(facts->ma_kevPatchDeadline)) == JSONREAD_OK;
}

static bool static_WATCHLISTEVENTSAppendAliasFacts(PGresult* res, int row_index, WATCHLISTEVENTSResult_t* result)
{
  assert(res    != NULL);
  assert(result != NULL);

  if (PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_CVE_FACTS)
      || !dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_CVE_FACTS, WATCHLIST_PACKAGE_CHECK_ADVISORY_CVE_FACTS_JSON_MAX_LEN))
  {
    return false;
  }
  JsonReadSpan_t facts_array_span;
  size_t fact_count = 0;
  if (jsonread_root(PQgetvalue(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_CVE_FACTS), (size_t)PQgetlength(res, row_index, WATCHLISTEVENTS_COLUMN_ADVISORY_CVE_FACTS), &facts_array_span) != JSONREAD_OK
      || jsonread_arrayLen(facts_array_span, &fact_count) != JSONREAD_OK
      || fact_count > WATCHLIST_PACKAGE_CHECK_ADVISORY_ALIAS_MAX_COUNT)
  {
    return false;
  }

  size_t element_offset = 0;
  for (size_t f = 0; f < fact_count; f++)
  {
    JsonReadSpan_t object_span;
    WATCHLISTEVENTSCveFacts_t* facts = &result->mp_cveFacts[result->m_cveFactCount];
    if (jsonread_arrayNextElement(facts_array_span, &element_offset, &object_span) != JSONREAD_OK
        || !static_WATCHLISTEVENTSReadAliasFact(object_span, facts)
        || static_WATCHLISTEVENTSHasCveFacts(result, facts->ma_cveId))
    {
      return false;
    }
    result->m_cveFactCount++;
  }
  return true;
}

static bool static_WATCHLISTEVENTSFillCveFacts(PGresult* res, int row_index, WATCHLISTEVENTSCveFacts_t* facts)
{
  assert(res   != NULL);
  assert(facts != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  memset(facts, 0, sizeof(*facts));
  if (PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_RISK_SCORE)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_RISK_LABEL)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_IN_KEV)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_KEV_KNOWN_RANSOMWARE)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_HAS_METASPLOIT)
      || PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_POC_COUNT))
  {
    return false;
  }
  if (!dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_CVE_ID, facts->ma_cveId, CVELOOKUP_ID_MAX_LEN)
      || !dbhelper_fetchColDouble(res, row_index, WATCHLISTEVENTS_COLUMN_RISK_SCORE, 0.0, &facts->m_riskScore)
      || !dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_RISK_LABEL, facts->ma_riskLabel, CVERISKSCORE_LABEL_LEN)
      || !dbhelper_fetchColBool(res, row_index, WATCHLISTEVENTS_COLUMN_IN_KEV,               &facts->m_isInKev)
      || !dbhelper_fetchColBool(res, row_index, WATCHLISTEVENTS_COLUMN_KEV_KNOWN_RANSOMWARE, &facts->m_kevKnownRansomware)
      || !dbhelper_fetchColBool(res, row_index, WATCHLISTEVENTS_COLUMN_HAS_METASPLOIT,       &facts->m_hasMetasploit)
      || !dbhelper_fetchColInt(res, row_index, WATCHLISTEVENTS_COLUMN_POC_COUNT, 0, &facts->m_pocCount))
  {
    return false;
  }

  facts->m_hasKev = !PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_KEV_PATCH_DEADLINE);
  if (!facts->m_hasKev)
    return true;
  if (!dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_KEV_PATCH_DEADLINE, facts->ma_kevPatchDeadline, CVELOOKUP_PUBLISHED_LEN))
    return false;

  return true;
}

static bool static_WATCHLISTEVENTSFillDomainFacts(PGresult* res, int row_index, const WatchlistItem_t* item, WATCHLISTEVENTSDomainFacts_t* facts)
{
  assert(res   != NULL);
  assert(item  != NULL);
  assert(facts != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  memset(facts, 0, sizeof(*facts));
  const char* domain_name = watchlist_findDomainName(item);
  if (domain_name == NULL)
    return false;
  memcpy(facts->ma_domainName, domain_name, sizeof(facts->ma_domainName));

  if (PQgetisnull(res, row_index, WATCHLISTEVENTS_COLUMN_REGISTERED_DOMAIN)
      || !dbhelper_fetchColStr(res, row_index, WATCHLISTEVENTS_COLUMN_REGISTERED_DOMAIN, facts->ma_registeredDomain, VALIDATE_DOMAIN_NAME_MAX_LEN))
  {
    return false;
  }

  return static_WATCHLISTEVENTSFillDomainDnsFacts(res, row_index, &facts->m_dnsFacts);
}

static bool static_WATCHLISTEVENTSFillDomainDnsFacts(PGresult* res, int row_index, WATCHLISTDNSLOOKUPFacts_t* dns_facts)
{
  return dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_DNS_PRESENCE_VALUE, WATCHLIST_DOMAIN_VALUE_MAX_LEN)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_NS_VALUE, WATCHLIST_DOMAIN_VALUE_MAX_LEN)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_MX_VALUE, WATCHLIST_DOMAIN_VALUE_MAX_LEN)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_IP_ADDRESS_REACHABILITY_VALUE, WATCHLIST_DOMAIN_VALUE_MAX_LEN)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_CNAME_TAKEOVER_VALUE, WATCHLIST_DOMAIN_VALUE_MAX_LEN)
      && dbhelper_isColWithinLength(res, row_index, WATCHLISTEVENTS_COLUMN_EMAIL_AUTH_VALUE, WATCHLIST_DOMAIN_VALUE_MAX_LEN)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_DNS_PRESENCE_VALUE, &dns_facts->mp_dnsPresenceValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_NS_VALUE, &dns_facts->mp_nsValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_MX_VALUE, &dns_facts->mp_mxValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_IP_ADDRESS_REACHABILITY_VALUE, &dns_facts->mp_ipAddressReachabilityValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_CNAME_TAKEOVER_VALUE, &dns_facts->mp_cnameTakeoverValue)
      && dbhelper_fetchColStrdup(res, row_index, WATCHLISTEVENTS_COLUMN_EMAIL_AUTH_VALUE, &dns_facts->mp_emailAuthValue);
}
