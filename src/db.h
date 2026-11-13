#ifndef DB_H
#define DB_H

#include <stdbool.h>
#include <libpq-fe.h>

#include "bulk.h"
#include "cve.h"
#include "watchlist/watchlist.h"
#include "d3fend.h"
#include "lol.h"
#include "ip.h"
#include "emailcheck.h"
#include "tlsprobe.h"
#include "package.h"
#include "watchlist/watchlist_domain.h"
#include "dbapikey.h"
#include "billing.h"
#include "keyvault.h"

#define DB_CONNECT_TIMEOUT_SEC    "5"
#define DB_STATEMENT_TIMEOUT_MS   "15000"

#define DB_REQUIRED_SCHEMA_VERSION 79

#define DB_CVE_CHANGE_PURGE_BATCH_EVENT_COUNT 10000

#define DB_WATCHLIST_PURGE_BATCH_KEY_COUNT 1000

#define DB_DOMAIN_CHANGE_PURGE_BATCH_EVENT_COUNT 10000

#define DB_PACKAGE_ADVISORY_CHANGE_PURGE_BATCH_EVENT_COUNT 10000

#define DB_EOL_CHANGE_PURGE_BATCH_EVENT_COUNT 10000

#define DB_DOMAIN_WATCH_PURGE_BATCH_DOMAIN_COUNT 1000

#define DB_IP_WATCH_WRITE_BATCH_ITEM_COUNT 500

#define DB_IP_CHANGE_PURGE_BATCH_EVENT_COUNT 10000

#define DB_VENDOR_KEY_PURGE_BATCH_KEY_COUNT 1000

#define DB_VENDOR_KEY_LINK_PURGE_BATCH_ROW_COUNT 10000

#define DB_BILLING_EVENT_PURGE_BATCH_EVENT_COUNT 10000

#define DB_VENDOR_KEY_LINK_LIFETIME_SECONDS 900

#define DB_VENDOR_KEY_FINGERPRINT_HEX_LEN 32

#define DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT 4

#define DB_DOMAIN_SCAN_LEASE_SECONDS 240

#define DB_DOMAIN_WATCH_LANE_DNS "dns"

#define DB_DOMAIN_WATCH_LANE_TLS "tls"

#define DB_DOMAIN_WATCH_LANE_RDAP_WHOIS "rdap_whois"

#define DB_DOMAIN_WATCH_LANE_HEADERS "headers"

#define DB_DOMAIN_WATCH_LANE_CT "ct"

typedef enum {
  DB_OK,
  DB_NOT_FOUND,
  DB_ERROR,
} DbStatus_t;

typedef struct {
  const char*                   mp_domain;
  const char*                   mp_claimedUntil;
  const WatchlistDomainValue_t* mp_dnsPresenceValue;
  const WatchlistDomainValue_t* mp_nsValue;
  const WatchlistDomainValue_t* mp_mxValue;
  const WatchlistDomainValue_t* mp_ipAddressReachabilityValue;
  const WatchlistDomainValue_t* mp_cnameTakeoverValue;
  const WatchlistDomainValue_t* mp_emailAuthValue;
  const char*                   mp_emailCheckIds;
  const char*                   mp_hostingIpAddresses;
  int                           m_questionCount;
} DbDnsScanRecord_t;

typedef struct {
  const char*                   mp_domain;
  const char*                   mp_claimedUntil;
  const WatchlistDomainValue_t* mp_certificateExpiryValue;
  const WatchlistDomainValue_t* mp_certificateValidityValue;
  const WatchlistDomainValue_t* mp_certificateListingValue;
  const WatchlistDomainValue_t* mp_tlsProtocolValue;
} DbTlsScanRecord_t;

typedef struct {
  const char*                   mp_domain;
  const char*                   mp_claimedUntil;
  const WatchlistDomainValue_t* mp_registrationExpiryValue;
  const WatchlistDomainValue_t* mp_registrarValue;
  const WatchlistDomainValue_t* mp_transferLockValue;
  const WatchlistDomainValue_t* mp_dnssecDelegationValue;
  unsigned int                  m_retryAfterSeconds;
} DbRdapWhoisScanRecord_t;

typedef struct {
  const char*                   mp_domain;
  const char*                   mp_claimedUntil;
  const WatchlistDomainValue_t* mp_securityHeadersValue;
  unsigned int                  m_retryAfterSeconds;
} DbHeadersScanRecord_t;

typedef struct {
  const char*                   mp_domain;
  const char*                   mp_claimedUntil;
  const WatchlistDomainValue_t* mp_certIssuersValue;
  unsigned int                  m_retryAfterSeconds;
} DbCtScanRecord_t;

typedef enum {
  DB_API_KEY_ACTIVE,
  DB_API_KEY_INACTIVE,
  DB_API_KEY_UNKNOWN,
} DbApiKeyState_t;

typedef struct {
  bool m_isSuperuser;
  bool m_isOwnerMember;
} DbConnectionRoleState_t;

typedef enum {
  DB_BILLING_EVENT_APPLIED,
  DB_BILLING_EVENT_DUPLICATE,
  DB_BILLING_EVENT_EXISTS,
  DB_BILLING_EVENT_STALE,
  DB_BILLING_EVENT_ORDER_REVOKED,
  DB_BILLING_EVENT_UNKNOWN_ORDER,
} DbBillingEventStatus_t;

typedef enum {
  DB_BILLING_CLAIM_CLAIMED,
  DB_BILLING_CLAIM_ALREADY_CLAIMED,
  DB_BILLING_CLAIM_LAPSED,
  DB_BILLING_CLAIM_REVOKED,
  DB_BILLING_CLAIM_UNKNOWN,
} DbBillingClaimStatus_t;

typedef struct {
  int64_t m_apiKeyId;
  char    ma_keyFingerprint[DB_VENDOR_KEY_FINGERPRINT_HEX_LEN + 1];
  char    ma_shodanSealedHex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  char    ma_abuseIpDbSealedHex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
} DbVendorKeys_t;

typedef enum {
  DB_VENDOR_KEY_LINK_INVALID = 0,
  DB_VENDOR_KEY_LINK_EXPIRED,
  DB_VENDOR_KEY_LINK_OPEN,
} DbVendorKeyLinkState_t;

typedef struct {
  DbVendorKeyLinkState_t m_linkState;
  int64_t                m_apiKeyId;
  int64_t                m_linkExpiresAt;
  char                   ma_shodanSealedHex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  char                   ma_abuseIpDbSealedHex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
} DbVendorKeyLink_t;

typedef struct {
  int64_t     m_apiKeyId;
  const char* mp_linkHash;
  const char* mp_keyFingerprint;
  bool        m_isLinkSpent;
  const char* mp_shodanSealedHex;
  bool        m_isShodanDeleted;
  const char* mp_abuseIpDbSealedHex;
  bool        m_isAbuseIpDbDeleted;
} DbVendorKeyChange_t;

typedef enum {
  DB_VENDOR_KEY_APPLY_APPLIED,
  DB_VENDOR_KEY_APPLY_EXPIRED,
  DB_VENDOR_KEY_APPLY_INVALID,
  DB_VENDOR_KEY_APPLY_INACTIVE,
} DbVendorKeyApplyStatus_t;

PGconn*     db_open                                     (const char* conninfo);
void        db_close                                    (PGconn* conn);
DbStatus_t  db_readSchemaVersion                        (PGconn* conn, int* version_out);
DbStatus_t  db_readConnectionRoleState                  (PGconn* conn, DbConnectionRoleState_t* state_out);
DbStatus_t  db_readApiKeyState                          (PGconn* conn, const char* key_hash, DbApiKeyState_t* state_out, DbApiKeyExpiry_t* expiry_out);
DbStatus_t  db_billingLemonSqueezyOrderPaid             (PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out);
DbStatus_t  db_billingLemonSqueezySetExpiry             (PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out);
DbStatus_t  db_billingLemonSqueezyClearExpiry           (PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out);
DbStatus_t  db_billingLemonSqueezyRevoke                (PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out);
DbStatus_t  db_billingLemonSqueezyEventRecord           (PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out);
DbStatus_t  db_billingNowPaymentsOrderPaid              (PGconn* conn, const char* event_ref, const char* event_name, const char* order_id, const char* order_ref, DbBillingEventStatus_t* status_out);
const char* db_billingEventStatusText                   (DbBillingEventStatus_t status);
DbStatus_t  db_billingClaim                             (PGconn* conn, const char* order_id, const char* key_hash, DbBillingClaimStatus_t* status_out);
DbStatus_t  db_readVendorKeys                           (PGconn* conn, const char* key_hash, DbVendorKeys_t* vendor_keys_out);
DbStatus_t  db_openVendorKeyLink                        (PGconn* conn, int64_t api_key_id, const char* link_hash_hex, int64_t* link_expires_at_out);
DbStatus_t  db_readVendorKeyLink                        (PGconn* conn, const char* link_hash_hex, DbVendorKeyLink_t* vendor_key_link_out);
DbStatus_t  db_applyVendorKeys                          (PGconn* conn, const DbVendorKeyChange_t* change, DbVendorKeyApplyStatus_t* apply_status_out);
bool        db_purgeExpiredCveChangeEvents              (PGconn* conn);
bool        db_purgeExpiredWatchlists                   (PGconn* conn);
bool        db_purgeExpiredDomainChangeEvents           (PGconn* conn);
bool        db_purgeExpiredPackageAdvisoryChangeEvents  (PGconn* conn);
bool        db_purgeExpiredEolChangeEvents              (PGconn* conn);
bool        db_purgeUnwatchedDomains                    (PGconn* conn);
bool        db_writeWatchedIpValues                     (PGconn* conn);
bool        db_purgeExpiredIpChangeEvents               (PGconn* conn);
bool        db_purgeExpiredVendorKeys                   (PGconn* conn);
bool        db_purgeExpiredVendorKeyLinks               (PGconn* conn);
bool        db_purgeExpiredBillingEvents                (PGconn* conn);
DbStatus_t  db_claimDomainLaneScans                     (PGconn* conn, const char* lane_name, WatchlistDomainScanClaim_t* claims_out, int* claim_count_out);
DbStatus_t  db_recordDnsScan                            (PGconn* conn, const DbDnsScanRecord_t* scan);
DbStatus_t  db_recordTlsScan                            (PGconn* conn, const DbTlsScanRecord_t* scan);
DbStatus_t  db_recordRdapWhoisScan                      (PGconn* conn, const DbRdapWhoisScanRecord_t* scan);
DbStatus_t  db_recordHeadersScan                        (PGconn* conn, const DbHeadersScanRecord_t* scan);
DbStatus_t  db_recordCtScan                             (PGconn* conn, const DbCtScanRecord_t* scan);

DbStatus_t  db_CVELOOKUP                                (PGconn* conn, const char* cve_id, CVELOOKUPRecord_t* record_out);
void        db_CVELOOKUPRecordFree                      (CVELOOKUPRecord_t* record);
DbStatus_t  db_CVELOOKUPGHSA                            (PGconn* conn, const char* cve_id, CVELOOKUPRecord_t* record);
DbStatus_t  db_CVELOOKUPBULK                            (PGconn* conn, const BulkIdsParams_t* params, CVELOOKUPBULKResult_t* results_out);
void        db_CVELOOKUPBULKResultFree                  (CVELOOKUPBULKResult_t* results);
DbStatus_t  db_CVEPRODUCTS                              (PGconn* conn, const CVEPRODUCTSParams_t* params, CVEPRODUCTSResult_t* result_out);
void        db_CVEPRODUCTSResultFree                    (CVEPRODUCTSResult_t* result);
DbStatus_t  db_CVESEARCH                                (PGconn* conn, const CVESEARCHParams_t* params, CveListResult_t* results_out);
void        db_CveListResultFree                        (CveListResult_t* results);
DbStatus_t  db_KEVLOOKUP                                (PGconn* conn, const char* cve_id, KEVLOOKUPRecord_t* record_out);
void        db_KEVLOOKUPRecordFree                      (KEVLOOKUPRecord_t* record);
DbStatus_t  db_CWELOOKUP                                (PGconn* conn, const char* cwe_id, CWELOOKUPRecord_t* record_out);
void        db_CWELOOKUPRecordFree                      (CWELOOKUPRecord_t* record);
DbStatus_t  db_CVELEADING                               (PGconn* conn, const CVELEADINGParams_t* params, CveListResult_t* results_out);
DbStatus_t  db_CVERISKSCORE                             (PGconn* conn, const char* cve_id, CVERISKSCORERecord_t* record_out);
DbStatus_t  db_CVETRIAGE                                (PGconn* conn, const CVETRIAGEParams_t* params, CVETRIAGEResult_t* results_out);
DbStatus_t  db_CVETRIAGEBULK                            (PGconn* conn, const BulkIdsParams_t* params, CVETRIAGEBULKResult_t* results_out);
void        db_CVETRIAGEResultFree                      (CVETRIAGEResult_t* results);
void        db_CVETRIAGEBULKResultFree                  (CVETRIAGEBULKResult_t* results);
DbStatus_t  db_PRODUCTEXPOSURE                          (PGconn* conn, const PRODUCTEXPOSUREParams_t* params, PRODUCTEXPOSURERecord_t* record_out);
DbStatus_t  db_CPESEARCH                                (PGconn* conn, const CPESEARCHParams_t* params, CPESEARCHResult_t* results_out);
void        db_CPESEARCHResultFree                      (CPESEARCHResult_t* results);
DbStatus_t  db_D3FENDFORATTACK                          (PGconn* conn, const char* attack_technique_id, D3FENDFORATTACKResult_t* result_out);
void        db_D3FENDFORATTACKResultFree                (D3FENDFORATTACKResult_t* result);
DbStatus_t  db_DRIVERLOOKUP                             (PGconn* conn, const char* file_hash, bool is_command_included, DRIVERLOOKUPRecord_t* record_out);
void        db_DRIVERLOOKUPRecordFree                   (DRIVERLOOKUPRecord_t* record);
DbStatus_t  db_DRIVERLOOKUPBULK                         (PGconn* conn, const BulkIdsParams_t* params, DRIVERLOOKUPBULKResult_t* results_out);
void        db_DRIVERLOOKUPBULKResultFree               (DRIVERLOOKUPBULKResult_t* results);
DbStatus_t  db_IPLOOKUP                                 (PGconn* conn, const char* ip_address, IPLOOKUPRecord_t* record_out);
void        db_IPLOOKUPRecordFree                       (IPLOOKUPRecord_t* record);
DbStatus_t  db_ASNLOOKUP                                (PGconn* conn, const ASNLOOKUPParams_t* params, ASNLOOKUPRecord_t* record_out);
void        db_ASNLOOKUPRecordFree                      (ASNLOOKUPRecord_t* record);
DbStatus_t  db_EMAILADDRESSCHECK                        (PGconn* conn, const char* domain, EMAILADDRESSCHECKRecord_t* record_out);
DbStatus_t  db_SSLCHECK                                 (PGconn* conn, const char* sha1_hex, SSLCHECKRecord_t* record_out);
DbStatus_t  db_PACKAGECHECK                             (PGconn* conn, const PACKAGECHECKParams_t* params, PACKAGECHECKResult_t* result_out);
void        db_PACKAGECHECKResultFree                   (PACKAGECHECKResult_t* result);
DbStatus_t  db_PACKAGECHECKBULK                         (PGconn* conn, const PACKAGECHECKBULKItem_t* items, int item_count, PACKAGECHECKBULKResult_t* result_out);
void        db_PACKAGECHECKBULKResultFree               (PACKAGECHECKBULKResult_t* result);
DbStatus_t  db_PACKAGECHECKBULKWeigh                    (PGconn* conn, const PACKAGECHECKBULKItem_t* items, int item_count, int* served_item_count_out);
DbStatus_t  db_WATCHLISTEDITItems                       (PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, const char* registered_domain, WATCHLISTEDITItemsResult_t* result_out);
void        db_WATCHLISTEDITItemsResultFree             (WATCHLISTEDITItemsResult_t* result);
DbStatus_t  db_WATCHLISTEDITPackageList                 (PGconn* conn, const WATCHLISTEDITPackageListDbParams_t* params, WATCHLISTEDITPackageListResult_t* result_out);
void        db_WATCHLISTEDITPackageListResultFree       (WATCHLISTEDITPackageListResult_t* result);
DbStatus_t  db_WATCHLISTEVENTS                          (PGconn* conn, const WATCHLISTEVENTSParams_t* params, int event_row_count, WATCHLISTEVENTSResult_t* result_out);
void        db_WATCHLISTEVENTSResultFree                (WATCHLISTEVENTSResult_t* result);

#define HEALTH_MAX_FEEDS              32
#define HEALTH_FEED_NAME_LEN          32
#define HEALTH_FEED_LAST_SYNCED_LEN   20
#define HEALTH_FEED_LAST_STATUS_LEN   16

typedef struct {
  char ma_name[HEALTH_FEED_NAME_LEN + 1];
  char ma_lastSynced[HEALTH_FEED_LAST_SYNCED_LEN + 1];
  char ma_lastStatus[HEALTH_FEED_LAST_STATUS_LEN + 1];
  int  m_recordsUpdated;
} HEALTHFeed_t;

typedef struct {
  int  m_cveCount;
  char ma_nvdLastCveId[CVELOOKUP_ID_MAX_LEN + 1];
  char ma_nvdLastPublishedTime[CVELOOKUP_PUBLISHED_LEN + 1];

  int  m_kevCount;
  char ma_kevLastCveId[CVELOOKUP_ID_MAX_LEN + 1];
  char ma_kevLastDateAdded[CVELOOKUP_PUBLISHED_LEN + 1];

  int  m_cweCount;
  char ma_cweLastId[CWELOOKUP_ID_MAX_LEN + 1];
  char ma_cweLastUpdatedAt[CWELOOKUP_UPDATED_AT_LEN + 1];

  int          m_feedCount;
  HEALTHFeed_t ma_feeds[HEALTH_MAX_FEEDS];
} HEALTHData_t;

DbStatus_t  db_HEALTH(PGconn* conn, HEALTHData_t* result_out);


#endif
