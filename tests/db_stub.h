#ifndef DB_STUB_H
#define DB_STUB_H

#include "db.h"
#include "watchlist/watchlist.h"

extern DbStatus_t g_stub_CVELOOKUP_status;

extern DbApiKeyState_t  g_stub_api_key_state;
extern DbApiKeyExpiry_t g_stub_api_key_expiry;
extern DbStatus_t       g_stub_api_key_db_status;

extern DbStatus_t             g_stub_billing_db_status;
extern DbBillingEventStatus_t g_stub_billing_event_status;
extern DbBillingClaimStatus_t g_stub_billing_claim_status;
extern int                    g_stub_billing_call_count;

extern const char* g_stub_billing_last_function;
extern char        g_stub_billing_last_webhook_id[VALIDATE_UUID_LEN + 1];
extern char        g_stub_billing_last_np_event_ref[BILLING_NOWPAYMENTS_EVENT_REF_MAX_LEN + 1];
extern char        g_stub_billing_last_np_event_name[32];
extern char        g_stub_billing_last_np_order_ref[BILLING_NOWPAYMENTS_REF_MAX_LEN + 1];
extern char        g_stub_billing_last_order_id[VALIDATE_UUID_LEN + 1];
extern char        g_stub_billing_last_key_hash[BYTES_SHA256_HEX_LEN + 1];

extern DbStatus_t               g_stub_vendor_keys_db_status;
extern DbVendorKeys_t           g_stub_vendor_keys;
extern DbStatus_t               g_stub_vendor_key_link_open_db_status;
extern int64_t                  g_stub_vendor_key_link_expires_at;
extern DbStatus_t               g_stub_vendor_key_link_read_db_status;
extern DbVendorKeyLink_t        g_stub_vendor_key_link;
extern DbStatus_t               g_stub_vendor_key_apply_db_status;
extern DbVendorKeyApplyStatus_t g_stub_vendor_key_apply_status;

extern int     g_stub_vendor_keys_call_count;
extern char    g_stub_vendor_keys_last_key_hash[BYTES_SHA256_HEX_LEN + 1];
extern int     g_stub_vendor_key_link_open_call_count;
extern int64_t g_stub_vendor_key_link_open_last_api_key_id;
extern char    g_stub_vendor_key_link_open_last_link_hash[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 2];
extern int     g_stub_vendor_key_link_read_call_count;
extern char    g_stub_vendor_key_link_read_last_link_hash[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 2];

extern int                 g_stub_vendor_key_apply_call_count;
extern DbVendorKeyChange_t g_stub_vendor_key_last_change;
extern char                g_stub_vendor_key_last_link_hash[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 2];
extern char                g_stub_vendor_key_last_key_fingerprint[DB_VENDOR_KEY_FINGERPRINT_HEX_LEN + 1];
extern char                g_stub_vendor_key_last_shodan_sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
extern char                g_stub_vendor_key_last_abuseipdb_sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
extern int        g_stub_CVELOOKUP_call_count;
extern const char* g_stub_CVELOOKUP_missing_id;

extern DbStatus_t  g_stub_CVELOOKUPGHSA_status;
extern bool        g_stub_CVELOOKUPGHSA_is_feed_loaded;
extern const char* g_stub_CVELOOKUPGHSA_advisory;
extern int         g_stub_CVELOOKUPGHSA_call_count;
extern char        g_stub_CVELOOKUPGHSA_last_cve_id[CVELOOKUP_ID_MAX_LEN + 1];

extern int        g_stub_CVELOOKUPBULK_call_count;
extern int        g_stub_CVELOOKUPBULK_id_count;

extern int        g_stub_query_call_count;
extern DbStatus_t g_stub_CVESEARCH_status;
extern DbStatus_t g_stub_KEVLOOKUP_status;
extern DbStatus_t g_stub_CWELOOKUP_status;
extern DbStatus_t g_stub_CVELEADING_status;
extern DbStatus_t g_stub_HEALTH_status;

extern DbStatus_t g_stub_CVERISKSCORE_status;
extern DbStatus_t g_stub_CVETRIAGE_status;
extern DbStatus_t g_stub_CVETRIAGEBULK_status;
extern int        g_stub_CVETRIAGEBULK_found;
extern int        g_stub_HEALTH_call_count;

extern int        g_stub_CVETRIAGEBULK_id_count;
extern DbStatus_t g_stub_PRODUCTEXPOSURE_status;

extern PRODUCTEXPOSUREParams_t g_stub_PRODUCTEXPOSURE_last_params;

extern CVESEARCHParams_t g_stub_CVESEARCH_last_params;

extern int g_stub_CVESEARCH_call_count;
extern int g_stub_CveListResultFree_call_count;

extern int g_stub_KEVLOOKUPRecordFree_call_count;
extern int g_stub_CWELOOKUPRecordFree_call_count;
extern int g_stub_CVETRIAGEResultFree_call_count;
extern int g_stub_CVETRIAGEBULKResultFree_call_count;

extern CVELEADINGParams_t  g_stub_CVELEADING_last_params;
extern int                 g_stub_CVELEADING_call_count;
extern CVETRIAGEParams_t   g_stub_CVETRIAGE_last_params;
extern int                 g_stub_CVETRIAGE_call_count;

extern CveListItem_t*      g_stub_CVESEARCH_items;
extern int                 g_stub_CVESEARCH_item_count;
extern CveListItem_t*      g_stub_CVELEADING_items;
extern int                 g_stub_CVELEADING_item_count;

extern int g_stub_CVETRIAGE_item_count;

extern DbStatus_t         g_stub_EPSSRISERS_status;
extern EPSSRISERSParams_t g_stub_EPSSRISERS_last_params;
extern int                g_stub_EPSSRISERS_call_count;
extern int                g_stub_EPSSRISERS_item_count;
extern const char*        g_stub_EPSSRISERS_from_date;
extern int                g_stub_EPSSRISERSResultFree_call_count;

extern DbStatus_t        g_stub_CPESEARCH_status;
extern CPESEARCHParams_t g_stub_CPESEARCH_last_params;
extern int               g_stub_CPESEARCH_call_count;
extern int               g_stub_CPESEARCH_item_count;
extern int               g_stub_CPESEARCHResultFree_call_count;

extern DbStatus_t g_stub_D3FENDFORATTACK_status;
extern char       g_stub_D3FENDFORATTACK_last_id[ATTACK_TECHNIQUE_ID_MAX_LEN + 1];
extern int        g_stub_D3FENDFORATTACK_call_count;
extern int        g_stub_D3FENDFORATTACK_defense_count;
extern int        g_stub_D3FENDFORATTACKResultFree_call_count;

extern DbStatus_t g_stub_DRIVERLOOKUP_status;
extern char       g_stub_DRIVERLOOKUP_last_hash[VALIDATE_SHA256_HEX_LEN + 1];
extern bool       g_stub_DRIVERLOOKUP_last_is_command_included;
extern int        g_stub_DRIVERLOOKUP_call_count;
extern int        g_stub_DRIVERLOOKUP_match_count;
extern bool       g_stub_DRIVERLOOKUP_is_driver_feed_loaded;
extern int        g_stub_DRIVERLOOKUPRecordFree_call_count;

extern DbStatus_t g_stub_DRIVERLOOKUPBULK_status;
extern int        g_stub_DRIVERLOOKUPBULK_call_count;
extern char       g_stub_DRIVERLOOKUPBULK_last_ids[BULK_MAX_IDS][BULK_ID_MAX_LEN + 1];
extern int        g_stub_DRIVERLOOKUPBULK_last_id_count;
extern int        g_stub_DRIVERLOOKUPBULK_failed_index;
extern int        g_stub_DRIVERLOOKUPBULKResultFree_call_count;
extern size_t     g_stub_DRIVERLOOKUPBULK_matches_len;
extern bool       g_stub_DRIVERLOOKUPBULK_matches_escaped;

#define DRIVERLOOKUP_STUB_MATCHES \
  R"([{"tags": ["RTCore64.sys"], "command": null, "cve_ids": ["CVE-2019-16098"], "category": "vulnerable driver", )" \
  R"("use_case": "Elevate privileges", "verified": true, "driver_id": "00000000-0000-0000-0000-00000000000a", )" \
  R"("matched_on": ["sha256"], "privileges": "kernel", "references": ["https://github.com/Barakat/CVE-2019-16098"], )" \
  R"("source_url": "https://www.loldrivers.io/drivers/00000000-0000-0000-0000-00000000000a/", )" \
  R"("description": "The driver lets a user read and write kernel memory.", "catalog_added": "2023-01-09", )" \
  R"("detection_rules": [{"type": "Sigma", "value": "driver_load_win_vuln_drivers.yml"}], "operating_system": "Windows 10", )" \
  R"("matched_driver_file": {"md5": "2d8e4f38b36c334d0a32a7324832501d", "sha1": "f6f11ad2cd2b0cf95ed42324876bee1d83e01775", )" \
  R"("sha256": "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd", "company": "Micro-Star International", )" \
  R"("imphash": "a5d2d4b3f4a5f6e7d8c9b0a1f2e3d4c5", "file_name": "RTCore64.sys", "publisher": "Micro-Star International Co., Ltd.", )" \
  R"("description": "RTCore64.sys", "authentihash": {"md5": "bcd9f192e2f6c1b8f1d4c3a2b1e0f9a8", )" \
  R"("sha1": "8d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4", "sha256": "d7d8e2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b"}, )" \
  R"("file_version": "4.6.2.15658", "product_name": "RTCore64", "product_version": "4.6.2.15658", "loads_despite_hvci": false, )" \
  R"("original_file_name": "RTCore64.sys"}, "attack_technique_ids": "T1068"}])"

extern DbStatus_t g_stub_IPLOOKUP_status;
extern char       g_stub_IPLOOKUP_last_ip_address[INET6_ADDRSTRLEN];
extern int        g_stub_IPLOOKUP_call_count;
extern int        g_stub_IPLOOKUPRecordFree_call_count;

extern void     (*g_stub_IPLOOKUP_change_record)(IPLOOKUPRecord_t* record);

#define IPLOOKUP_STUB_LISTED_ON \
  R"([{"prefix": "1.10.16.0/20", "source": "drop", "copyright": "(c) 2026 The Spamhaus Project SLU", "list_time": "2026-10-24T00:00:00Z", "listing_id": "SBL256894"}])"

extern DbStatus_t        g_stub_ASNLOOKUP_status;
extern ASNLOOKUPParams_t g_stub_ASNLOOKUP_last_params;
extern int               g_stub_ASNLOOKUP_call_count;
extern int               g_stub_ASNLOOKUPRecordFree_call_count;

#define ASNLOOKUP_STUB_PREFIX         "1.1.1.0/24"
#define ASNLOOKUP_STUB_IPV4_PREFIXES  R"(["1.0.0.0/24", "1.1.1.0/24"])"
#define ASNLOOKUP_STUB_IPV6_PREFIXES  R"(["2606:4700::/32"])"

extern DbStatus_t g_stub_EMAILADDRESSCHECK_status;
extern bool       g_stub_EMAILADDRESSCHECK_is_feed_loaded;
extern char       g_stub_EMAILADDRESSCHECK_listed_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern char       g_stub_EMAILADDRESSCHECK_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern int        g_stub_EMAILADDRESSCHECK_call_count;

extern DbStatus_t g_stub_SSLCHECK_status;
extern bool       g_stub_SSLCHECK_is_feed_loaded;
extern char       g_stub_SSLCHECK_listing_reason[SSLCHECK_BLACKLIST_LISTING_REASON_MAX_LEN + 1];
extern char       g_stub_SSLCHECK_listing_time[TLSPROBE_TIME_TEXT_SIZE];
extern char       g_stub_SSLCHECK_last_sha1[TLSPROBE_CERTIFICATE_SHA1_HEX_SIZE];
extern int        g_stub_SSLCHECK_call_count;

extern DbStatus_t           g_stub_PACKAGECHECK_status;
extern PACKAGECHECKParams_t g_stub_PACKAGECHECK_last_params;
extern int                  g_stub_PACKAGECHECK_call_count;
extern bool                 g_stub_PACKAGECHECK_is_advisory_feed_loaded;
extern int                  g_stub_PACKAGECHECKResultFree_call_count;

#define PACKAGECHECK_STUB_FIXED_VERSION "4.17.21"
#define PACKAGECHECK_STUB_MALICIOUS \
  R"json({"id":"MAL-2024-1","summary":"Malicious code in stub (npm)","published_time":"2024-01-01T00:00:00Z","affects_version":true})json"
#define PACKAGECHECK_STUB_RESULTS \
  R"([{"id":"GHSA-35jh-r3h4-6jhm","fixed":["4.17.21"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}],)" \
  R"("source":"ghsa","aliases":["CVE-2021-23337"],"summary":"Command Injection in lodash","fixed_version":"4.17.21",)" \
  R"("published_time":"2021-02-15T11:36:55Z","affects_version":true}])"
#define PACKAGECHECK_STUB_ATTRIBUTION \
  R"([{"url":"https://github.com/github/advisory-database","notice":"Retrieved through OSV.dev. ContrastAPI selected and normalized )" \
  R"(the fields and computed affects_version and fixed_version. No warranty; the source does not endorse ContrastAPI.",)" \
  R"("source":"ghsa","license":"CC-BY-4.0"}])"

extern DbStatus_t             g_stub_PACKAGECHECKBULK_status;
extern int                    g_stub_PACKAGECHECKBULK_failed_item_count;
extern PACKAGECHECKBULKItem_t g_stub_PACKAGECHECKBULK_last_items[PACKAGECHECKBULK_MAX_ITEMS];
extern int                    g_stub_PACKAGECHECKBULK_last_item_count;
extern int                    g_stub_PACKAGECHECKBULK_call_count;
extern int                    g_stub_PACKAGECHECKBULKResultFree_call_count;

extern DbStatus_t             g_stub_PACKAGECHECKBULKWeigh_status;
extern int                    g_stub_PACKAGECHECKBULKWeigh_served_item_count;
extern PACKAGECHECKBULKItem_t g_stub_PACKAGECHECKBULKWeigh_last_items[PACKAGECHECKBULK_MAX_ITEMS];
extern int                    g_stub_PACKAGECHECKBULKWeigh_last_item_count;
extern int                    g_stub_PACKAGECHECKBULKWeigh_call_count;

#define PACKAGECHECKBULK_STUB_RESULTS \
  R"([{"eol":null,"name":"lodash","version":"4.17.20","ecosystem":"npm","malicious":null,)" \
  R"("advisories":[{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"],"affects_version":true}],)" \
  R"("fixed_version":"4.17.21","advisory_total":1,"has_advisory_data":true}])"
#define PACKAGECHECKBULK_STUB_ATTRIBUTION \
  R"([{"url":"https://github.com/github/advisory-database","source":"ghsa","license":"CC-BY-4.0"}])"

extern DbStatus_t          g_stub_CVEPRODUCTS_status;
extern CVEPRODUCTSParams_t g_stub_CVEPRODUCTS_last_params;
extern int                 g_stub_CVEPRODUCTS_call_count;
extern int                 g_stub_CVEPRODUCTSResultFree_call_count;

#define CVEPRODUCTS_STUB_AFFECTED_PRODUCT_COUNT 37
#define CVEPRODUCTS_STUB_PRODUCTS R"([{"vendor":"apache","product":"log4j","is_vulnerable":true,"product_source":"nvd","version_end_excluding":"2.15.0"}])"

#define CVELOOKUP_STUB_AFFECTED_PRODUCT_COUNT  23
#define CVELOOKUP_STUB_PRODUCT_COUNT_BY_VENDOR R"({"apache":2,"cisco":21})"
#define CVELOOKUP_STUB_REF_COUNT               41

extern size_t g_stub_CVELOOKUP_affected_products_len;

extern size_t g_stub_KEVLOOKUP_cwes_len;
extern size_t g_stub_CWELOOKUP_mitigations_len;

extern bool g_stub_KEVLOOKUP_cwes_null;
extern bool g_stub_CWELOOKUP_documents_null;

extern bool g_stub_HEALTH_full_feeds;

extern bool g_stub_HEALTH_no_feeds;

#define STUB_WATCHLISTEDIT_PACKAGE_COPY_COUNT 3
extern DbStatus_t                    g_stub_WATCHLISTEDIT_status;
extern WATCHLISTEDITStatus_t         g_stub_WATCHLISTEDIT_result_status;
extern WATCHLISTEDITItemsDbParams_t  g_stub_WATCHLISTEDIT_last_params;
extern int                           g_stub_WATCHLISTEDIT_call_count;
extern char                          g_stub_WATCHLISTEDIT_last_registered_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern bool                          g_stub_WATCHLISTEDIT_last_has_registered_domain;
extern WATCHLISTEDITPackageElement_t g_stub_WATCHLISTEDIT_last_packages[STUB_WATCHLISTEDIT_PACKAGE_COPY_COUNT];
extern int                           g_stub_WATCHLISTEDIT_last_package_count;
extern WATCHLISTEDITPackageRepeat_t  g_stub_WATCHLISTEDIT_package_repeat;
extern int                           g_stub_WATCHLISTEDITResultFree_call_count;
extern DbStatus_t                    g_stub_WATCHLISTEVENTS_status;
extern WATCHLISTEVENTSStatus_t       g_stub_WATCHLISTEVENTS_result_status;
extern WATCHLISTEVENTSParams_t       g_stub_WATCHLISTEVENTS_last_params;
extern int                           g_stub_WATCHLISTEVENTS_last_event_row_count;
extern int                           g_stub_WATCHLISTEVENTS_call_count;
extern int                           g_stub_WATCHLISTEVENTSResultFree_call_count;

#define WATCHLISTEVENTS_STUB_ATTRIBUTION \
  R"([{"url":"https://endoflife.date","notice":"Retrieved from endoflife.date. ContrastAPI selected the fields and matched the release )" \
  R"(cycles to the watched product. No warranty; the source does not endorse ContrastAPI.","source":"endoflife.date","license":"MIT"},)" \
  R"({"url":"https://github.com/github/advisory-database","notice":"Retrieved through OSV.dev. ContrastAPI selected and normalized )" \
  R"(the fields and computed affects_version and fixed_version. No warranty; the source does not endorse ContrastAPI.",)" \
  R"("source":"ghsa","license":"CC-BY-4.0"}])"

#endif
