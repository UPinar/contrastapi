#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"
#include "db_stub.h"

DbStatus_t g_stub_CVELOOKUP_status  = DB_NOT_FOUND;
const char* g_stub_CVELOOKUP_missing_id = NULL;

DbApiKeyState_t  g_stub_api_key_state     = DB_API_KEY_UNKNOWN;
DbApiKeyExpiry_t g_stub_api_key_expiry    = { false, 0 };
DbStatus_t       g_stub_api_key_db_status = DB_OK;

DbStatus_t             g_stub_billing_db_status    = DB_OK;
DbBillingEventStatus_t g_stub_billing_event_status = DB_BILLING_EVENT_APPLIED;
DbBillingClaimStatus_t g_stub_billing_claim_status = DB_BILLING_CLAIM_CLAIMED;
int                    g_stub_billing_call_count   = 0;

const char* g_stub_billing_last_function = NULL;
char        g_stub_billing_last_webhook_id[VALIDATE_UUID_LEN + 1] = "";
char        g_stub_billing_last_order_id[VALIDATE_UUID_LEN + 1]   = "";
char        g_stub_billing_last_key_hash[SHA256_HEX_LEN + 1]      = "";

DbStatus_t               g_stub_vendor_keys_db_status                = DB_OK;
DbVendorKeys_t           g_stub_vendor_keys                          = { 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "" };
int                      g_stub_vendor_keys_call_count                = 0;
char                     g_stub_vendor_keys_last_key_hash[SHA256_HEX_LEN + 1] = "";
int                      g_stub_vendor_key_link_open_call_count      = 0;
int64_t                  g_stub_vendor_key_link_open_last_api_key_id = 0;
char                     g_stub_vendor_key_link_open_last_link_hash[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 2] = "";
int                      g_stub_vendor_key_link_read_call_count      = 0;
char                     g_stub_vendor_key_link_read_last_link_hash[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 2] = "";
DbStatus_t               g_stub_vendor_key_link_open_db_status       = DB_OK;
int64_t                  g_stub_vendor_key_link_expires_at           = 4102444800;
DbStatus_t               g_stub_vendor_key_link_read_db_status       = DB_OK;
DbVendorKeyLink_t        g_stub_vendor_key_link                      = { DB_VENDOR_KEY_LINK_OPEN, 1, 4102444800, "", "" };
DbStatus_t               g_stub_vendor_key_apply_db_status           = DB_OK;
DbVendorKeyApplyStatus_t g_stub_vendor_key_apply_status              = DB_VENDOR_KEY_APPLY_APPLIED;
int                      g_stub_vendor_key_apply_call_count          = 0;
DbVendorKeyChange_t      g_stub_vendor_key_last_change               = { 0 };
char                     g_stub_vendor_key_last_link_hash[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 2]   = "";
char                     g_stub_vendor_key_last_key_fingerprint[DB_VENDOR_KEY_FINGERPRINT_HEX_LEN + 1] = "";
char                     g_stub_vendor_key_last_shodan_sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1]    = "";
char                     g_stub_vendor_key_last_abuseipdb_sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1] = "";

int        g_stub_CVELOOKUP_call_count = 0;

int        g_stub_CVELOOKUPBULK_call_count = 0;
int        g_stub_CVELOOKUPBULK_id_count   = 0;

int        g_stub_query_call_count = 0;

size_t     g_stub_CVELOOKUP_affected_products_len = 0;

const char* g_stub_CVELOOKUP_ransomware = "Known";

const char* g_stub_CVELOOKUP_cvss_v4_vector = "";

bool g_stub_CVELOOKUP_has_ssvc = false;

static void static_CVELOOKUPFillSsvc(CVELOOKUPRecord_t* record_out)
{
  static const char* const LEVEL_DECISIONS[SSVC_MISSION_WELLBEING_LEVEL_COUNT]    = { "Attend", "Act", "Act" };
  static const char* const LEVEL_REMEDIATION_ADVICE[SSVC_MISSION_WELLBEING_LEVEL_COUNT] = {
    "sooner than standard update timelines", "as soon as possible", "as soon as possible"
  };
  const bool has_ssvc = g_stub_CVELOOKUP_has_ssvc;
  snprintf(record_out->ma_ssvcExploitation, sizeof(record_out->ma_ssvcExploitation), "%s", has_ssvc ? "active" : "");
  snprintf(record_out->ma_ssvcAutomatable, sizeof(record_out->ma_ssvcAutomatable), "%s", has_ssvc ? "yes" : "");
  snprintf(record_out->ma_ssvcTechnicalImpact, sizeof(record_out->ma_ssvcTechnicalImpact), "%s", has_ssvc ? "total" : "");
  snprintf(record_out->ma_ssvcVersion, sizeof(record_out->ma_ssvcVersion), "%s", has_ssvc ? "2.0.3" : "");
  snprintf(record_out->ma_ssvcScoredAt, sizeof(record_out->ma_ssvcScoredAt), "%s", has_ssvc ? "2024-04-17T04:00:13Z" : "");
  memset(&record_out->m_ssvcResult, 0, sizeof(record_out->m_ssvcResult));
  if (!has_ssvc)
    return;
  for (int level = 0; level < SSVC_MISSION_WELLBEING_LEVEL_COUNT; level++)
  {
    snprintf(record_out->m_ssvcResult.ma_decisions[level], sizeof(record_out->m_ssvcResult.ma_decisions[level]),
             "%s", LEVEL_DECISIONS[level]);
    snprintf(record_out->m_ssvcResult.ma_remediationAdvice[level], sizeof(record_out->m_ssvcResult.ma_remediationAdvice[level]),
             "%s", LEVEL_REMEDIATION_ADVICE[level]);
  }
}

static char* static_paddedStringArrayDocument(size_t wanted)
{
  const size_t total = wanted < 4 ? 4 : wanted;
  char* doc = malloc(total + 1);
  if (!doc)
    return NULL;
  doc[0] = '[';
  doc[1] = '"';
  memset(doc + 2, 'a', total - 4);
  doc[total - 2] = '"';
  doc[total - 1] = ']';
  doc[total]     = '\0';
  return doc;
}

static char* static_affectedProductsDocument(void)
{
  if (g_stub_CVELOOKUP_affected_products_len == 0)
    return strdup("[{\"vendor\":\"apache\",\"product\":\"log4j\"}]");
  return static_paddedStringArrayDocument(g_stub_CVELOOKUP_affected_products_len);
}

DbStatus_t db_readApiKeyState(PGconn* conn, const char* key_hash, DbApiKeyState_t* state_out, DbApiKeyExpiry_t* expiry_out)
{
  g_stub_query_call_count++;
  (void)conn;
  (void)key_hash;
  if (g_stub_api_key_db_status == DB_OK)
  {
    *state_out  = g_stub_api_key_state;
    *expiry_out = g_stub_api_key_expiry;
  }
  return g_stub_api_key_db_status;
}

char g_stub_billing_last_np_event_ref[BILLING_NOWPAYMENTS_EVENT_REF_MAX_LEN + 1] = "";
char g_stub_billing_last_np_event_name[32] = "";
char g_stub_billing_last_np_order_ref[BILLING_NOWPAYMENTS_REF_MAX_LEN + 1] = "";

static DbStatus_t static_answerBillingEvent(const char* function, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  g_stub_billing_last_function = function;
  snprintf(g_stub_billing_last_webhook_id, sizeof(g_stub_billing_last_webhook_id), "%s", event->ma_webhookId);
  g_stub_query_call_count++;
  g_stub_billing_call_count++;
  if (g_stub_billing_db_status == DB_OK)
    *status_out = g_stub_billing_event_status;
  return g_stub_billing_db_status;
}

const char* db_billingEventStatusText(DbBillingEventStatus_t status)
{
  static char text[32];
  snprintf(text, sizeof(text), "stub_status_%d", (int)status);
  return text;
}

DbStatus_t db_billingLemonSqueezyOrderPaid(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  (void)conn;
  return static_answerBillingEvent(__func__, event, status_out);
}

DbStatus_t db_billingLemonSqueezySetExpiry(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  (void)conn;
  return static_answerBillingEvent(__func__, event, status_out);
}

DbStatus_t db_billingLemonSqueezyClearExpiry(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  (void)conn;
  return static_answerBillingEvent(__func__, event, status_out);
}

DbStatus_t db_billingLemonSqueezyRevoke(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  (void)conn;
  return static_answerBillingEvent(__func__, event, status_out);
}

DbStatus_t db_billingLemonSqueezyEventRecord(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  (void)conn;
  return static_answerBillingEvent(__func__, event, status_out);
}

DbStatus_t db_billingNowPaymentsOrderPaid(PGconn* conn, const char* event_ref, const char* event_name, const char* order_id, const char* order_ref, DbBillingEventStatus_t* status_out)
{
  (void)conn;
  g_stub_billing_last_function = __func__;
  snprintf(g_stub_billing_last_np_event_ref, sizeof(g_stub_billing_last_np_event_ref), "%s", event_ref);
  snprintf(g_stub_billing_last_np_event_name, sizeof(g_stub_billing_last_np_event_name), "%s", event_name);
  snprintf(g_stub_billing_last_order_id, sizeof(g_stub_billing_last_order_id), "%s", order_id);
  snprintf(g_stub_billing_last_np_order_ref, sizeof(g_stub_billing_last_np_order_ref), "%s", order_ref);
  g_stub_query_call_count++;
  g_stub_billing_call_count++;
  if (g_stub_billing_db_status == DB_OK)
    *status_out = g_stub_billing_event_status;
  return g_stub_billing_db_status;
}

DbStatus_t db_billingClaim(PGconn* conn, const char* order_id, const char* key_hash, DbBillingClaimStatus_t* status_out)
{
  (void)conn;
  g_stub_billing_last_function = __func__;
  snprintf(g_stub_billing_last_order_id, sizeof(g_stub_billing_last_order_id), "%s", order_id);
  snprintf(g_stub_billing_last_key_hash, sizeof(g_stub_billing_last_key_hash), "%s", key_hash);
  g_stub_query_call_count++;
  g_stub_billing_call_count++;
  if (g_stub_billing_db_status == DB_OK)
    *status_out = g_stub_billing_claim_status;
  return g_stub_billing_db_status;
}

DbStatus_t db_readVendorKeys(PGconn* conn, const char* key_hash, DbVendorKeys_t* vendor_keys_out)
{
  (void)conn;
  g_stub_query_call_count++;
  g_stub_vendor_keys_call_count++;
  snprintf(g_stub_vendor_keys_last_key_hash, sizeof(g_stub_vendor_keys_last_key_hash), "%s", key_hash);
  if (g_stub_vendor_keys_db_status == DB_OK)
    *vendor_keys_out = g_stub_vendor_keys;
  return g_stub_vendor_keys_db_status;
}

DbStatus_t db_openVendorKeyLink(PGconn* conn, int64_t api_key_id, const char* link_hash_hex, int64_t* link_expires_at_out)
{
  (void)conn;
  g_stub_query_call_count++;
  g_stub_vendor_key_link_open_call_count++;
  g_stub_vendor_key_link_open_last_api_key_id = api_key_id;
  snprintf(g_stub_vendor_key_link_open_last_link_hash, sizeof(g_stub_vendor_key_link_open_last_link_hash), "%s", link_hash_hex);
  if (g_stub_vendor_key_link_open_db_status == DB_OK)
    *link_expires_at_out = g_stub_vendor_key_link_expires_at;
  return g_stub_vendor_key_link_open_db_status;
}

DbStatus_t db_readVendorKeyLink(PGconn* conn, const char* link_hash_hex, DbVendorKeyLink_t* vendor_key_link_out)
{
  (void)conn;
  g_stub_query_call_count++;
  g_stub_vendor_key_link_read_call_count++;
  snprintf(g_stub_vendor_key_link_read_last_link_hash, sizeof(g_stub_vendor_key_link_read_last_link_hash), "%s", link_hash_hex);
  if (g_stub_vendor_key_link_read_db_status == DB_OK)
    *vendor_key_link_out = g_stub_vendor_key_link;
  return g_stub_vendor_key_link_read_db_status;
}

static const char* static_copyChangeText(const char* text, char* copy, size_t copy_len)
{
  if (text == NULL)
    return NULL;
  snprintf(copy, copy_len, "%s", text);
  return copy;
}

DbStatus_t db_applyVendorKeys(PGconn* conn, const DbVendorKeyChange_t* change, DbVendorKeyApplyStatus_t* apply_status_out)
{
  (void)conn;
  g_stub_query_call_count++;
  g_stub_vendor_key_apply_call_count++;
  g_stub_vendor_key_last_change = *change;
  g_stub_vendor_key_last_change.mp_linkHash           = static_copyChangeText(change->mp_linkHash, g_stub_vendor_key_last_link_hash, sizeof(g_stub_vendor_key_last_link_hash));
  g_stub_vendor_key_last_change.mp_keyFingerprint     = static_copyChangeText(change->mp_keyFingerprint, g_stub_vendor_key_last_key_fingerprint, sizeof(g_stub_vendor_key_last_key_fingerprint));
  g_stub_vendor_key_last_change.mp_shodanSealedHex    = static_copyChangeText(change->mp_shodanSealedHex, g_stub_vendor_key_last_shodan_sealed_hex, sizeof(g_stub_vendor_key_last_shodan_sealed_hex));
  g_stub_vendor_key_last_change.mp_abuseIpDbSealedHex = static_copyChangeText(change->mp_abuseIpDbSealedHex, g_stub_vendor_key_last_abuseipdb_sealed_hex, sizeof(g_stub_vendor_key_last_abuseipdb_sealed_hex));
  if (g_stub_vendor_key_apply_db_status == DB_OK)
    *apply_status_out = g_stub_vendor_key_apply_status;
  return g_stub_vendor_key_apply_db_status;
}

static DbStatus_t static_fillCvelookupRecord(const char* cve_id, CVELOOKUPRecord_t* record_out)
{
  record_out->mp_cwes               = NULL;
  record_out->mp_cveTags            = NULL;
  record_out->mp_affectedProducts     = NULL;
  record_out->mp_productCountByVendor = NULL;
  record_out->mp_refs               = NULL;
  record_out->mp_epssTrend          = NULL;
  record_out->mp_nucleiTemplates    = NULL;
  record_out->mp_ghsa               = NULL;
  record_out->m_pocCount            = 0;
  record_out->m_vendorAdvisoryCount = 0;
  if (g_stub_CVELOOKUP_missing_id != NULL && strcmp(cve_id, g_stub_CVELOOKUP_missing_id) == 0)
    return DB_NOT_FOUND;
  if (g_stub_CVELOOKUP_status == DB_OK)
  {
    strncpy(record_out->ma_cveId, cve_id, CVELOOKUP_ID_MAX_LEN);
    record_out->ma_cveId[CVELOOKUP_ID_MAX_LEN] = '\0';
    strncpy(record_out->ma_description, "Remote code execution", CVELOOKUP_DESC_MAX_LEN);
    record_out->ma_description[CVELOOKUP_DESC_MAX_LEN] = '\0';
    strncpy(record_out->ma_severity, "CRITICAL", CVELOOKUP_SEVERITY_LEN);
    record_out->ma_severity[CVELOOKUP_SEVERITY_LEN] = '\0';
    record_out->m_cvssV3 = 9.8;
    strncpy(record_out->ma_cvssV3Vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CVELOOKUP_V3_VECTOR_LEN);
    record_out->ma_cvssV3Vector[CVELOOKUP_V3_VECTOR_LEN] = '\0';
    record_out->m_cvssV4 = 9.3;
    strncpy(record_out->ma_cvssV4Vector, g_stub_CVELOOKUP_cvss_v4_vector, CVELOOKUP_V4_VECTOR_LEN);
    record_out->ma_cvssV4Vector[CVELOOKUP_V4_VECTOR_LEN] = '\0';
    strncpy(record_out->ma_cvssV3Source, "nvd", CVELOOKUP_SOURCE_LEN);
    record_out->ma_cvssV3Source[CVELOOKUP_SOURCE_LEN] = '\0';
    strncpy(record_out->ma_cvssV4Source, "cna", CVELOOKUP_SOURCE_LEN);
    record_out->ma_cvssV4Source[CVELOOKUP_SOURCE_LEN] = '\0';
    strncpy(record_out->ma_publishedTime, "2021-12-10", CVELOOKUP_PUBLISHED_LEN);
    record_out->ma_publishedTime[CVELOOKUP_PUBLISHED_LEN] = '\0';
    record_out->m_epssScore = 0.9756;
    record_out->m_epssPercentile = 0.997;
    strncpy(record_out->ma_cweId, "CWE-917", CVELOOKUP_CWE_ID_LEN);
    record_out->ma_cweId[CVELOOKUP_CWE_ID_LEN] = '\0';
    strncpy(record_out->ma_cweSource, "adp", CVELOOKUP_SOURCE_LEN);
    record_out->ma_cweSource[CVELOOKUP_SOURCE_LEN] = '\0';
    record_out->m_inKev = true;
    strncpy(record_out->ma_kevDateAdded, "2021-12-10", CVELOOKUP_PUBLISHED_LEN);
    record_out->ma_kevDateAdded[CVELOOKUP_PUBLISHED_LEN] = '\0';
    strncpy(record_out->ma_vulnerabilityStatus, "Analyzed", CVELOOKUP_STATUS_LEN);
    record_out->ma_vulnerabilityStatus[CVELOOKUP_STATUS_LEN] = '\0';
    strncpy(record_out->ma_ransomwareCampaign, g_stub_CVELOOKUP_ransomware, CVELOOKUP_RANSOMWARE_LEN);
    record_out->ma_ransomwareCampaign[CVELOOKUP_RANSOMWARE_LEN] = '\0';
    static_CVELOOKUPFillSsvc(record_out);
    record_out->m_pocCount            = 3;
    record_out->m_vendorAdvisoryCount = 2;
    record_out->mp_cwes               = strdup("[\"CWE-917\"]");
    record_out->mp_cveTags            = strdup("[\"unsupported-when-assigned\"]");
    record_out->mp_affectedProducts   = static_affectedProductsDocument();
    record_out->mp_productCountByVendor = strdup(CVELOOKUP_STUB_PRODUCT_COUNT_BY_VENDOR);
    record_out->mp_refs               = strdup("[{\"url\":\"https://example.com\",\"tags\":[\"Exploit\"]}]");
    record_out->mp_epssTrend          = strdup("[]");
    record_out->mp_nucleiTemplates    = strdup("[{\"template_id\":\"CVE-2021-44228\",\"name\":\"Apache Log4j2 Remote Code Injection\",\"severity\":\"critical\","
                                               "\"template_path\":\"http/cves/2021/CVE-2021-44228.yaml\","
                                               "\"url\":\"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml\"}]");
    if (!record_out->mp_cwes || !record_out->mp_cveTags || !record_out->mp_affectedProducts || !record_out->mp_productCountByVendor ||
        !record_out->mp_refs || !record_out->mp_epssTrend || !record_out->mp_nucleiTemplates)
    {
      db_CVELOOKUPRecordFree(record_out);
      return DB_ERROR;
    }
    record_out->m_metasploitModuleCount  = 3;
    record_out->m_isMetasploitFeedLoaded = true;
    record_out->m_nucleiTemplateCount        = 1;
    record_out->m_isNucleiTemplateFeedLoaded = true;
    record_out->m_affectedProductCount       = CVELOOKUP_STUB_AFFECTED_PRODUCT_COUNT;
    record_out->m_refCount                   = CVELOOKUP_STUB_REF_COUNT;
  }
  return g_stub_CVELOOKUP_status;
}

DbStatus_t db_CVELOOKUP(PGconn* conn, const char* cve_id, CVELOOKUPRecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_CVELOOKUP_call_count++;
  return static_fillCvelookupRecord(cve_id, record_out);
}

void db_CVELOOKUPRecordFree(CVELOOKUPRecord_t* r)
{
  if (!r) return;
  free(r->mp_cwes);
  free(r->mp_cveTags);
  free(r->mp_affectedProducts);
  free(r->mp_productCountByVendor);
  free(r->mp_refs);
  free(r->mp_epssTrend);
  free(r->mp_nucleiTemplates);
  free(r->mp_ghsa);
  r->mp_cwes                 = NULL;
  r->mp_cveTags              = NULL;
  r->mp_affectedProducts     = NULL;
  r->mp_productCountByVendor = NULL;
  r->mp_refs                 = NULL;
  r->mp_epssTrend            = NULL;
  r->mp_nucleiTemplates      = NULL;
  r->mp_ghsa                 = NULL;
}

DbStatus_t  g_stub_CVELOOKUPGHSA_status         = DB_OK;
bool        g_stub_CVELOOKUPGHSA_is_feed_loaded = true;
const char* g_stub_CVELOOKUPGHSA_advisory       = NULL;
int         g_stub_CVELOOKUPGHSA_call_count     = 0;
char        g_stub_CVELOOKUPGHSA_last_cve_id[CVELOOKUP_ID_MAX_LEN + 1];

DbStatus_t db_CVELOOKUPGHSA(PGconn* conn, const char* cve_id, CVELOOKUPRecord_t* record)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_CVELOOKUPGHSA_call_count++;
  snprintf(g_stub_CVELOOKUPGHSA_last_cve_id, sizeof(g_stub_CVELOOKUPGHSA_last_cve_id), "%s", cve_id);
  if (g_stub_CVELOOKUPGHSA_status != DB_OK)
    return g_stub_CVELOOKUPGHSA_status;

  record->m_isGhsaFeedLoaded = g_stub_CVELOOKUPGHSA_is_feed_loaded;
  if (g_stub_CVELOOKUPGHSA_advisory)
  {
    record->mp_ghsa = strdup(g_stub_CVELOOKUPGHSA_advisory);
    if (!record->mp_ghsa)
      return DB_ERROR;
  }
  return DB_OK;
}

void db_CVELOOKUPBULKResultFree(CVELOOKUPBULKResult_t* results)
{
  if (!results || !results->mp_items) return;
  for (int i = 0; i < results->m_successful; i++)
    db_CVELOOKUPRecordFree(&results->mp_items[i]);
  free(results->mp_items);
  results->mp_items = NULL;
}

DbStatus_t db_CVELOOKUPBULK(PGconn* conn, const BulkIdsParams_t* params, CVELOOKUPBULKResult_t* results_out)
{
  g_stub_query_call_count++;
  (void)conn;
  int id_count = params->m_idCount;
  g_stub_CVELOOKUPBULK_call_count++;
  g_stub_CVELOOKUPBULK_id_count += id_count;
  results_out->m_successful = 0;
  results_out->m_failed     = 0;
  results_out->mp_items     = NULL;
  if (g_stub_CVELOOKUP_status == DB_ERROR)
    return DB_ERROR;

  if (id_count > 0)
  {
    results_out->mp_items = calloc((size_t)id_count, sizeof(CVELOOKUPRecord_t));
    if (!results_out->mp_items)
      return DB_ERROR;
  }
  int successful = 0;
  for (int i = 0; i < id_count; i++)
  {
    if (static_fillCvelookupRecord(params->ma_ids[i], &results_out->mp_items[successful]) == DB_OK)
      successful++;
  }
  results_out->m_successful = successful;
  results_out->m_failed     = id_count - successful;
  return DB_OK;
}

PGconn* db_open(const char* conninfo)
{
  (void)conninfo;
  return (PGconn *)1;
}

void db_close(PGconn* conn)
{
  (void)conn;
}

DbStatus_t g_stub_CVESEARCH_status = DB_ERROR;

CVESEARCHParams_t g_stub_CVESEARCH_last_params = { 0 };

int g_stub_CVESEARCH_call_count = 0;

CveListItem_t* g_stub_CVESEARCH_items = NULL;
int            g_stub_CVESEARCH_item_count = 0;

DbStatus_t db_CVESEARCH(PGconn* conn, const CVESEARCHParams_t* params, CveListResult_t* results_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_CVESEARCH_last_params = *params;
  g_stub_CVESEARCH_call_count++;
  results_out->m_total  = g_stub_CVESEARCH_item_count;
  results_out->m_count  = g_stub_CVESEARCH_item_count;
  results_out->mp_items = g_stub_CVESEARCH_items;
  return g_stub_CVESEARCH_status;
}

int g_stub_CveListResultFree_call_count = 0;

void db_CveListResultFree(CveListResult_t* r)
{
  (void)r;
  g_stub_CveListResultFree_call_count++;
}

DbStatus_t g_stub_KEVLOOKUP_status   = DB_NOT_FOUND;
size_t     g_stub_KEVLOOKUP_cwes_len = 0;

DbStatus_t db_KEVLOOKUP(PGconn* conn, const char* cve_id, KEVLOOKUPRecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  record_out->mp_cwes  = NULL;
  record_out->mp_notes = NULL;
  if (g_stub_KEVLOOKUP_status == DB_OK)
  {
    strncpy(record_out->ma_cveId, cve_id, CVELOOKUP_ID_MAX_LEN);
    record_out->ma_cveId[CVELOOKUP_ID_MAX_LEN] = '\0';
    record_out->m_inKev = true;
    strncpy(record_out->ma_vendorProject, "Apache", KEVLOOKUP_VENDOR_LEN);
    record_out->ma_vendorProject[KEVLOOKUP_VENDOR_LEN] = '\0';
    strncpy(record_out->ma_product, "Log4j", KEVLOOKUP_PRODUCT_LEN);
    record_out->ma_product[KEVLOOKUP_PRODUCT_LEN] = '\0';
    strncpy(record_out->ma_patchDeadline, "2021-12-24", CVELOOKUP_PUBLISHED_LEN);
    record_out->ma_patchDeadline[CVELOOKUP_PUBLISHED_LEN] = '\0';
    strncpy(record_out->ma_requiredAction,
            "Apply updates per vendor instructions.", KEVLOOKUP_REQUIRED_ACTION_LEN);
    record_out->ma_requiredAction[KEVLOOKUP_REQUIRED_ACTION_LEN] = '\0';
    record_out->m_knownRansomwareUse = false;
    strncpy(record_out->ma_vulnerabilityName, "Log4Shell", KEVLOOKUP_VULN_NAME_LEN);
    record_out->ma_vulnerabilityName[KEVLOOKUP_VULN_NAME_LEN] = '\0';
    strncpy(record_out->ma_shortDescription,
            "Remote code execution via JNDI lookup.", KEVLOOKUP_SHORT_DESC_LEN);
    record_out->ma_shortDescription[KEVLOOKUP_SHORT_DESC_LEN] = '\0';
    strncpy(record_out->ma_dateAdded, "2021-12-10", CVELOOKUP_PUBLISHED_LEN);
    record_out->ma_dateAdded[CVELOOKUP_PUBLISHED_LEN] = '\0';
    strncpy(record_out->ma_dateRemoved, "", KEVLOOKUP_DATE_REMOVED_LEN);
    record_out->ma_dateRemoved[KEVLOOKUP_DATE_REMOVED_LEN] = '\0';
    record_out->mp_cwes = g_stub_KEVLOOKUP_cwes_len == 0
                        ? strdup("[\"CWE-917\"]")
                        : static_paddedStringArrayDocument(g_stub_KEVLOOKUP_cwes_len);
    if (!record_out->mp_cwes)
      return DB_ERROR;
    record_out->mp_notes = strdup("https://logging.apache.org/log4j/2.x/security.html");
    if (!record_out->mp_notes)
    {
      free(record_out->mp_cwes);
      record_out->mp_cwes = NULL;
      return DB_ERROR;
    }
  }
  return g_stub_KEVLOOKUP_status;
}

int g_stub_KEVLOOKUPRecordFree_call_count = 0;

void db_KEVLOOKUPRecordFree(KEVLOOKUPRecord_t* r)
{
  g_stub_KEVLOOKUPRecordFree_call_count++;
  if (!r) return;
  free(r->mp_cwes);
  free(r->mp_notes);
  r->mp_cwes  = NULL;
  r->mp_notes = NULL;
}

DbStatus_t g_stub_CWELOOKUP_status          = DB_NOT_FOUND;
size_t     g_stub_CWELOOKUP_mitigations_len = 0;

DbStatus_t db_CWELOOKUP(PGconn* conn, const char* cwe_id, CWELOOKUPRecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  record_out->mp_mitigations         = NULL;
  record_out->mp_extendedDescription = NULL;
  record_out->mp_examples            = NULL;
  if (g_stub_CWELOOKUP_status == DB_OK)
  {
    strncpy(record_out->ma_cweId, cwe_id, CWELOOKUP_ID_MAX_LEN);
    record_out->ma_cweId[CWELOOKUP_ID_MAX_LEN] = '\0';
    strncpy(record_out->ma_name, "Improper Input Validation", CWELOOKUP_NAME_LEN);
    record_out->ma_name[CWELOOKUP_NAME_LEN] = '\0';
    strncpy(record_out->ma_abstraction, "Class", CWELOOKUP_ABSTRACTION_LEN);
    record_out->ma_abstraction[CWELOOKUP_ABSTRACTION_LEN] = '\0';
    strncpy(record_out->ma_status, "Stable", CWELOOKUP_STATUS_LEN);
    record_out->ma_status[CWELOOKUP_STATUS_LEN] = '\0';
    strncpy(record_out->ma_description, "Input not validated properly.", CWELOOKUP_DESC_MAX_LEN);
    record_out->ma_description[CWELOOKUP_DESC_MAX_LEN] = '\0';
    strncpy(record_out->ma_likelihood, "High", CWELOOKUP_LIKELIHOOD_LEN);
    record_out->ma_likelihood[CWELOOKUP_LIKELIHOOD_LEN] = '\0';
    strncpy(record_out->ma_parentCwe, "CWE-74", CWELOOKUP_PARENT_CWE_LEN);
    record_out->ma_parentCwe[CWELOOKUP_PARENT_CWE_LEN] = '\0';
    strncpy(record_out->ma_updatedAt, "2026-05-21T00:00:00+00:00", CWELOOKUP_UPDATED_AT_LEN);
    record_out->ma_updatedAt[CWELOOKUP_UPDATED_AT_LEN] = '\0';
    record_out->m_cveCount = 42;
    record_out->m_kevCount       = 3;
    record_out->m_avgCvss        = 6.5;
    record_out->m_avgEpss  = 0.0287;
    record_out->mp_mitigations = g_stub_CWELOOKUP_mitigations_len == 0
                               ? strdup("[\"Use allowlists.\"]")
                               : static_paddedStringArrayDocument(g_stub_CWELOOKUP_mitigations_len);
    if (!record_out->mp_mitigations)
      return DB_ERROR;
    record_out->mp_extendedDescription = strdup("Extended description of the weakness.");
    if (!record_out->mp_extendedDescription)
    {
      free(record_out->mp_mitigations);
      record_out->mp_mitigations = NULL;
      return DB_ERROR;
    }
    record_out->mp_examples = strdup("[\"CVE-2024-1234: Example.\"]");
    if (!record_out->mp_examples)
    {
      free(record_out->mp_mitigations);
      free(record_out->mp_extendedDescription);
      record_out->mp_mitigations         = NULL;
      record_out->mp_extendedDescription = NULL;
      return DB_ERROR;
    }
  }
  return g_stub_CWELOOKUP_status;
}

int g_stub_CWELOOKUPRecordFree_call_count = 0;

void db_CWELOOKUPRecordFree(CWELOOKUPRecord_t* r)
{
  g_stub_CWELOOKUPRecordFree_call_count++;
  if (!r) return;
  free(r->mp_mitigations);
  free(r->mp_extendedDescription);
  free(r->mp_examples);
  r->mp_mitigations         = NULL;
  r->mp_extendedDescription = NULL;
  r->mp_examples            = NULL;
}

DbStatus_t g_stub_CVELEADING_status = DB_ERROR;

CVELEADINGParams_t g_stub_CVELEADING_last_params = { 0 };
int                g_stub_CVELEADING_call_count  = 0;
CveListItem_t*     g_stub_CVELEADING_items       = NULL;
int                g_stub_CVELEADING_item_count  = 0;

DbStatus_t db_CVELEADING(PGconn* conn, const CVELEADINGParams_t* params, CveListResult_t* results_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_CVELEADING_last_params = *params;
  g_stub_CVELEADING_call_count++;
  results_out->m_total  = g_stub_CVELEADING_item_count;
  results_out->m_count  = g_stub_CVELEADING_item_count;
  results_out->mp_items = g_stub_CVELEADING_items;
  return g_stub_CVELEADING_status;
}

DbStatus_t g_stub_HEALTH_status     = DB_OK;
bool       g_stub_HEALTH_full_feeds = false;
int        g_stub_HEALTH_call_count = 0;

DbStatus_t db_HEALTH(PGconn* conn, HEALTHData_t* result_out)
{
  g_stub_query_call_count++;
  g_stub_HEALTH_call_count++;
  memset(result_out, 0, sizeof(*result_out));
  if (conn == NULL)
    return DB_ERROR;
  if (g_stub_HEALTH_status == DB_OK)
  {
    result_out->m_cveCount = 251430;
    strncpy(result_out->ma_nvdLastCveId,     "CVE-2026-1234", CVELOOKUP_ID_MAX_LEN);
    result_out->ma_nvdLastCveId[CVELOOKUP_ID_MAX_LEN] = '\0';
    strncpy(result_out->ma_nvdLastPublishedTime, "2026-05-22T10:00:00Z", CVELOOKUP_PUBLISHED_LEN);
    result_out->ma_nvdLastPublishedTime[CVELOOKUP_PUBLISHED_LEN] = '\0';

    result_out->m_kevCount       = 1602;
    strncpy(result_out->ma_kevLastCveId,     "CVE-2024-5678", CVELOOKUP_ID_MAX_LEN);
    result_out->ma_kevLastCveId[CVELOOKUP_ID_MAX_LEN] = '\0';
    strncpy(result_out->ma_kevLastDateAdded, "2026-05-20T00:00:00Z", CVELOOKUP_PUBLISHED_LEN);
    result_out->ma_kevLastDateAdded[CVELOOKUP_PUBLISHED_LEN] = '\0';

    result_out->m_cweCount = 944;
    strncpy(result_out->ma_cweLastId,        "CWE-79",        CWELOOKUP_ID_MAX_LEN);
    result_out->ma_cweLastId[CWELOOKUP_ID_MAX_LEN] = '\0';
    strncpy(result_out->ma_cweLastUpdatedAt, "2026-03-15T14:07:56Z", CWELOOKUP_UPDATED_AT_LEN);
    result_out->ma_cweLastUpdatedAt[CWELOOKUP_UPDATED_AT_LEN] = '\0';

    if (g_stub_HEALTH_full_feeds)
    {
      result_out->m_feedCount = HEALTH_MAX_FEEDS;
      for (int i = 0; i < HEALTH_MAX_FEEDS; i++)
      {
        HEALTHFeed_t* feed = &result_out->ma_feeds[i];
        memset(feed->ma_name, '\001', HEALTH_FEED_NAME_LEN);
        feed->ma_name[HEALTH_FEED_NAME_LEN] = '\0';
        strcpy(feed->ma_lastSynced, "2026-10-08T01:22:39Z");
        memset(feed->ma_lastStatus, '\001', HEALTH_FEED_LAST_STATUS_LEN);
        feed->ma_lastStatus[HEALTH_FEED_LAST_STATUS_LEN] = '\0';
        feed->m_recordsUpdated = i;
      }
    }
    else
    {
      result_out->m_feedCount = 2;
      strcpy(result_out->ma_feeds[0].ma_name,       "nvd");
      strcpy(result_out->ma_feeds[0].ma_lastSynced, "2026-05-22T10:05:00Z");
      strcpy(result_out->ma_feeds[0].ma_lastStatus, "ok");
      result_out->ma_feeds[0].m_recordsUpdated = 21874;
      strcpy(result_out->ma_feeds[1].ma_name,       "cwe");
      strcpy(result_out->ma_feeds[1].ma_lastStatus, "in_progress");
    }
  }
  else
  {
    result_out->m_cveCount = 251430;
  }
  return g_stub_HEALTH_status;
}

DbStatus_t g_stub_CVERISKSCORE_status = DB_NOT_FOUND;
char       g_stub_CVERISKSCORE_last_cve_id[CVELOOKUP_ID_MAX_LEN + 1] = { 0 };

DbStatus_t db_CVERISKSCORE(PGconn* conn, const char* cve_id, CVERISKSCORERecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  strncpy(g_stub_CVERISKSCORE_last_cve_id, cve_id, CVELOOKUP_ID_MAX_LEN);
  g_stub_CVERISKSCORE_last_cve_id[CVELOOKUP_ID_MAX_LEN] = '\0';
  memset(record_out, 0, sizeof(*record_out));

  if (g_stub_CVERISKSCORE_status == DB_OK)
  {
    record_out->m_score                      = 97.8;
    record_out->m_hasPublicPoc               = true;
    record_out->m_exploitabilityComponent    = 60.00;
    record_out->m_impactComponent            = 30.00;
    record_out->m_evidenceComponent          = 7.80;
    strncpy(record_out->ma_label, "CRITICAL", CVERISKSCORE_LABEL_LEN);
    record_out->ma_label[CVERISKSCORE_LABEL_LEN] = '\0';
  }
  return g_stub_CVERISKSCORE_status;
}

static void static_fillTriageItem(CVETRIAGEItem_t* it, const char* cve_id)
{
  memset(it, 0, sizeof(*it));
  strncpy(it->ma_cveId, cve_id ? cve_id : "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  it->ma_cveId[CVELOOKUP_ID_MAX_LEN] = '\0';
  it->m_riskScore = 96.5;
  strncpy(it->ma_label, "CRITICAL", CVERISKSCORE_LABEL_LEN);
  it->ma_label[CVERISKSCORE_LABEL_LEN] = '\0';
}

DbStatus_t g_stub_CVETRIAGE_status = DB_ERROR;

CVETRIAGEParams_t g_stub_CVETRIAGE_last_params = { 0 };
int               g_stub_CVETRIAGE_call_count  = 0;
int               g_stub_CVETRIAGE_item_count  = 1;

DbStatus_t db_CVETRIAGE(PGconn* conn, const CVETRIAGEParams_t* params, CVETRIAGEResult_t* results_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_CVETRIAGE_last_params = *params;
  g_stub_CVETRIAGE_call_count++;
  results_out->m_total  = 0;
  results_out->m_count  = 0;
  results_out->mp_items = NULL;
  if (g_stub_CVETRIAGE_status == DB_OK)
  {
    const int item_count = g_stub_CVETRIAGE_item_count;
    if (item_count > 0)
    {
      results_out->mp_items = calloc((size_t)item_count, sizeof(CVETRIAGEItem_t));
      if (!results_out->mp_items)
        return DB_ERROR;
      for (int i = 0; i < item_count; i++)
        static_fillTriageItem(&results_out->mp_items[i], "CVE-2021-44228");
    }
    results_out->m_total = item_count;
    results_out->m_count = item_count;
  }
  return g_stub_CVETRIAGE_status;
}

int g_stub_CVETRIAGEResultFree_call_count = 0;

void db_CVETRIAGEResultFree(CVETRIAGEResult_t* r)
{
  g_stub_CVETRIAGEResultFree_call_count++;
  if (!r) return;
  free(r->mp_items);
  r->mp_items = NULL;
}

DbStatus_t                    g_stub_WATCHLISTEDIT_status                                                   = DB_ERROR;
WATCHLISTEDITStatus_t         g_stub_WATCHLISTEDIT_result_status                                            = WATCHLISTEDIT_OK;
WATCHLISTEDITItemsDbParams_t  g_stub_WATCHLISTEDIT_last_params                                              = { 0 };
int                           g_stub_WATCHLISTEDIT_call_count                                               = 0;
char                          g_stub_WATCHLISTEDIT_last_registered_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
bool                          g_stub_WATCHLISTEDIT_last_has_registered_domain                               = false;
WATCHLISTEDITPackageElement_t g_stub_WATCHLISTEDIT_last_packages[STUB_WATCHLISTEDIT_PACKAGE_COPY_COUNT];
int                           g_stub_WATCHLISTEDIT_last_package_count                                       = 0;
WATCHLISTEDITPackageRepeat_t  g_stub_WATCHLISTEDIT_package_repeat                                           = { .m_currentIndex = -1, .m_earlierIndex = -1 };

DbStatus_t db_WATCHLISTEDITItems(PGconn* conn, const WATCHLISTEDITItemsDbParams_t* params, const char* registered_domain, WATCHLISTEDITItemsResult_t* result_out)
{
  g_stub_query_call_count++;
  (void)conn;
  memcpy(&g_stub_WATCHLISTEDIT_last_params, params, sizeof(g_stub_WATCHLISTEDIT_last_params));
  g_stub_WATCHLISTEDIT_last_has_registered_domain = registered_domain != NULL;
  snprintf(g_stub_WATCHLISTEDIT_last_registered_domain, sizeof(g_stub_WATCHLISTEDIT_last_registered_domain), "%s",
           registered_domain != NULL ? registered_domain : "");
  g_stub_WATCHLISTEDIT_call_count++;
  memset(g_stub_WATCHLISTEDIT_last_packages, 0, sizeof(g_stub_WATCHLISTEDIT_last_packages));
  g_stub_WATCHLISTEDIT_last_package_count = 0;
  memset(result_out, 0, sizeof(*result_out));
  result_out->m_status = WATCHLISTEDIT_OK;
  if (g_stub_WATCHLISTEDIT_status != DB_OK)
    return g_stub_WATCHLISTEDIT_status;

  result_out->m_status = g_stub_WATCHLISTEDIT_result_status;
  if (g_stub_WATCHLISTEDIT_result_status == WATCHLISTEDIT_UNKNOWN_KEY)
    return DB_OK;
  result_out->mp_items = calloc(2, sizeof(WatchlistItem_t));
  if (!result_out->mp_items)
    return DB_ERROR;
  WatchlistItem_t* cve = &result_out->mp_items[0];
  cve->m_itemKind = WATCHLIST_ITEM_CVE_LOOKUP;
  strncpy(cve->m_cveLookup.ma_cveId, "CVE-2021-44228", sizeof(cve->m_cveLookup.ma_cveId) - 1);
  WatchlistItem_t* product = &result_out->mp_items[1];
  product->m_itemKind = WATCHLIST_ITEM_PRODUCT_EXPOSURE;
  strncpy(product->m_productExposure.ma_vendor, "apache", sizeof(product->m_productExposure.ma_vendor) - 1);
  strncpy(product->m_productExposure.ma_product, "log4j", sizeof(product->m_productExposure.ma_product) - 1);
  strncpy(product->m_productExposure.ma_version, "2.14.1", sizeof(product->m_productExposure.ma_version) - 1);
  product->m_productExposure.m_hasCves    = true;
  result_out->m_itemCount                 = 2;
  result_out->m_itemCountForCurrentApiKey = 2;
  return DB_OK;
}

int g_stub_WATCHLISTEDITResultFree_call_count = 0;

void db_WATCHLISTEDITItemsResultFree(WATCHLISTEDITItemsResult_t* result)
{
  g_stub_WATCHLISTEDITResultFree_call_count++;
  if (!result) return;
  free(result->mp_items);
  result->mp_items = NULL;
}

DbStatus_t db_WATCHLISTEDITPackageList(PGconn* conn, const WATCHLISTEDITPackageListDbParams_t* params, WATCHLISTEDITPackageListResult_t* result_out)
{
  g_stub_query_call_count++;
  (void)conn;
  memset(&g_stub_WATCHLISTEDIT_last_params, 0, sizeof(g_stub_WATCHLISTEDIT_last_params));
  g_stub_WATCHLISTEDIT_last_params.mp_creditBudget = params->mp_creditBudget;
  g_stub_WATCHLISTEDIT_last_params.m_action        = params->m_action;
  g_stub_WATCHLISTEDIT_last_has_registered_domain  = false;
  g_stub_WATCHLISTEDIT_last_registered_domain[0]   = '\0';
  g_stub_WATCHLISTEDIT_call_count++;
  memset(g_stub_WATCHLISTEDIT_last_packages, 0, sizeof(g_stub_WATCHLISTEDIT_last_packages));
  g_stub_WATCHLISTEDIT_last_package_count = params->m_elementCount;
  for (int i = 0; i < params->m_elementCount && i < STUB_WATCHLISTEDIT_PACKAGE_COPY_COUNT; i++)
    g_stub_WATCHLISTEDIT_last_packages[i] = params->mp_elements[i];
  memset(result_out, 0, sizeof(*result_out));
  result_out->m_status = WATCHLISTEDIT_OK;
  if (g_stub_WATCHLISTEDIT_status != DB_OK)
    return g_stub_WATCHLISTEDIT_status;

  result_out->m_status = g_stub_WATCHLISTEDIT_result_status;
  if (g_stub_WATCHLISTEDIT_result_status == WATCHLISTEDIT_UNKNOWN_KEY)
    return DB_OK;
  result_out->m_action = params->m_action;
  if (g_stub_WATCHLISTEDIT_result_status == WATCHLISTEDIT_PACKAGE_PROBLEM)
  {
    if (g_stub_WATCHLISTEDIT_package_repeat.m_currentIndex < 0)
      return DB_OK;
    result_out->mp_repeatedPackages = calloc(1, sizeof(WATCHLISTEDITPackageRepeat_t));
    if (!result_out->mp_repeatedPackages)
      return DB_ERROR;
    result_out->mp_repeatedPackages[0] = g_stub_WATCHLISTEDIT_package_repeat;
    result_out->m_repeatedCount        = 1;
    return DB_OK;
  }
  bool is_add = params->m_action == WATCHLISTEDIT_ACTION_ADD;
  result_out->m_addedCount                       = is_add ? 1 : 0;
  result_out->m_removedCount                     = is_add ? 0 : 1;
  result_out->m_unchangedCount                   = 2;
  result_out->m_packageItemCountForCurrentApiKey = 3;
  return DB_OK;
}

void db_WATCHLISTEDITPackageListResultFree(WATCHLISTEDITPackageListResult_t* result)
{
  g_stub_WATCHLISTEDITResultFree_call_count++;
  if (!result) return;
  free(result->mp_repeatedPackages);
  result->mp_repeatedPackages = NULL;
}

DbStatus_t              g_stub_WATCHLISTEVENTS_status               = DB_ERROR;
WATCHLISTEVENTSStatus_t g_stub_WATCHLISTEVENTS_result_status        = WATCHLISTEVENTS_OK;
WATCHLISTEVENTSParams_t g_stub_WATCHLISTEVENTS_last_params          = { 0 };
int                     g_stub_WATCHLISTEVENTS_last_event_row_count = 0;
int                     g_stub_WATCHLISTEVENTS_call_count           = 0;

DbStatus_t db_WATCHLISTEVENTS(PGconn* conn, const WATCHLISTEVENTSParams_t* params, int event_row_count, WATCHLISTEVENTSResult_t* result_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_WATCHLISTEVENTS_last_params          = *params;
  g_stub_WATCHLISTEVENTS_last_event_row_count = event_row_count;
  g_stub_WATCHLISTEVENTS_call_count++;
  memset(result_out, 0, sizeof(*result_out));
  if (g_stub_WATCHLISTEVENTS_status != DB_OK)
    return g_stub_WATCHLISTEVENTS_status;

  result_out->m_status = g_stub_WATCHLISTEVENTS_result_status;
  if (g_stub_WATCHLISTEVENTS_result_status != WATCHLISTEVENTS_OK)
    return DB_OK;
  strncpy(result_out->ma_nextCursor, "58", sizeof(result_out->ma_nextCursor) - 1);
  result_out->mp_events                = calloc(4, sizeof(WATCHLISTEVENTSEvent_t));
  result_out->m_eventCount             = 4;
  result_out->mp_answerItems           = calloc(4, sizeof(WATCHLISTEVENTSAnswerItem_t));
  result_out->m_answerItemCount        = 4;
  result_out->mp_pairEventIndexes      = calloc(4, sizeof(int));
  result_out->mp_pairIsVersionAffected = calloc(4, sizeof(bool));
  result_out->m_pairCount              = 4;
  result_out->mp_cveFacts              = calloc(2, sizeof(WATCHLISTEVENTSCveFacts_t));
  result_out->m_cveFactCount           = 2;
  result_out->mp_domainFacts           = calloc(1, sizeof(WATCHLISTEVENTSDomainFacts_t));
  result_out->m_domainFactCount        = 1;
  result_out->mp_advisories            = calloc(1, sizeof(WATCHLISTPACKAGECHECKAdvisory_t));
  result_out->m_advisoryCount          = 1;
  if (!result_out->mp_events || !result_out->mp_answerItems || !result_out->mp_pairEventIndexes || !result_out->mp_pairIsVersionAffected ||
      !result_out->mp_cveFacts || !result_out->mp_domainFacts || !result_out->mp_advisories)
  {
    db_WATCHLISTEVENTSResultFree(result_out);
    return DB_ERROR;
  }

  WATCHLISTEVENTSAnswerItem_t* cve_item = &result_out->mp_answerItems[0];
  cve_item->m_item.m_itemKind = WATCHLIST_ITEM_CVE_LOOKUP;
  strncpy(cve_item->m_item.m_cveLookup.ma_cveId, "CVE-2021-44228", sizeof(cve_item->m_item.m_cveLookup.ma_cveId) - 1);
  cve_item->m_firstPairIndex = 0;
  cve_item->m_pairCount      = 1;
  WATCHLISTEVENTSAnswerItem_t* domain_item = &result_out->mp_answerItems[1];
  domain_item->m_item.m_itemKind = WATCHLIST_ITEM_DNS_LOOKUP;
  strncpy(domain_item->m_item.m_dnsLookup.ma_domainName, "example.com", sizeof(domain_item->m_item.m_dnsLookup.ma_domainName) - 1);
  domain_item->m_firstPairIndex = 1;
  domain_item->m_pairCount      = 1;
  WATCHLISTEVENTSAnswerItem_t* package_item = &result_out->mp_answerItems[2];
  package_item->m_item.m_itemKind = WATCHLIST_ITEM_PACKAGE_CHECK;
  WATCHLISTPACKAGECHECKItem_t* package = &package_item->m_item.m_packageCheck;
  strncpy(package->ma_ecosystem, "npm", sizeof(package->ma_ecosystem) - 1);
  strncpy(package->ma_name, "lodash", sizeof(package->ma_name) - 1);
  strncpy(package->ma_version, "4.17.20", sizeof(package->ma_version) - 1);
  package_item->m_firstPairIndex = 2;
  package_item->m_pairCount      = 1;
  WATCHLISTEVENTSAnswerItem_t* product_item = &result_out->mp_answerItems[3];
  product_item->m_item.m_itemKind = WATCHLIST_ITEM_PRODUCT_EXPOSURE;
  WATCHLISTPRODUCTEXPOSUREItem_t* product = &product_item->m_item.m_productExposure;
  strncpy(product->ma_vendor, "f5", sizeof(product->ma_vendor) - 1);
  strncpy(product->ma_product, "nginx", sizeof(product->ma_product) - 1);
  strncpy(product->ma_version, "1.24.0", sizeof(product->ma_version) - 1);
  product->m_hasCves = true;
  product_item->m_firstPairIndex = 3;
  product_item->m_pairCount      = 1;
  result_out->mp_pairEventIndexes[0]      = 0;
  result_out->mp_pairEventIndexes[1]      = 1;
  result_out->mp_pairEventIndexes[2]      = 2;
  result_out->mp_pairEventIndexes[3]      = 3;
  result_out->mp_pairIsVersionAffected[2] = true;

  WATCHLISTEVENTSEvent_t* event = &result_out->mp_events[0];
  strncpy(event->ma_eventType, "kev_added", sizeof(event->ma_eventType) - 1);
  strncpy(event->ma_changedAt, "2026-10-15T08:09:10Z", sizeof(event->ma_changedAt) - 1);
  strncpy(event->m_cveChange.ma_cveId, "CVE-2021-44228", sizeof(event->m_cveChange.ma_cveId) - 1);
  WATCHLISTEVENTSEvent_t* domain_event = &result_out->mp_events[1];
  strncpy(domain_event->ma_eventType, "ns_changed", sizeof(domain_event->ma_eventType) - 1);
  strncpy(domain_event->ma_changedAt, "2026-10-15T08:09:11Z", sizeof(domain_event->ma_changedAt) - 1);
  domain_event->m_eventKind                        = WATCHLIST_EVENT_DNS_LOOKUP;
  domain_event->m_dnsLookupChange.mp_previousValue = strdup("ns1.example.net\nns2.example.net");
  domain_event->m_dnsLookupChange.mp_currentValue  = strdup("ns1.example.org");
  WATCHLISTEVENTSEvent_t* package_event = &result_out->mp_events[2];
  strncpy(package_event->ma_eventType, "fix_available", sizeof(package_event->ma_eventType) - 1);
  strncpy(package_event->ma_changedAt, "2026-10-15T08:09:12Z", sizeof(package_event->ma_changedAt) - 1);
  package_event->m_eventKind = WATCHLIST_EVENT_PACKAGE_CHECK;
  WATCHLISTPACKAGECHECKChange_t* package_change = &package_event->m_packageCheckChange;
  strncpy(package_change->ma_advisoryId, "GHSA-p6mc-m468-83gw", sizeof(package_change->ma_advisoryId) - 1);
  strncpy(package_change->ma_fixedVersion, "4.17.21", sizeof(package_change->ma_fixedVersion) - 1);
  WATCHLISTEVENTSEvent_t* eol_event = &result_out->mp_events[3];
  strncpy(eol_event->ma_eventType, "eol_date_changed", sizeof(eol_event->ma_eventType) - 1);
  strncpy(eol_event->ma_changedAt, "2026-10-15T08:09:13Z", sizeof(eol_event->ma_changedAt) - 1);
  eol_event->m_eventKind = WATCHLIST_EVENT_PRODUCT_EXPOSURE;
  WATCHLISTPRODUCTEXPOSUREChange_t* eol_change = &eol_event->m_productExposureChange;
  strncpy(eol_change->ma_eolProduct, "nginx", sizeof(eol_change->ma_eolProduct) - 1);
  strncpy(eol_change->ma_cycle, "1.24", sizeof(eol_change->ma_cycle) - 1);
  memcpy(eol_change->ma_eolDate, "2027-05-31", sizeof("2027-05-31"));
  memcpy(eol_change->ma_previousEolDate, "2026-11-30", sizeof("2026-11-30"));

  WATCHLISTEVENTSCveFacts_t* facts = &result_out->mp_cveFacts[0];
  strncpy(facts->ma_cveId, "CVE-2021-44228", sizeof(facts->ma_cveId) - 1);
  facts->m_riskScore = 96.5;
  strncpy(facts->ma_riskLabel, "CRITICAL", sizeof(facts->ma_riskLabel) - 1);
  facts->m_isInKev = true;
  facts->m_hasKev  = true;
  strncpy(facts->ma_kevPatchDeadline, "2021-12-24", sizeof(facts->ma_kevPatchDeadline) - 1);
  facts->m_kevKnownRansomware = true;
  facts->m_hasMetasploit      = false;
  facts->m_pocCount           = 3;
  WATCHLISTEVENTSCveFacts_t* alias_facts = &result_out->mp_cveFacts[1];
  strncpy(alias_facts->ma_cveId, "CVE-2020-8203", sizeof(alias_facts->ma_cveId) - 1);
  alias_facts->m_riskScore = 74.0;
  strncpy(alias_facts->ma_riskLabel, "HIGH", sizeof(alias_facts->ma_riskLabel) - 1);
  alias_facts->m_hasMetasploit = true;
  alias_facts->m_pocCount      = 9;

  WATCHLISTPACKAGECHECKAdvisory_t* advisory = &result_out->mp_advisories[0];
  strncpy(advisory->ma_advisoryId, "GHSA-p6mc-m468-83gw", sizeof(advisory->ma_advisoryId) - 1);
  strncpy(advisory->ma_source, "ghsa", sizeof(advisory->ma_source) - 1);
  advisory->mp_aliases       = strdup("[\"CVE-2020-8203\"]");
  result_out->mp_attribution = strdup("[{\"source\":\"endoflife.date\",\"license\":\"MIT\"},{\"source\":\"ghsa\",\"license\":\"CC-BY-4.0\"}]");

  WATCHLISTEVENTSDomainFacts_t* domain_facts = &result_out->mp_domainFacts[0];
  strncpy(domain_facts->ma_domainName, "example.com", sizeof(domain_facts->ma_domainName) - 1);
  strncpy(domain_facts->ma_registeredDomain, "example.com", sizeof(domain_facts->ma_registeredDomain) - 1);
  WATCHLISTDNSLOOKUPFacts_t* dns_facts = &domain_facts->m_dnsFacts;
  dns_facts->mp_dnsPresenceValue           = strdup("found");
  dns_facts->mp_nsValue                    = strdup("ns1.example.org");
  dns_facts->mp_mxValue                    = strdup("10 mx.example.com");
  dns_facts->mp_ipAddressReachabilityValue = strdup("public");
  dns_facts->mp_cnameTakeoverValue         = strdup("none");
  dns_facts->mp_emailAuthValue             = strdup("ppppppppfwppppppppppp");
  if (!domain_event->m_dnsLookupChange.mp_previousValue || !domain_event->m_dnsLookupChange.mp_currentValue || !dns_facts->mp_dnsPresenceValue ||
      !dns_facts->mp_nsValue || !dns_facts->mp_mxValue || !dns_facts->mp_ipAddressReachabilityValue ||
      !dns_facts->mp_cnameTakeoverValue || !dns_facts->mp_emailAuthValue || !advisory->mp_aliases || !result_out->mp_attribution)
  {
    db_WATCHLISTEVENTSResultFree(result_out);
    return DB_ERROR;
  }
  return DB_OK;
}

int g_stub_WATCHLISTEVENTSResultFree_call_count = 0;

void db_WATCHLISTEVENTSResultFree(WATCHLISTEVENTSResult_t* result)
{
  g_stub_WATCHLISTEVENTSResultFree_call_count++;
  if (!result) return;
  for (int i = 0; result->mp_events && i < result->m_eventCount; i++)
  {
    WATCHLISTEVENTSEvent_t* event = &result->mp_events[i];
    if (event->m_eventKind != WATCHLIST_EVENT_DNS_LOOKUP)
      continue;
    free(event->m_dnsLookupChange.mp_previousValue);
    free(event->m_dnsLookupChange.mp_currentValue);
  }
  for (int i = 0; result->mp_domainFacts && i < result->m_domainFactCount; i++)
  {
    WATCHLISTDNSLOOKUPFacts_t* dns_facts = &result->mp_domainFacts[i].m_dnsFacts;
    free(dns_facts->mp_dnsPresenceValue);
    free(dns_facts->mp_nsValue);
    free(dns_facts->mp_mxValue);
    free(dns_facts->mp_ipAddressReachabilityValue);
    free(dns_facts->mp_cnameTakeoverValue);
    free(dns_facts->mp_emailAuthValue);
  }
  for (int i = 0; result->mp_advisories && i < result->m_advisoryCount; i++)
    free(result->mp_advisories[i].mp_aliases);
  free(result->mp_events);
  free(result->mp_answerItems);
  free(result->mp_pairEventIndexes);
  free(result->mp_pairIsVersionAffected);
  free(result->mp_cveFacts);
  free(result->mp_domainFacts);
  free(result->mp_advisories);
  free(result->mp_attribution);
  memset(result, 0, sizeof(*result));
}

DbStatus_t              g_stub_PRODUCTEXPOSURE_status      = DB_ERROR;
PRODUCTEXPOSUREParams_t g_stub_PRODUCTEXPOSURE_last_params = { 0 };

DbStatus_t db_PRODUCTEXPOSURE(PGconn* conn, const PRODUCTEXPOSUREParams_t* params, PRODUCTEXPOSURERecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_PRODUCTEXPOSURE_last_params = *params;
  memset(record_out, 0, sizeof(*record_out));
  snprintf(record_out->ma_vendor,  sizeof(record_out->ma_vendor),  "%s", params->ma_vendor);
  snprintf(record_out->ma_product, sizeof(record_out->ma_product), "%s", params->ma_product);

  if (g_stub_PRODUCTEXPOSURE_status == DB_OK)
  {
    record_out->m_totalCveCount  = 42;
    record_out->m_criticalCount  = 10;
    record_out->m_highCount      = 20;
    record_out->m_mediumCount    = 8;
    record_out->m_lowCount       = 4;
    record_out->m_kevCount       = 7;
    record_out->m_maxCvss        = 9.8;
    record_out->m_avgCvss        = 6.42;
    record_out->m_maxEpss        = 0.97531;
    record_out->m_pocBackedCount = 12;
    record_out->m_worstRiskScore = 96.5;
    strncpy(record_out->ma_mostRecentPublished, "2024-01-15T00:00:00Z", CVELOOKUP_PUBLISHED_LEN);
    record_out->ma_mostRecentPublished[CVELOOKUP_PUBLISHED_LEN] = '\0';
    static_fillTriageItem(&record_out->ma_topCves[0], "CVE-2021-44228");
    static_fillTriageItem(&record_out->ma_topCves[1], "CVE-2014-0160");
    record_out->m_topCveCount = 2;
  }
  return g_stub_PRODUCTEXPOSURE_status;
}

DbStatus_t g_stub_CVETRIAGEBULK_status   = DB_ERROR;
int        g_stub_CVETRIAGEBULK_found    = -1;
int        g_stub_CVETRIAGEBULK_id_count = 0;

DbStatus_t db_CVETRIAGEBULK(PGconn* conn, const BulkIdsParams_t* params, CVETRIAGEBULKResult_t* results_out)
{
  g_stub_query_call_count++;
  (void)conn;
  int id_count = params->m_idCount;
  g_stub_CVETRIAGEBULK_id_count += id_count;
  results_out->m_successful = 0;
  results_out->m_failed     = 0;
  results_out->mp_items     = NULL;
  if (g_stub_CVETRIAGEBULK_status == DB_OK)
  {
    int found = (g_stub_CVETRIAGEBULK_found < 0 || g_stub_CVETRIAGEBULK_found > id_count)
              ? id_count : g_stub_CVETRIAGEBULK_found;
    if (found > 0)
    {
      results_out->mp_items = calloc((size_t)found, sizeof(CVETRIAGEItem_t));
      if (!results_out->mp_items)
        return DB_ERROR;
      for (int i = 0; i < found; i++)
        static_fillTriageItem(&results_out->mp_items[i], params->ma_ids[i]);
    }
    results_out->m_successful = found;
    results_out->m_failed     = id_count - found;
  }
  return g_stub_CVETRIAGEBULK_status;
}

int g_stub_CVETRIAGEBULKResultFree_call_count = 0;

void db_CVETRIAGEBULKResultFree(CVETRIAGEBULKResult_t* r)
{
  g_stub_CVETRIAGEBULKResultFree_call_count++;
  if (!r) return;
  free(r->mp_items);
  r->mp_items = NULL;
}

DbStatus_t        g_stub_CPESEARCH_status               = DB_ERROR;
CPESEARCHParams_t g_stub_CPESEARCH_last_params          = { 0 };
int               g_stub_CPESEARCH_call_count           = 0;
int               g_stub_CPESEARCH_item_count           = 1;
int               g_stub_CPESEARCHResultFree_call_count = 0;

DbStatus_t db_CPESEARCH(PGconn* conn, const CPESEARCHParams_t* params, CPESEARCHResult_t* results_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_CPESEARCH_last_params = *params;
  g_stub_CPESEARCH_call_count++;
  results_out->m_total  = 0;
  results_out->m_count  = 0;
  results_out->mp_items = NULL;
  if (g_stub_CPESEARCH_status == DB_OK)
  {
    const int item_count = g_stub_CPESEARCH_item_count;
    if (item_count > 0)
    {
      results_out->mp_items = calloc((size_t)item_count, sizeof(CPESEARCHItem_t));
      if (!results_out->mp_items)
        return DB_ERROR;
      results_out->m_count = item_count;
      for (int i = 0; i < item_count; i++)
      {
        strncpy(results_out->mp_items[i].ma_vendor,  "notepad-plus-plus", CVESEARCH_VENDOR_LEN);
        strncpy(results_out->mp_items[i].ma_product, "notepad\\+\\+",     CVESEARCH_PRODUCT_LEN);
        results_out->mp_items[i].m_vulnerableCveCount = 7;
        results_out->mp_items[i].mp_productNamedBy = strdup("[\"cna\", \"nvd\"]");
        if (!results_out->mp_items[i].mp_productNamedBy)
        {
          db_CPESEARCHResultFree(results_out);
          return DB_ERROR;
        }
      }
    }
    results_out->m_total = item_count;
    results_out->m_count = item_count;
  }
  return g_stub_CPESEARCH_status;
}

void db_CPESEARCHResultFree(CPESEARCHResult_t* r)
{
  g_stub_CPESEARCHResultFree_call_count++;
  if (!r) return;
  for (int i = 0; i < r->m_count; i++)
    free(r->mp_items[i].mp_productNamedBy);
  free(r->mp_items);
  r->mp_items = NULL;
  r->m_count  = 0;
}

DbStatus_t g_stub_D3FENDFORATTACK_status                         = DB_ERROR;
char       g_stub_D3FENDFORATTACK_last_id[ATTACK_TECHNIQUE_ID_MAX_LEN + 1] = "";
int        g_stub_D3FENDFORATTACK_call_count                     = 0;
int        g_stub_D3FENDFORATTACK_defense_count                  = 2;
int        g_stub_D3FENDFORATTACKResultFree_call_count           = 0;

static const D3FENDFORATTACKItem_t D3FENDFORATTACK_STUB_DEFENSES[] = {
  { .ma_defenseId = "Multi-factorAuthentication", .ma_defenseLabel = "Multi-factor \"Authentication\\",
    .ma_defenseTactic = "Harden", .ma_digitalArtifact = "" },
  { .ma_defenseId = "SystemCallAnalysis", .ma_defenseLabel = "System Call Analysis",
    .ma_defenseTactic = "Detect", .ma_digitalArtifact = "System Call" },
};
static const char* const D3FENDFORATTACK_STUB_PARENT_LABELS[] = { "[]", R"(["Process Analysis"])" };

DbStatus_t db_D3FENDFORATTACK(PGconn* conn, const char* attack_technique_id, D3FENDFORATTACKResult_t* result_out)
{
  g_stub_query_call_count++;
  (void)conn;
  snprintf(g_stub_D3FENDFORATTACK_last_id, sizeof(g_stub_D3FENDFORATTACK_last_id), "%s", attack_technique_id);
  g_stub_D3FENDFORATTACK_call_count++;
  memset(result_out, 0, sizeof(*result_out));
  if (g_stub_D3FENDFORATTACK_status != DB_OK || g_stub_D3FENDFORATTACK_defense_count <= 0)
    return g_stub_D3FENDFORATTACK_status;

  const int defense_count = g_stub_D3FENDFORATTACK_defense_count;
  result_out->mp_defenses = calloc((size_t)defense_count, sizeof(D3FENDFORATTACKItem_t));
  result_out->mp_attackTechniques = strdup(R"([{"attack_technique_id":"T1055.012","subtechnique_of":"T1055","attack_label":"Process Hollowing"}])");
  if (!result_out->mp_defenses || !result_out->mp_attackTechniques)
  {
    db_D3FENDFORATTACKResultFree(result_out);
    return DB_ERROR;
  }
  result_out->m_defenseCount = defense_count;
  for (int i = 0; i < defense_count; i++)
  {
    result_out->mp_defenses[i] = D3FENDFORATTACK_STUB_DEFENSES[i % 2];
    result_out->mp_defenses[i].mp_parentDefenseLabels = strdup(D3FENDFORATTACK_STUB_PARENT_LABELS[i % 2]);
    result_out->mp_defenses[i].mp_attackTechniqueIds  = strdup(R"(["T1055.012"])");
    if (!result_out->mp_defenses[i].mp_parentDefenseLabels || !result_out->mp_defenses[i].mp_attackTechniqueIds)
    {
      db_D3FENDFORATTACKResultFree(result_out);
      return DB_ERROR;
    }
  }
  return DB_OK;
}

void db_D3FENDFORATTACKResultFree(D3FENDFORATTACKResult_t* result)
{
  g_stub_D3FENDFORATTACKResultFree_call_count++;
  if (!result) return;
  for (int i = 0; i < result->m_defenseCount; i++)
  {
    free(result->mp_defenses[i].mp_parentDefenseLabels);
    free(result->mp_defenses[i].mp_attackTechniqueIds);
  }
  free(result->mp_defenses);
  free(result->mp_attackTechniques);
  memset(result, 0, sizeof(*result));
}

DbStatus_t g_stub_DRIVERLOOKUP_status                                 = DB_ERROR;
char       g_stub_DRIVERLOOKUP_last_hash[VALIDATE_SHA256_HEX_LEN + 1] = "";
bool       g_stub_DRIVERLOOKUP_last_is_command_included               = false;
int        g_stub_DRIVERLOOKUP_call_count                             = 0;
int        g_stub_DRIVERLOOKUP_match_count                            = 1;
bool       g_stub_DRIVERLOOKUP_is_driver_feed_loaded                  = true;
int        g_stub_DRIVERLOOKUPRecordFree_call_count                   = 0;

DbStatus_t db_DRIVERLOOKUP(PGconn* conn, const char* file_hash, bool is_command_included, DRIVERLOOKUPRecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  snprintf(g_stub_DRIVERLOOKUP_last_hash, sizeof(g_stub_DRIVERLOOKUP_last_hash), "%s", file_hash);
  g_stub_DRIVERLOOKUP_last_is_command_included = is_command_included;
  g_stub_DRIVERLOOKUP_call_count++;
  memset(record_out, 0, sizeof(*record_out));
  if (g_stub_DRIVERLOOKUP_status != DB_OK)
    return g_stub_DRIVERLOOKUP_status;

  for (size_t i = 0; file_hash[i] != '\0' && i < VALIDATE_SHA256_HEX_LEN; i++)
    record_out->ma_fileHash[i] = (char)tolower((unsigned char)file_hash[i]);
  record_out->m_matchCount         = g_stub_DRIVERLOOKUP_match_count;
  record_out->m_isDriverFeedLoaded = g_stub_DRIVERLOOKUP_is_driver_feed_loaded;
  record_out->mp_matches           = strdup(g_stub_DRIVERLOOKUP_match_count > 0 ? DRIVERLOOKUP_STUB_MATCHES : "[]");
  if (!record_out->mp_matches)
    return DB_ERROR;
  return DB_OK;
}

void db_DRIVERLOOKUPRecordFree(DRIVERLOOKUPRecord_t* record)
{
  g_stub_DRIVERLOOKUPRecordFree_call_count++;
  if (!record) return;
  free(record->mp_matches);
  record->mp_matches = NULL;
}

DbStatus_t g_stub_IPLOOKUP_status                              = DB_ERROR;
char       g_stub_IPLOOKUP_last_ip_address[INET6_ADDRSTRLEN]   = "";
int        g_stub_IPLOOKUP_call_count                          = 0;
int        g_stub_IPLOOKUPRecordFree_call_count                = 0;

DbStatus_t db_IPLOOKUP(PGconn* conn, const char* ip_address, IPLOOKUPRecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  snprintf(g_stub_IPLOOKUP_last_ip_address, sizeof(g_stub_IPLOOKUP_last_ip_address), "%s", ip_address);
  g_stub_IPLOOKUP_call_count++;
  record_out->mp_listedOn = NULL;
  if (g_stub_IPLOOKUP_status != DB_OK)
    return g_stub_IPLOOKUP_status;

  snprintf(record_out->ma_ipAddress, sizeof(record_out->ma_ipAddress), "%s", ip_address);
  record_out->m_asn                  = 13335;
  snprintf(record_out->ma_asnName, sizeof(record_out->ma_asnName), "%s", "CLOUDFLARENET");
  snprintf(record_out->ma_asnCountry, sizeof(record_out->ma_asnCountry), "%s", "US");
  snprintf(record_out->ma_geoCountry, sizeof(record_out->ma_geoCountry), "%s", "AU");
  snprintf(record_out->ma_cloudProvider, sizeof(record_out->ma_cloudProvider), "%s", "cloudflare");
  snprintf(record_out->ma_cloudService, sizeof(record_out->ma_cloudService), "%s", "cdn");
  record_out->m_isCdn                = true;
  record_out->m_isDatacenter         = true;
  record_out->m_isTorExit            = false;
  record_out->m_isAsnFeedLoaded      = true;
  record_out->m_isGeoFeedLoaded      = true;
  record_out->m_isCloudFeedLoaded    = true;
  record_out->m_isTorFeedLoaded      = true;
  record_out->m_isDropListFeedLoaded = true;
  record_out->mp_listedOn            = strdup(IPLOOKUP_STUB_LISTED_ON);
  if (!record_out->mp_listedOn)
    return DB_ERROR;
  return DB_OK;
}

void db_IPLOOKUPRecordFree(IPLOOKUPRecord_t* record)
{
  g_stub_IPLOOKUPRecordFree_call_count++;
  if (!record) return;
  free(record->mp_listedOn);
  record->mp_listedOn = NULL;
}

DbStatus_t        g_stub_ASNLOOKUP_status               = DB_ERROR;
ASNLOOKUPParams_t g_stub_ASNLOOKUP_last_params;
int               g_stub_ASNLOOKUP_call_count           = 0;
int               g_stub_ASNLOOKUPRecordFree_call_count = 0;

DbStatus_t db_ASNLOOKUP(PGconn* conn, const ASNLOOKUPParams_t* params, ASNLOOKUPRecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_ASNLOOKUP_last_params = *params;
  g_stub_ASNLOOKUP_call_count++;
  record_out->mp_ipv4Prefixes = NULL;
  record_out->mp_ipv6Prefixes = NULL;
  if (g_stub_ASNLOOKUP_status != DB_OK)
    return g_stub_ASNLOOKUP_status;

  record_out->m_asn = 13335;
  snprintf(record_out->ma_asnName, sizeof(record_out->ma_asnName), "%s", "CLOUDFLARENET");
  snprintf(record_out->ma_asnCountry, sizeof(record_out->ma_asnCountry), "%s", "US");
  snprintf(record_out->ma_prefix, sizeof(record_out->ma_prefix), "%s",
           strncmp(params->ma_target, "AS", 2) == 0 ? "" : ASNLOOKUP_STUB_PREFIX);
  record_out->m_ipv4PrefixCount = 1789;
  record_out->m_ipv6PrefixCount = 214;
  record_out->mp_ipv4Prefixes   = strdup(ASNLOOKUP_STUB_IPV4_PREFIXES);
  record_out->mp_ipv6Prefixes   = strdup(ASNLOOKUP_STUB_IPV6_PREFIXES);
  if (!record_out->mp_ipv4Prefixes || !record_out->mp_ipv6Prefixes)
  {
    db_ASNLOOKUPRecordFree(record_out);
    return DB_ERROR;
  }
  return DB_OK;
}

void db_ASNLOOKUPRecordFree(ASNLOOKUPRecord_t* record)
{
  g_stub_ASNLOOKUPRecordFree_call_count++;
  if (!record) return;
  free(record->mp_ipv4Prefixes);
  record->mp_ipv4Prefixes = NULL;
  free(record->mp_ipv6Prefixes);
  record->mp_ipv6Prefixes = NULL;
}

DbStatus_t g_stub_EMAILADDRESSCHECK_status                                    = DB_ERROR;
bool       g_stub_EMAILADDRESSCHECK_is_feed_loaded                            = true;
char       g_stub_EMAILADDRESSCHECK_listed_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1] = "";
char       g_stub_EMAILADDRESSCHECK_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1]   = "";
int        g_stub_EMAILADDRESSCHECK_call_count                                = 0;

DbStatus_t db_EMAILADDRESSCHECK(PGconn* conn, const char* domain, EMAILADDRESSCHECKRecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  snprintf(g_stub_EMAILADDRESSCHECK_last_domain, sizeof(g_stub_EMAILADDRESSCHECK_last_domain), "%s", domain);
  g_stub_EMAILADDRESSCHECK_call_count++;
  record_out->m_isDisposableFeedLoaded     = false;
  record_out->ma_disposableListedDomain[0] = '\0';
  if (g_stub_EMAILADDRESSCHECK_status != DB_OK)
    return g_stub_EMAILADDRESSCHECK_status;

  record_out->m_isDisposableFeedLoaded = g_stub_EMAILADDRESSCHECK_is_feed_loaded;
  snprintf(record_out->ma_disposableListedDomain, sizeof(record_out->ma_disposableListedDomain), "%s", g_stub_EMAILADDRESSCHECK_listed_domain);
  return DB_OK;
}

DbStatus_t g_stub_SSLCHECK_status                                                       = DB_OK;
bool       g_stub_SSLCHECK_is_feed_loaded                                               = true;
char       g_stub_SSLCHECK_listing_reason[SSLCHECK_BLACKLIST_LISTING_REASON_MAX_LEN + 1] = "";
char       g_stub_SSLCHECK_listing_time[TLSPROBE_TIME_TEXT_SIZE]                         = "";
char       g_stub_SSLCHECK_last_sha1[TLSPROBE_CERTIFICATE_SHA1_HEX_SIZE]                 = "";
int        g_stub_SSLCHECK_call_count                                                   = 0;

DbStatus_t db_SSLCHECK(PGconn* conn, const char* sha1_hex, SSLCHECKRecord_t* record_out)
{
  g_stub_query_call_count++;
  (void)conn;
  snprintf(g_stub_SSLCHECK_last_sha1, sizeof(g_stub_SSLCHECK_last_sha1), "%s", sha1_hex);
  g_stub_SSLCHECK_call_count++;
  record_out->m_isBlacklistFeedLoaded      = false;
  record_out->ma_blacklistListingReason[0] = '\0';
  record_out->ma_blacklistListingTime[0]   = '\0';
  if (g_stub_SSLCHECK_status != DB_OK)
    return g_stub_SSLCHECK_status;

  record_out->m_isBlacklistFeedLoaded = g_stub_SSLCHECK_is_feed_loaded;
  snprintf(record_out->ma_blacklistListingReason, sizeof(record_out->ma_blacklistListingReason), "%s", g_stub_SSLCHECK_listing_reason);
  snprintf(record_out->ma_blacklistListingTime, sizeof(record_out->ma_blacklistListingTime), "%s", g_stub_SSLCHECK_listing_time);
  return DB_OK;
}

DbStatus_t          g_stub_CVEPRODUCTS_status                = DB_ERROR;
CVEPRODUCTSParams_t g_stub_CVEPRODUCTS_last_params;
int                 g_stub_CVEPRODUCTS_call_count            = 0;
int                 g_stub_CVEPRODUCTSResultFree_call_count  = 0;

DbStatus_t db_CVEPRODUCTS(PGconn* conn, const CVEPRODUCTSParams_t* params, CVEPRODUCTSResult_t* result_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_CVEPRODUCTS_last_params = *params;
  g_stub_CVEPRODUCTS_call_count++;
  memset(result_out, 0, sizeof(*result_out));
  if (g_stub_CVEPRODUCTS_status != DB_OK)
    return g_stub_CVEPRODUCTS_status;

  result_out->m_affectedProductCount = CVEPRODUCTS_STUB_AFFECTED_PRODUCT_COUNT;
  result_out->m_listedProductCount   = 1;
  result_out->mp_affectedProducts    = strdup(CVEPRODUCTS_STUB_PRODUCTS);
  if (!result_out->mp_affectedProducts)
    return DB_ERROR;
  return DB_OK;
}

void db_CVEPRODUCTSResultFree(CVEPRODUCTSResult_t* result)
{
  g_stub_CVEPRODUCTSResultFree_call_count++;
  if (!result) return;
  free(result->mp_affectedProducts);
  result->mp_affectedProducts = NULL;
}

DbStatus_t           g_stub_PACKAGECHECK_status                  = DB_ERROR;
PACKAGECHECKParams_t g_stub_PACKAGECHECK_last_params;
int                  g_stub_PACKAGECHECK_call_count              = 0;
bool                 g_stub_PACKAGECHECK_is_advisory_feed_loaded = true;
int                  g_stub_PACKAGECHECKResultFree_call_count    = 0;

DbStatus_t db_PACKAGECHECK(PGconn* conn, const PACKAGECHECKParams_t* params, PACKAGECHECKResult_t* result_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_PACKAGECHECK_last_params = *params;
  g_stub_PACKAGECHECK_call_count++;
  memset(result_out, 0, sizeof(*result_out));
  if (g_stub_PACKAGECHECK_status != DB_OK)
    return g_stub_PACKAGECHECK_status;

  result_out->m_isAdvisoryFeedLoaded = g_stub_PACKAGECHECK_is_advisory_feed_loaded;
  result_out->m_hasAdvisoryData      = true;
  result_out->m_resultCount          = 1;
  snprintf(result_out->ma_fixedVersion, sizeof(result_out->ma_fixedVersion), "%s", PACKAGECHECK_STUB_FIXED_VERSION);
  result_out->mp_malicious   = strdup(PACKAGECHECK_STUB_MALICIOUS);
  result_out->mp_results     = strdup(PACKAGECHECK_STUB_RESULTS);
  result_out->mp_attribution = strdup(PACKAGECHECK_STUB_ATTRIBUTION);
  if (!result_out->mp_malicious || !result_out->mp_results || !result_out->mp_attribution)
    return DB_ERROR;
  return DB_OK;
}

void db_PACKAGECHECKResultFree(PACKAGECHECKResult_t* result)
{
  g_stub_PACKAGECHECKResultFree_call_count++;
  if (!result) return;
  free(result->mp_malicious);
  free(result->mp_results);
  free(result->mp_attribution);
  result->mp_malicious   = NULL;
  result->mp_results     = NULL;
  result->mp_attribution = NULL;
}

DbStatus_t             g_stub_PACKAGECHECKBULK_status               = DB_ERROR;
int                    g_stub_PACKAGECHECKBULK_failed_item_count    = 0;
PACKAGECHECKBULKItem_t g_stub_PACKAGECHECKBULK_last_items[PACKAGECHECKBULK_MAX_ITEMS];
int                    g_stub_PACKAGECHECKBULK_last_item_count      = 0;
int                    g_stub_PACKAGECHECKBULK_call_count           = 0;
int                    g_stub_PACKAGECHECKBULKResultFree_call_count = 0;

DbStatus_t db_PACKAGECHECKBULK(PGconn* conn, const PACKAGECHECKBULKItem_t* items, int item_count, PACKAGECHECKBULKResult_t* result_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_PACKAGECHECKBULK_call_count++;
  g_stub_PACKAGECHECKBULK_last_item_count = item_count;
  memcpy(g_stub_PACKAGECHECKBULK_last_items, items, (size_t)item_count * sizeof(items[0]));
  result_out->m_successful   = 0;
  result_out->m_failed       = 0;
  result_out->mp_results     = NULL;
  result_out->mp_attribution = NULL;
  if (g_stub_PACKAGECHECKBULK_status != DB_OK)
    return g_stub_PACKAGECHECKBULK_status;

  result_out->m_isAdvisoryFeedLoaded = g_stub_PACKAGECHECK_is_advisory_feed_loaded;
  result_out->mp_results             = strdup(PACKAGECHECKBULK_STUB_RESULTS);
  result_out->mp_attribution         = strdup(PACKAGECHECKBULK_STUB_ATTRIBUTION);
  if (!result_out->mp_results || !result_out->mp_attribution)
    return DB_ERROR;
  result_out->m_successful = item_count - g_stub_PACKAGECHECKBULK_failed_item_count;
  result_out->m_failed     = g_stub_PACKAGECHECKBULK_failed_item_count;
  return DB_OK;
}

void db_PACKAGECHECKBULKResultFree(PACKAGECHECKBULKResult_t* result)
{
  g_stub_PACKAGECHECKBULKResultFree_call_count++;
  if (!result) return;
  free(result->mp_results);
  free(result->mp_attribution);
  result->mp_results     = NULL;
  result->mp_attribution = NULL;
}

DbStatus_t             g_stub_PACKAGECHECKBULKWeigh_status            = DB_OK;
int                    g_stub_PACKAGECHECKBULKWeigh_served_item_count = -1;
PACKAGECHECKBULKItem_t g_stub_PACKAGECHECKBULKWeigh_last_items[PACKAGECHECKBULK_MAX_ITEMS];
int                    g_stub_PACKAGECHECKBULKWeigh_last_item_count   = 0;
int                    g_stub_PACKAGECHECKBULKWeigh_call_count        = 0;

DbStatus_t db_PACKAGECHECKBULKWeigh(PGconn* conn, const PACKAGECHECKBULKItem_t* items, int item_count, int* served_item_count_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_PACKAGECHECKBULKWeigh_call_count++;
  g_stub_PACKAGECHECKBULKWeigh_last_item_count = item_count;
  memcpy(g_stub_PACKAGECHECKBULKWeigh_last_items, items, (size_t)item_count * sizeof(items[0]));
  if (g_stub_PACKAGECHECKBULKWeigh_status != DB_OK)
    return g_stub_PACKAGECHECKBULKWeigh_status;

  int served_item_count = g_stub_PACKAGECHECKBULKWeigh_served_item_count;
  *served_item_count_out = (served_item_count < 0 || served_item_count > item_count) ? item_count : served_item_count;
  return DB_OK;
}

DbStatus_t g_stub_DRIVERLOOKUPBULK_status                                   = DB_ERROR;
int        g_stub_DRIVERLOOKUPBULK_call_count                               = 0;
char       g_stub_DRIVERLOOKUPBULK_last_ids[BULK_MAX_IDS][BULK_ID_MAX_LEN + 1];
int        g_stub_DRIVERLOOKUPBULK_last_id_count                            = 0;
int        g_stub_DRIVERLOOKUPBULK_failed_index                             = -1;
int        g_stub_DRIVERLOOKUPBULKResultFree_call_count                     = 0;
size_t     g_stub_DRIVERLOOKUPBULK_matches_len                              = 0;

static char* static_driverMatchesDocument(void)
{
  if (g_stub_DRIVERLOOKUPBULK_matches_len == 0)
    return strdup(DRIVERLOOKUP_STUB_MATCHES);
  return static_paddedStringArrayDocument(g_stub_DRIVERLOOKUPBULK_matches_len);
}

DbStatus_t db_DRIVERLOOKUPBULK(PGconn* conn, const BulkIdsParams_t* params, DRIVERLOOKUPBULKResult_t* results_out)
{
  g_stub_query_call_count++;
  (void)conn;
  g_stub_DRIVERLOOKUPBULK_call_count++;
  g_stub_DRIVERLOOKUPBULK_last_id_count = params->m_idCount;
  for (int i = 0; i < params->m_idCount; i++)
    snprintf(g_stub_DRIVERLOOKUPBULK_last_ids[i], sizeof(g_stub_DRIVERLOOKUPBULK_last_ids[i]), "%s", params->ma_ids[i]);
  results_out->m_successful = 0;
  results_out->m_failed     = 0;
  results_out->mp_items     = NULL;
  if (g_stub_DRIVERLOOKUPBULK_status != DB_OK)
    return g_stub_DRIVERLOOKUPBULK_status;

  results_out->mp_items = calloc((size_t)params->m_idCount, sizeof(DRIVERLOOKUPRecord_t));
  if (!results_out->mp_items)
    return DB_ERROR;
  for (int i = 0; i < params->m_idCount; i++)
  {
    if (i == g_stub_DRIVERLOOKUPBULK_failed_index)
      continue;
    DRIVERLOOKUPRecord_t* record = &results_out->mp_items[results_out->m_successful];
    snprintf(record->ma_fileHash, sizeof(record->ma_fileHash), "%s", params->ma_ids[i]);
    record->m_matchCount         = g_stub_DRIVERLOOKUP_match_count;
    record->m_isDriverFeedLoaded = g_stub_DRIVERLOOKUP_is_driver_feed_loaded;
    record->mp_matches           = g_stub_DRIVERLOOKUP_match_count > 0 ? static_driverMatchesDocument() : strdup("[]");
    if (!record->mp_matches)
    {
      db_DRIVERLOOKUPBULKResultFree(results_out);
      return DB_ERROR;
    }
    results_out->m_successful++;
  }
  results_out->m_failed = params->m_idCount - results_out->m_successful;
  return DB_OK;
}

void db_DRIVERLOOKUPBULKResultFree(DRIVERLOOKUPBULKResult_t* results)
{
  g_stub_DRIVERLOOKUPBULKResultFree_call_count++;
  if (!results) return;
  for (int i = 0; i < results->m_successful; i++)
    free(results->mp_items[i].mp_matches);
  free(results->mp_items);
  results->mp_items     = NULL;
  results->m_successful = 0;
}
