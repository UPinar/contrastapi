#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>

#include "endpoint_run.h"
#include "cve.h"
#include "cvss.h"
#include "db.h"
#include "response.h"
#include "serialize.h"
#include "cve_exploit.h"
#include "external/hibp.h"
#include "dns.h"
#include "emailcheck.h"
#include "ip.h"
#include "ipguard.h"
#include "tlsprobe.h"
#include "header_fetch.h"
#include "header_check.h"
#include "http.h"
#include "cache.h"
#include "quota.h"
#include "monotonic.h"
#include "etld.h"
#include "external/rdap.h"
#include "registryask.h"
#include "external/certspotter.h"
#include "subdomain.h"
#include "external/wayback.h"
#include "jsonbuf.h"
#include "validate.h"
#include "d3fend.h"
#include "lol.h"
#include "package.h"
#include "imagescan.h"
#include "exifclient.h"
#include "imageindicator.h"
#include "macro.h"
#include "keyvault.h"
#include "external/shodan.h"
#include "external/abuseipdb.h"
#include "request.h"
#include "vendorkey.h"

static __thread HEALTHData_t g_healthCache;
static __thread int64_t      g_healthCacheFilledAtMs;
static __thread bool         g_isHealthCacheFilled;

EndpointRunStatus_t endpoint_HEALTHRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)params;
  (void)message_out;

  int64_t now_ms = monotonic_nowMs();
  if (g_isHealthCacheFilled && now_ms - g_healthCacheFilledAtMs < ENDPOINT_RUN_HEALTH_CACHE_TTL_MS)
  {
    serialize_HEALTH_response(&g_healthCache, json_buf);
    return ENDPOINT_RUN_OK;
  }

  HEALTHData_t health_data;
  DbStatus_t db_status = db_HEALTH(conn, &health_data);
  if (db_status != DB_OK)
  {
    serialize_HEALTH_response(NULL, json_buf);
    return ENDPOINT_RUN_DEGRADED;
  }

  g_healthCache           = health_data;
  g_healthCacheFilledAtMs = now_ms;
  g_isHealthCacheFilled   = true;
  serialize_HEALTH_response(&g_healthCache, json_buf);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVELOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;
  const CVELOOKUPParams_t* cve_lookup_params = &params->m_cveLookup;

  CVELOOKUPRecord_t* record = calloc(1, sizeof(*record));
  if (!record)
    return ENDPOINT_RUN_NO_MEMORY;

  DbStatus_t db_status = db_CVELOOKUP(conn, cve_lookup_params->ma_cveId, record);
  if (db_status != DB_OK)
  {
    db_CVELOOKUPRecordFree(record);
    free(record);
    return db_status == DB_NOT_FOUND ? ENDPOINT_RUN_NOT_FOUND : ENDPOINT_RUN_DB_ERROR;
  }

  if (cve_lookup_params->m_isGhsaIncluded)
  {
    record->m_isGhsaAsked     = true;
    record->m_ghsaUnavailable = db_CVELOOKUPGHSA(conn, cve_lookup_params->ma_cveId, record) != DB_OK;
  }

  serialize_CVELOOKUP_response(record, json_buf);
  db_CVELOOKUPRecordFree(record);
  free(record);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVELOOKUPBULKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;
  const BulkIdsParams_t* bulk_ids_params = &params->m_bulkIds;

  CVELOOKUPBULKResult_t result;
  memset(&result, 0, sizeof(result));
  if (bulk_ids_params->m_idCount > 0 && db_CVELOOKUPBULK(conn, bulk_ids_params, &result) != DB_OK)
  {
    db_CVELOOKUPBULKResultFree(&result);
    return ENDPOINT_RUN_DB_ERROR;
  }
  result.m_total              = bulk_ids_params->m_idCount + bulk_ids_params->m_skippedIdCount + bulk_ids_params->m_notProcessedIdCount;
  result.m_processed          = bulk_ids_params->m_idCount;
  result.m_skipped            = bulk_ids_params->m_skippedIdCount;
  result.mp_notProcessedIds   = &bulk_ids_params->ma_ids[bulk_ids_params->m_idCount];
  result.m_notProcessedCount  = bulk_ids_params->m_notProcessedIdCount;

  serialize_CVELOOKUPBULK_response(&result, json_buf);
  db_CVELOOKUPBULKResultFree(&result);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVEPRODUCTSRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  CVEPRODUCTSResult_t result;
  memset(&result, 0, sizeof(result));

  DbStatus_t db_status = db_CVEPRODUCTS(conn, &params->m_cveProducts, &result);
  if (db_status != DB_OK)
  {
    db_CVEPRODUCTSResultFree(&result);
    return db_status == DB_NOT_FOUND ? ENDPOINT_RUN_NOT_FOUND : ENDPOINT_RUN_DB_ERROR;
  }

  serialize_CVEPRODUCTS_response(&result, &params->m_cveProducts, json_buf);
  db_CVEPRODUCTSResultFree(&result);

  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVESEARCHRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  CveListResult_t results;
  memset(&results, 0, sizeof(results));
  if (db_CVESEARCH(conn, &params->m_cveSearch, &results) != DB_OK)
  {
    db_CveListResultFree(&results);
    return ENDPOINT_RUN_DB_ERROR;
  }

  serialize_CVESEARCH_response(&results, &params->m_cveSearch, json_buf);
  db_CveListResultFree(&results);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVELEADINGRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  CveListResult_t results;
  memset(&results, 0, sizeof(results));
  if (db_CVELEADING(conn, &params->m_cveLeading, &results) != DB_OK)
  {
    db_CveListResultFree(&results);
    return ENDPOINT_RUN_DB_ERROR;
  }

  serialize_CVELEADING_response(&results, &params->m_cveLeading, json_buf);
  db_CveListResultFree(&results);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_KEVLOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  KEVLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  DbStatus_t db_status = db_KEVLOOKUP(conn, params->m_cveId.ma_cveId, &record);
  if (db_status != DB_OK)
  {
    db_KEVLOOKUPRecordFree(&record);
    return db_status == DB_NOT_FOUND ? ENDPOINT_RUN_NOT_FOUND : ENDPOINT_RUN_DB_ERROR;
  }

  serialize_KEVLOOKUP_response(&record, json_buf);
  db_KEVLOOKUPRecordFree(&record);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CWELOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  CWELOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  DbStatus_t db_status = db_CWELOOKUP(conn, params->m_cweLookup.ma_cweId, &record);
  if (db_status != DB_OK)
  {
    db_CWELOOKUPRecordFree(&record);
    return db_status == DB_NOT_FOUND ? ENDPOINT_RUN_NOT_FOUND : ENDPOINT_RUN_DB_ERROR;
  }

  serialize_CWELOOKUP_response(&record, json_buf);
  db_CWELOOKUPRecordFree(&record);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVERISKSCORERun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  CVERISKSCORERecord_t record;
  memset(&record, 0, sizeof(record));
  DbStatus_t db_status = db_CVERISKSCORE(conn, params->m_cveId.ma_cveId, &record);
  if (db_status == DB_NOT_FOUND)
    return ENDPOINT_RUN_NOT_FOUND;
  else if (db_status != DB_OK)
    return ENDPOINT_RUN_DB_ERROR;

  serialize_CVERISKSCORE_response(&record, json_buf);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVEEXPLOITRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  CVEEXPLOITRecord_t record;
  cve_exploit_fetch(conn, params->m_cveId.ma_cveId, &record);
  serialize_CVEEXPLOIT_response(&record, json_buf);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVETRIAGERun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  CVETRIAGEResult_t results;
  memset(&results, 0, sizeof(results));
  if (db_CVETRIAGE(conn, &params->m_cveTriage, &results) != DB_OK)
  {
    db_CVETRIAGEResultFree(&results);
    return ENDPOINT_RUN_DB_ERROR;
  }

  serialize_CVETRIAGE_response(&results, &params->m_cveTriage, json_buf);
  db_CVETRIAGEResultFree(&results);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVETRIAGEBULKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;
  const BulkIdsParams_t* bulk_ids_params = &params->m_bulkIds;

  CVETRIAGEBULKResult_t result;
  memset(&result, 0, sizeof(result));
  if (bulk_ids_params->m_idCount > 0 && db_CVETRIAGEBULK(conn, bulk_ids_params, &result) != DB_OK)
  {
    db_CVETRIAGEBULKResultFree(&result);
    return ENDPOINT_RUN_DB_ERROR;
  }
  result.m_total              = bulk_ids_params->m_idCount + bulk_ids_params->m_skippedIdCount + bulk_ids_params->m_notProcessedIdCount;
  result.m_processed          = bulk_ids_params->m_idCount;
  result.m_skipped            = bulk_ids_params->m_skippedIdCount;
  result.mp_notProcessedIds   = &bulk_ids_params->ma_ids[bulk_ids_params->m_idCount];
  result.m_notProcessedCount  = bulk_ids_params->m_notProcessedIdCount;

  serialize_CVETRIAGEBULK_response(&result, json_buf);
  db_CVETRIAGEBULKResultFree(&result);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_PRODUCTEXPOSURERun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;
  const PRODUCTEXPOSUREParams_t* product_exposure_params = &params->m_productExposure;

  PRODUCTEXPOSURERecord_t record;
  memset(&record, 0, sizeof(record));
  if (db_PRODUCTEXPOSURE(conn, product_exposure_params, &record) != DB_OK)
    return ENDPOINT_RUN_DB_ERROR;

  serialize_PRODUCTEXPOSURE_response(&record, json_buf);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CPESEARCHRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  CPESEARCHResult_t results;
  memset(&results, 0, sizeof(results));
  if (db_CPESEARCH(conn, &params->m_cpeSearch, &results) != DB_OK)
  {
    db_CPESEARCHResultFree(&results);
    return ENDPOINT_RUN_DB_ERROR;
  }

  serialize_CPESEARCH_response(&results, &params->m_cpeSearch, json_buf);
  db_CPESEARCHResultFree(&results);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_CVSSCALCULATORRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  assert(message_out != NULL);

  CvssResult_t result;
  CvssParseStatus_t parse_status = cvss_parse(params->m_cvssCalculator.ma_vector, &result);
  if (parse_status != CVSS_OK)
  {
    *message_out = cvss_parseStatusMessage(parse_status);
    return ENDPOINT_RUN_REFUSED;
  }

  serialize_CVSSCALCULATOR_response(&result, json_buf);
  return ENDPOINT_RUN_OK;
}

static void static_PRIVACYMYDATAReadVendorKeys(PGconn* conn, const char* key_hash, char* manage_url_out, PRIVACYMYDATAVendorKeys_t* vendor_keys_out)
{
  if (conn == NULL)
    return;
  DbVendorKeys_t stored;
  if (db_readVendorKeys(conn, key_hash, &stored) != DB_OK)
    return;
  if (!endpoint_tryWriteVendorKeysManageUrl(conn, &stored, manage_url_out))
    return;
  vendor_keys_out->m_isShodanConfigured    = stored.ma_shodanSealedHex[0] != '\0';
  vendor_keys_out->m_isAbuseIpDbConfigured = stored.ma_abuseIpDbSealedHex[0] != '\0';
  vendor_keys_out->mp_manageUrl            = manage_url_out;
}

EndpointRunStatus_t endpoint_PRIVACYMYDATARun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;
  const RequestCreditBudget_t* credit_budget = params->m_privacyMyData.mp_creditBudget;
  assert(credit_budget != NULL);

  char                             manage_url[ENDPOINT_RUN_VENDOR_KEYS_MANAGE_URL_BUF_SIZE] = "";
  PRIVACYMYDATAVendorKeys_t        vendor_keys = { .mp_manageUrl = "" };
  const PRIVACYMYDATAVendorKeys_t* shown_vendor_keys = NULL;
  if (credit_budget->m_tier == REQUEST_TIER_PRO)
  {
    static_PRIVACYMYDATAReadVendorKeys(conn, credit_budget->ma_budgetHash, manage_url, &vendor_keys);
    shown_vendor_keys = &vendor_keys;
  }

  char resets_in[RESPONSE_RESET_COUNTDOWN_BUF_SIZE];
  response_formatResetCountdown(credit_budget->m_rateLimitInfo.m_reset, time(NULL), resets_in, sizeof(resets_in));
  serialize_PRIVACYMYDATA_response(credit_budget, resets_in, shown_vendor_keys, json_buf);
  return ENDPOINT_RUN_OK;
}

#define PASSWORDCHECK_HOLD_NAME   "hibp"

EndpointRunStatus_t endpoint_PASSWORDCHECKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  unsigned int hold_seconds = 0;
  if (!quota_dbTryReadHoldRemainingSeconds(conn, PASSWORDCHECK_HOLD_NAME, &hold_seconds))
    return ENDPOINT_RUN_DB_ERROR;
  if (hold_seconds > 0)
    return ENDPOINT_RUN_UPSTREAM_ERROR;

  PASSWORDCHECKRecord_t record;
  unsigned int retry_after_seconds = 0;
  HibpStatus_t hibp_status = hibp_check(params->m_passwordCheck.ma_sha1Hash, &record, &retry_after_seconds);
  if (hibp_status == HIBP_INVALID_HASH)
  {
    *message_out = VALIDATE_SHA1_HEX_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }
  if (hibp_status == HIBP_RATE_LIMITED)
    quota_dbSetHold(conn, PASSWORDCHECK_HOLD_NAME, retry_after_seconds);
  if (hibp_status != HIBP_OK)
    return ENDPOINT_RUN_UPSTREAM_ERROR;

  serialize_PASSWORDCHECK_response(&record, json_buf);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_DNSLOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;

  DNSLOOKUPRecord_t   record;
  EndpointRunStatus_t run_status = ENDPOINT_RUN_NO_MEMORY;
  switch (dns_lookupDomain(params->m_dnsLookup.ma_domain, &record))
  {
    case DNS_LOOKUP_OK:
      serialize_DNSLOOKUP_response(&record, json_buf);
      run_status = ENDPOINT_RUN_OK;
      break;
    case DNS_LOOKUP_NOT_FOUND:
      run_status = ENDPOINT_RUN_NOT_FOUND;
      break;
    case DNS_LOOKUP_NO_ANSWER:
      run_status = ENDPOINT_RUN_UPSTREAM_ERROR;
      break;
    case DNS_LOOKUP_INVALID_NAME:
      *message_out = VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case DNS_LOOKUP_NO_MEMORY:
      run_status = ENDPOINT_RUN_NO_MEMORY;
      break;
  }
  dns_DNSLOOKUPRecordFree(&record);
  return run_status;
}

EndpointRunStatus_t endpoint_DNSTAKEOVERCHECKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;

  DNSTAKEOVERCHECKRecord_t record;
  switch (dns_checkTakeover(params->m_dnsTakeoverCheck.ma_hostname, &record))
  {
    case DNS_LOOKUP_OK:
      serialize_DNSTAKEOVERCHECK_response(&record, json_buf);
      return ENDPOINT_RUN_OK;
    case DNS_LOOKUP_NOT_FOUND:
      return ENDPOINT_RUN_NOT_FOUND;
    case DNS_LOOKUP_NO_ANSWER:
      return ENDPOINT_RUN_UPSTREAM_ERROR;
    case DNS_LOOKUP_INVALID_NAME:
      *message_out = VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    case DNS_LOOKUP_NO_MEMORY:
      break;
  }
  return ENDPOINT_RUN_NO_MEMORY;
}

EndpointRunStatus_t endpoint_EMAILAUTHCHECKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;

  const EMAILAUTHCHECKParams_t* check_params = &params->m_emailAuthCheck;
  EMAILAUTHCHECKRecord_t        record;
  EndpointRunStatus_t           run_status = ENDPOINT_RUN_NO_MEMORY;

  switch (emailcheck_checkDomain(check_params->ma_domain, check_params->ma_dkimSelector, &record))
  {
    case DNS_LOOKUP_OK:
      serialize_EMAILAUTHCHECK_response(&record, json_buf);
      run_status = ENDPOINT_RUN_OK;
      break;
    case DNS_LOOKUP_NOT_FOUND:
      run_status = ENDPOINT_RUN_NOT_FOUND;
      break;
    case DNS_LOOKUP_NO_ANSWER:
      run_status = ENDPOINT_RUN_UPSTREAM_ERROR;
      break;
    case DNS_LOOKUP_INVALID_NAME:
      *message_out = check_params->ma_dkimSelector[0] != '\0' ? EMAILCHECK_NAME_TOO_LONG_REFUSAL_MESSAGE
                                                              : VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case DNS_LOOKUP_NO_MEMORY:
      run_status = ENDPOINT_RUN_NO_MEMORY;
      break;
  }
  emailcheck_EMAILAUTHCHECKRecordFree(&record);
  return run_status;
}

EndpointRunStatus_t endpoint_EMAILADDRESSCHECKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  const char* email = params->m_emailAddressCheck.ma_email;
  if (!validate_emailAddress(email))
  {
    *message_out = VALIDATE_EMAIL_ADDRESS_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  EMAILADDRESSCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  size_t local_part_len = (size_t)(strchr(email, '@') - email);
  size_t email_len      = strlen(email);
  memcpy(record.ma_email, email, email_len + 1);
  for (size_t i = local_part_len + 1; i < email_len; i++)
    record.ma_email[i] = (char)tolower((unsigned char)email[i]);
  memcpy(record.ma_domain, record.ma_email + local_part_len + 1, email_len - local_part_len);

  EndpointRunStatus_t run_status = ENDPOINT_RUN_NO_MEMORY;
  if (db_EMAILADDRESSCHECK(conn, record.ma_domain, &record) != DB_OK)
    run_status = ENDPOINT_RUN_DB_ERROR;
  else
  {
    switch (emailcheck_checkAddressDomain(record.ma_domain, &record))
    {
      case DNS_LOOKUP_OK:
      case DNS_LOOKUP_NOT_FOUND:
        serialize_EMAILADDRESSCHECK_response(&record, json_buf);
        run_status = ENDPOINT_RUN_OK;
        break;
      case DNS_LOOKUP_NO_ANSWER:
        run_status = ENDPOINT_RUN_UPSTREAM_ERROR;
        break;
      case DNS_LOOKUP_INVALID_NAME:
        *message_out = VALIDATE_EMAIL_ADDRESS_REFUSAL_MESSAGE;
        run_status   = ENDPOINT_RUN_REFUSED;
        break;
      case DNS_LOOKUP_NO_MEMORY:
        run_status = ENDPOINT_RUN_NO_MEMORY;
        break;
    }
  }
  emailcheck_EMAILADDRESSCHECKRecordFree(&record);
  return run_status;
}

static void static_IPLOOKUPAskShodan(int64_t api_key_id, const char* sealed_hex, const char* ip_address, IPLOOKUPVendorSlots_t* slots)
{
  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 0;
  if (!keyvault_tryOpen(api_key_id, VENDORKEY_SHODAN_SEAL_NAME, sealed_hex, vendor_key, &vendor_key_len))
  {
    slots->m_internetExposure.m_slotState = IPLOOKUP_SLOT_DB_ERROR;
    return;
  }

  unsigned int   retry_after_seconds = 0;
  ShodanStatus_t shodan_status       = shodan_lookupHost(vendor_key, ip_address, &slots->m_shodanHost, &retry_after_seconds);
  OPENSSL_cleanse(vendor_key, sizeof(vendor_key));

  if (shodan_status == SHODAN_OK || shodan_status == SHODAN_NOT_FOUND)
    slots->m_internetExposure.m_slotState = IPLOOKUP_SLOT_FILLED;
  else if (shodan_status == SHODAN_KEY_REJECTED)
    slots->m_internetExposure.m_slotState = IPLOOKUP_SLOT_KEY_REJECTED;
  else
  {
    slots->m_internetExposure.m_slotState         = IPLOOKUP_SLOT_VENDOR_UNAVAILABLE;
    slots->m_internetExposure.m_retryAfterSeconds = retry_after_seconds;
  }
}

static void static_IPLOOKUPAskAbuseIpDb(int64_t api_key_id, const char* sealed_hex, const char* ip_address, IPLOOKUPVendorSlots_t* slots)
{
  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 0;
  if (!keyvault_tryOpen(api_key_id, VENDORKEY_ABUSEIPDB_SEAL_NAME, sealed_hex, vendor_key, &vendor_key_len))
  {
    slots->m_reputation.m_slotState = IPLOOKUP_SLOT_DB_ERROR;
    return;
  }

  unsigned int      retry_after_seconds = 0;
  AbuseIpDbStatus_t abuseipdb_status    = abuseipdb_checkAddress(vendor_key, ip_address, &slots->m_abuseIpDbReport, &retry_after_seconds);
  OPENSSL_cleanse(vendor_key, sizeof(vendor_key));

  if (abuseipdb_status == ABUSEIPDB_OK)
    slots->m_reputation.m_slotState = IPLOOKUP_SLOT_FILLED;
  else if (abuseipdb_status == ABUSEIPDB_KEY_REJECTED)
    slots->m_reputation.m_slotState = IPLOOKUP_SLOT_KEY_REJECTED;
  else
  {
    slots->m_reputation.m_slotState         = IPLOOKUP_SLOT_VENDOR_UNAVAILABLE;
    slots->m_reputation.m_retryAfterSeconds = retry_after_seconds;
  }
}

static void static_IPLOOKUPFillVendorSlots(PGconn* conn, const RequestCreditBudget_t* credit_budget, const char* ip_address, IPLOOKUPVendorSlots_t* slots)
{
  if (credit_budget->m_tier != REQUEST_TIER_PRO)
  {
    slots->m_internetExposure.m_slotState = IPLOOKUP_SLOT_PRO_KEY_REQUIRED;
    slots->m_reputation.m_slotState       = IPLOOKUP_SLOT_PRO_KEY_REQUIRED;
    return;
  }

  DbVendorKeys_t vendor_keys;
  if (db_readVendorKeys(conn, credit_budget->ma_budgetHash, &vendor_keys) != DB_OK)
  {
    slots->m_internetExposure.m_slotState = IPLOOKUP_SLOT_DB_ERROR;
    slots->m_reputation.m_slotState       = IPLOOKUP_SLOT_DB_ERROR;
    return;
  }

  if (vendor_keys.ma_shodanSealedHex[0] == '\0')
    slots->m_internetExposure.m_slotState = IPLOOKUP_SLOT_KEY_MISSING;
  else
    static_IPLOOKUPAskShodan(vendor_keys.m_apiKeyId, vendor_keys.ma_shodanSealedHex, ip_address, slots);

  if (vendor_keys.ma_abuseIpDbSealedHex[0] == '\0')
    slots->m_reputation.m_slotState = IPLOOKUP_SLOT_KEY_MISSING;
  else
    static_IPLOOKUPAskAbuseIpDb(vendor_keys.m_apiKeyId, vendor_keys.ma_abuseIpDbSealedHex, ip_address, slots);
}

EndpointRunStatus_t endpoint_IPLOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  char ip_address[INET6_ADDRSTRLEN];
  if (!ipguard_tryWriteCanonicalIp(params->m_ipLookup.ma_ipAddress, ip_address))
  {
    *message_out = IPGUARD_GLOBALLY_REACHABLE_IP_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  IPLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  if (db_IPLOOKUP(conn, ip_address, &record) != DB_OK)
  {
    db_IPLOOKUPRecordFree(&record);
    return ENDPOINT_RUN_DB_ERROR;
  }

  dns_lookupPtr(ip_address, &record.m_ptrAnswer);

  IPLOOKUPVendorSlots_t slots;
  memset(&slots, 0, sizeof(slots));
  static_IPLOOKUPFillVendorSlots(conn, params->m_ipLookup.mp_creditBudget, ip_address, &slots);
  serialize_IPLOOKUP_response(&record, &slots, json_buf);

  shodan_freeHost(&slots.m_shodanHost);
  dns_answerFree(&record.m_ptrAnswer);
  db_IPLOOKUPRecordFree(&record);
  return ENDPOINT_RUN_OK;
}

static bool static_ASNLOOKUPTryWriteCanonicalTarget(const char* target, char target_out[INET6_ADDRSTRLEN])
{
  if (ipguard_tryWriteCanonicalIp(target, target_out))
    return true;
  if (!validate_asn(target))
    return false;

  const char* digits = isdigit((unsigned char)target[0]) ? target : target + sizeof("AS") - 1;
  int target_len = snprintf(target_out, INET6_ADDRSTRLEN, "AS%s", digits);

  return target_len >= 0 && (size_t)target_len < INET6_ADDRSTRLEN;
}

EndpointRunStatus_t endpoint_ASNLOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  ASNLOOKUPParams_t canonical_params = params->m_asnLookup;
  if (!static_ASNLOOKUPTryWriteCanonicalTarget(params->m_asnLookup.ma_target, canonical_params.ma_target))
  {
    *message_out = VALIDATE_ASN_LOOKUP_TARGET_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  ASNLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  DbStatus_t db_status = db_ASNLOOKUP(conn, &canonical_params, &record);
  if (db_status != DB_OK)
  {
    db_ASNLOOKUPRecordFree(&record);
    return db_status == DB_NOT_FOUND ? ENDPOINT_RUN_NOT_FOUND : ENDPOINT_RUN_DB_ERROR;
  }

  serialize_ASNLOOKUP_response(&record, &canonical_params, json_buf);

  db_ASNLOOKUPRecordFree(&record);
  return ENDPOINT_RUN_OK;
}

#define SSLCHECK_CACHE_KEY_PREFIX             "ssl_check:"
#define SSLCHECK_CACHE_EXPIRES_AFTER_SECONDS  3600

#define SSLCHECK_CONNECT_FAILED_MESSAGE "no address of the host name took a connection on port " MACRO_STR(TLSPROBE_PORT)
#define SSLCHECK_TIMEOUT_MESSAGE        "the TLS handshake did not finish within " MACRO_STR(TLSPROBE_DEADLINE_MS) " ms"

static const char* static_SSLCHECKHandshakeErrorMessage(TlsProbeHandshakeError_t handshake_error)
{
  switch (handshake_error)
  {
    case TLSPROBE_HANDSHAKE_ERROR_ANSWER_NOT_TLS:
      return "the server on port " MACRO_STR(TLSPROBE_PORT) " did not answer with TLS";
    case TLSPROBE_HANDSHAKE_ERROR_PEER_CLOSED:
      return "the server closed the connection during the TLS handshake";
    case TLSPROBE_HANDSHAKE_ERROR_PROTOCOL_VERSION:
      return "the server takes none of the TLS versions the check offers, TLS 1.0 to TLS 1.3 (protocol_version alert)";
    case TLSPROBE_HANDSHAKE_ERROR_HANDSHAKE_FAILURE:
      return "the server ended the TLS handshake with a handshake_failure alert, such as when it shares no cipher with the check";
    case TLSPROBE_HANDSHAKE_ERROR_UNRECOGNIZED_NAME:
      return "the server does not serve the host name over TLS (unrecognized_name alert)";
    case TLSPROBE_HANDSHAKE_ERROR_CLIENT_CERTIFICATE_REQUIRED:
      return "the server requires a client certificate";
    case TLSPROBE_HANDSHAKE_ERROR_OTHER_ALERT:
      return "the server ended the TLS handshake with an alert";
    case TLSPROBE_HANDSHAKE_ERROR_NO_CERTIFICATE:
      return "the server sent no certificate the check can read";
    case TLSPROBE_HANDSHAKE_ERROR_NONE:
    case TLSPROBE_HANDSHAKE_ERROR_OTHER:
      break;
  }
  return "the TLS handshake failed";
}

EndpointRunStatus_t endpoint_SSLCHECKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  const char* hostname = params->m_sslCheck.ma_hostname;
  char cache_key[sizeof(SSLCHECK_CACHE_KEY_PREFIX) + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(cache_key, sizeof(cache_key), "%s%s", SSLCHECK_CACHE_KEY_PREFIX, hostname);

  if (conn != NULL)
  {
    CacheEntry_t cache_entry;
    if (cache_dbGet(conn, cache_key, &cache_entry) == CACHE_HIT)
    {
      jsonbuf_appendJsonText(json_buf, cache_entry.mp_body);
      cache_entryFree(&cache_entry);
      return ENDPOINT_RUN_OK;
    }
  }

  SSLCHECKRecord_t record;
  switch (tlsprobe_probeHost(hostname, &record.m_result))
  {
    case TLSPROBE_OK:
      break;
    case TLSPROBE_INVALID_NAME:
      *message_out = VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    case TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE:
      *message_out = TLSPROBE_ADDRESS_NOT_GLOBALLY_REACHABLE_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    case TLSPROBE_NAME_NOT_FOUND:
      return ENDPOINT_RUN_NOT_FOUND;
    case TLSPROBE_RESOLVE_FAILED:
      return ENDPOINT_RUN_UPSTREAM_ERROR;
    case TLSPROBE_CONNECT_FAILED:
      *message_out = SSLCHECK_CONNECT_FAILED_MESSAGE;
      return ENDPOINT_RUN_TARGET_UNREACHABLE;
    case TLSPROBE_TIMEOUT:
      *message_out = SSLCHECK_TIMEOUT_MESSAGE;
      return ENDPOINT_RUN_TARGET_UNREACHABLE;
    case TLSPROBE_HANDSHAKE_FAILED:
      *message_out = static_SSLCHECKHandshakeErrorMessage(record.m_result.m_handshakeError);
      return ENDPOINT_RUN_TARGET_UNREACHABLE;
    case TLSPROBE_NO_MEMORY:
      return ENDPOINT_RUN_NO_MEMORY;
  }

  time_t    now     = time(NULL);
  struct tm now_utc = { 0 };
  gmtime_r(&now, &now_utc);
  strftime(record.ma_checkedAt, sizeof(record.ma_checkedAt), "%Y-%m-%dT%H:%M:%SZ", &now_utc);

  record.m_isBlacklistUnavailable       = true;
  record.m_isBlacklistFeedLoaded        = false;
  record.ma_blacklistListingReason[0]   = '\0';
  record.ma_blacklistListingTime[0]     = '\0';
  if (conn != NULL)
    record.m_isBlacklistUnavailable = db_SSLCHECK(conn, record.m_result.m_serverCertificate.ma_sha1Hex, &record) != DB_OK;

  JsonBuf_t* body_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (body_buf == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  serialize_SSLCHECK_response(&record, body_buf);
  char* body = jsonbuf_finish(body_buf);
  jsonbuf_destroy(body_buf);
  if (body == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  if (record.m_isBlacklistFeedLoaded)
    cache_dbPut(conn, cache_key, body, false, SSLCHECK_CACHE_EXPIRES_AFTER_SECONDS);

  jsonbuf_appendJsonText(json_buf, body);
  
  free(body);
  return ENDPOINT_RUN_OK;
}

#define HEADERSCHECK_CACHE_KEY_PREFIX             "headers_check:"
#define HEADERSCHECK_CACHE_FULL_VALUE_MARK        "full:"
#define HEADERSCHECK_CACHE_CUT_VALUE_MARK         "cut:"
#define HEADERSCHECK_CACHE_EXPIRES_AFTER_SECONDS  3600

#define HEADERSCHECK_RESOLVE_FAILED_MESSAGE  "the host name did not resolve"
#define HEADERSCHECK_CONNECT_FAILED_MESSAGE  "no address of the site took a connection on port " MACRO_STR(HEADER_FETCH_PORT)
#define HEADERSCHECK_TIMEOUT_MESSAGE         "the site did not answer in time: a connection may take " MACRO_STR(HTTP_CONNECT_TIMEOUT_MS) " ms, and the whole fetch " MACRO_STR(HEADER_FETCH_DEADLINE_MS) " ms"
#define HEADERSCHECK_TLS_FAILED_MESSAGE      "the TLS handshake with the site failed, or its certificate did not verify; /ssl_check shows why"

EndpointRunStatus_t endpoint_HEADERSCHECKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  HEADERSCHECKRecord_t record;
  memset(&record, 0, sizeof(record));

  const char* hostname = params->m_headersCheck.ma_hostname;

  char cache_key[sizeof(HEADERSCHECK_CACHE_KEY_PREFIX) + sizeof(HEADERSCHECK_CACHE_FULL_VALUE_MARK) + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf( cache_key,
            sizeof(cache_key),
            "%s%s%s",
            HEADERSCHECK_CACHE_KEY_PREFIX,
            params->m_headersCheck.m_isFullHeaderValueIncluded  ? HEADERSCHECK_CACHE_FULL_VALUE_MARK
                                                                : HEADERSCHECK_CACHE_CUT_VALUE_MARK,
            hostname);

  if (conn != NULL)
  {
    CacheEntry_t cache_entry;
    if (cache_dbGet(conn, cache_key, &cache_entry) == CACHE_HIT)
    {
      jsonbuf_appendJsonText(json_buf, cache_entry.mp_body);
      cache_entryFree(&cache_entry);
      return ENDPOINT_RUN_OK;
    }
  }

  switch (header_fetch_fetchHomePage(hostname, &record.m_fetchResult))
  {
    case HTTP_ERROR_NONE:
      break;
    case HTTP_ERROR_RESOLVE:
      *message_out = HEADERSCHECK_RESOLVE_FAILED_MESSAGE;
      return ENDPOINT_RUN_TARGET_UNREACHABLE;
    case HTTP_ERROR_CONNECT:
      *message_out = HEADERSCHECK_CONNECT_FAILED_MESSAGE;
      return ENDPOINT_RUN_TARGET_UNREACHABLE;
    case HTTP_ERROR_TIMEOUT:
      *message_out = HEADERSCHECK_TIMEOUT_MESSAGE;
      return ENDPOINT_RUN_TARGET_UNREACHABLE;
    case HTTP_ERROR_TLS:
      *message_out = HEADERSCHECK_TLS_FAILED_MESSAGE;
      return ENDPOINT_RUN_TARGET_UNREACHABLE;
    case HTTP_ERROR_BLOCKED:
      *message_out = HEADER_FETCH_ADDRESS_NOT_GLOBALLY_REACHABLE_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    case HTTP_ERROR_BODY_TOO_LARGE:
    case HTTP_ERROR_OTHER:
      return ENDPOINT_RUN_UPSTREAM_ERROR;
  }

  assert(record.m_fetchResult.m_capturedHeaderValueCount == HEADER_CHECK_HEADER_COUNT);
  header_check_evaluate(record.m_fetchResult.mp_capturedHeaderValues, record.m_fetchResult.m_setCookieCopyCount, &record.m_report);

  time_t    now     = time(NULL);
  struct tm now_utc = { 0 };
  gmtime_r(&now, &now_utc);
  strftime(record.ma_checkedAt, sizeof(record.ma_checkedAt), "%Y-%m-%dT%H:%M:%SZ", &now_utc);

  char*      body     = NULL;
  JsonBuf_t* body_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (body_buf != NULL)
  {
    serialize_HEADERSCHECK_response(&record, &params->m_headersCheck, body_buf);
    body = jsonbuf_finish(body_buf);
    jsonbuf_destroy(body_buf);
  }
  header_fetch_resultFree(&record.m_fetchResult);
  
  if (body == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  if (conn != NULL && strlen(body) <= CACHE_MAX_BODY_LEN)
    cache_dbPut(conn, cache_key, body, false, HEADERSCHECK_CACHE_EXPIRES_AFTER_SECONDS);
  
  jsonbuf_appendJsonText(json_buf, body);

  free(body);
  return ENDPOINT_RUN_OK;
}

#define WHOISLOOKUP_RDAP_CACHE_KEY_PREFIX         "rdap:"
#define WHOISLOOKUP_WHOIS_CACHE_KEY_PREFIX        "whois:"
#define WHOISLOOKUP_CACHE_EXPIRES_AFTER_SECONDS   3600

EndpointRunStatus_t endpoint_WHOISLOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  const char* registrable_domain = etld_findPlusOne(params->m_whoisLookup.ma_domain);
  if (registrable_domain == NULL)
  {
    *message_out = ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  WHOISLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", registrable_domain);

  RegistryAskServer_t server;
  if (!registryask_tryFindServer(record.ma_domain, &server))
  {
    record.m_unavailableReason = WHOISLOOKUP_UNAVAILABLE_NO_REGISTRY_SERVER;
    serialize_WHOISLOOKUP_response(&record, json_buf);
    return ENDPOINT_RUN_OK;
  }
  record.mp_rdapServerBaseUrl = server.mp_rdapServerBaseUrl;
  record.mp_whoisServerHost   = server.mp_whoisServer != NULL ? server.mp_whoisServer->mp_host : NULL;

  char cache_key[sizeof(WHOISLOOKUP_WHOIS_CACHE_KEY_PREFIX) + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(cache_key, sizeof(cache_key), "%s%s", server.mp_whoisServer == NULL ? WHOISLOOKUP_RDAP_CACHE_KEY_PREFIX : WHOISLOOKUP_WHOIS_CACHE_KEY_PREFIX, record.ma_domain);
  CacheEntry_t cache_entry;
  if (cache_dbGet(conn, cache_key, &cache_entry) == CACHE_HIT)
  {
    jsonbuf_appendJsonText(json_buf, cache_entry.mp_body);
    cache_entryFree(&cache_entry);
    return ENDPOINT_RUN_OK;
  }

  unsigned int retry_after_seconds = 0;
  switch (registryask_askDomain(conn, &registryask_userRequestThrottleRules, NULL, &server, record.ma_domain, &record.m_registration, &retry_after_seconds))
  {
    case REGISTRYASK_OK:
      break;
    case REGISTRYASK_UNAVAILABLE:
      record.m_unavailableReason = WHOISLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED;
      record.m_retryAfterSeconds = retry_after_seconds;
      serialize_WHOISLOOKUP_response(&record, json_buf);
      return ENDPOINT_RUN_OK;
    case REGISTRYASK_NOT_REGISTERED:
      return ENDPOINT_RUN_NOT_FOUND;
    case REGISTRYASK_INVALID_NAME:
      *message_out = VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    case REGISTRYASK_DAILY_QUOTA_EXHAUSTED:
    case REGISTRYASK_UPSTREAM_ERROR:
      return ENDPOINT_RUN_UPSTREAM_ERROR;
    case REGISTRYASK_DB_ERROR:
      return ENDPOINT_RUN_DB_ERROR;
  }

  JsonBuf_t* body_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (body_buf == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  serialize_WHOISLOOKUP_response(&record, body_buf);
  char* body = jsonbuf_finish(body_buf);
  jsonbuf_destroy(body_buf);
  if (body == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  cache_dbPut(conn, cache_key, body, false, WHOISLOOKUP_CACHE_EXPIRES_AFTER_SECONDS);
  jsonbuf_appendJsonText(json_buf, body);

  free(body);
  return ENDPOINT_RUN_OK;
}

#define WAYBACKLOOKUP_CACHE_KEY_PREFIX              "wayback:"
#define WAYBACKLOOKUP_CACHE_EXPIRES_AFTER_SECONDS   86400

static const QuotaRule_t WAYBACKLOOKUP_CDX_QUOTA_RULE = { "wayback", 10, 2 };

#define WAYBACKLOOKUP_HOLD_NAME "wayback"

static EndpointRunStatus_t static_WAYBACKLOOKUPFetch(PGconn* conn, WAYBACKLOOKUPRecord_t* record, WaybackOrder_t order, int capture_limit, int64_t deadline_ms, WaybackCapture_t* captures_out, int* count_out, const char** message_out)
{
  if (monotonic_nowMs() >= deadline_ms)
    return ENDPOINT_RUN_UPSTREAM_ERROR;

  unsigned int hold_seconds = 0;
  if (!quota_dbTryReadHoldRemainingSeconds(conn, WAYBACKLOOKUP_HOLD_NAME, &hold_seconds))
    return ENDPOINT_RUN_DB_ERROR;
  if (hold_seconds > 0)
  {
    record->m_unavailableReason = WAYBACKLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED;
    record->m_retryAfterSeconds = hold_seconds;
    return ENDPOINT_RUN_OK;
  }

  switch (quota_dbReserve(conn, &WAYBACKLOOKUP_CDX_QUOTA_RULE))
  {
    case QUOTA_GRANTED:
      break;
    case QUOTA_EXHAUSTED:
      record->m_unavailableReason = WAYBACKLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED;
      record->m_retryAfterSeconds = quota_windowRemainingSeconds(&WAYBACKLOOKUP_CDX_QUOTA_RULE, time(NULL));
      return ENDPOINT_RUN_OK;
    case QUOTA_ERROR:
      return ENDPOINT_RUN_DB_ERROR;
  }

  EndpointRunStatus_t status = ENDPOINT_RUN_UPSTREAM_ERROR;
  unsigned int retry_after_seconds = 0;
  switch (wayback_lookupCaptures(record->ma_domain, order, capture_limit, deadline_ms, captures_out, count_out, &retry_after_seconds))
  {
    case WAYBACK_OK:
      status = ENDPOINT_RUN_OK;
      break;
    case WAYBACK_RATE_LIMITED:
      quota_dbSetHold(conn, WAYBACKLOOKUP_HOLD_NAME, retry_after_seconds);
      record->m_unavailableReason = WAYBACKLOOKUP_UNAVAILABLE_QUOTA_EXHAUSTED;
      record->m_retryAfterSeconds = retry_after_seconds;
      status = ENDPOINT_RUN_OK;
      break;
    case WAYBACK_UPSTREAM_ERROR:
      break;
    case WAYBACK_INVALID_NAME:
      *message_out = VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE;
      status = ENDPOINT_RUN_REFUSED;
      break;
  }
  return status;
}

EndpointRunStatus_t endpoint_WAYBACKLOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  WAYBACKLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", params->m_waybackLookup.ma_domain);

  char cache_key[sizeof(WAYBACKLOOKUP_CACHE_KEY_PREFIX) + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(cache_key, sizeof(cache_key), "%s%s", WAYBACKLOOKUP_CACHE_KEY_PREFIX, record.ma_domain);
  CacheEntry_t cache_entry;
  if (cache_dbGet(conn, cache_key, &cache_entry) == CACHE_HIT)
  {
    jsonbuf_appendJsonText(json_buf, cache_entry.mp_body);
    cache_entryFree(&cache_entry);
    return ENDPOINT_RUN_OK;
  }

  const int64_t deadline_ms   = monotonic_nowMs() + WAYBACK_LOOKUP_DEADLINE_MS;
  EndpointRunStatus_t status  = static_WAYBACKLOOKUPFetch(conn, &record, WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT, deadline_ms, record.ma_latestCaptures, &record.m_latestCaptureCount, message_out);
  if (status != ENDPOINT_RUN_OK)
    return status;

  if (record.m_latestCaptureCount < WAYBACK_LATEST_CAPTURE_MAX_COUNT)
  {
    if (record.m_latestCaptureCount > 0)
      record.m_firstCapture = record.ma_latestCaptures[record.m_latestCaptureCount - 1];
  }
  else
  {
    int first_capture_count = 0;
    status = static_WAYBACKLOOKUPFetch(conn, &record, WAYBACK_ORDER_OLDEST_FIRST, 1, deadline_ms, &record.m_firstCapture, &first_capture_count, message_out);
    if (status != ENDPOINT_RUN_OK)
      return status;
    if (record.m_unavailableReason == WAYBACKLOOKUP_UNAVAILABLE_NONE && first_capture_count != 1)
      return ENDPOINT_RUN_UPSTREAM_ERROR;
  }

  if (record.m_unavailableReason != WAYBACKLOOKUP_UNAVAILABLE_NONE)
  {
    serialize_WAYBACKLOOKUP_response(&record, json_buf);
    return ENDPOINT_RUN_OK;
  }

  JsonBuf_t* body_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (body_buf == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  serialize_WAYBACKLOOKUP_response(&record, body_buf);
  char* body = jsonbuf_finish(body_buf);
  jsonbuf_destroy(body_buf);
  if (body == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  cache_dbPut(conn, cache_key, body, false, WAYBACKLOOKUP_CACHE_EXPIRES_AFTER_SECONDS);
  jsonbuf_appendJsonText(json_buf, body);

  free(body);
  return ENDPOINT_RUN_OK;
}

#define CERTSEARCH_CACHE_KEY_PREFIX              "certspotter:"
#define CERTSEARCH_CACHE_EXPIRES_AFTER_SECONDS   86400

static const QuotaRule_t CERTSEARCH_QUOTA_RULE = { "certspotter_name", 3600, 80 };


EndpointRunStatus_t endpoint_CERTSEARCHRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  CERTSEARCHRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", params->m_certSearch.ma_domain);

  char cache_key[sizeof(CERTSEARCH_CACHE_KEY_PREFIX) + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(cache_key, sizeof(cache_key), "%s%s", CERTSEARCH_CACHE_KEY_PREFIX, record.ma_domain);
  CacheEntry_t cache_entry;
  if (cache_dbGet(conn, cache_key, &cache_entry) == CACHE_HIT)
  {
    jsonbuf_appendJsonText(json_buf, cache_entry.mp_body);
    cache_entryFree(&cache_entry);
    return ENDPOINT_RUN_OK;
  }

  if (!certspotter_hasApiKey())
    return ENDPOINT_RUN_UPSTREAM_ERROR;

  unsigned int hold_seconds = 0;
  if (!quota_dbTryReadHoldRemainingSeconds(conn, CERTSPOTTER_HOLD_NAME, &hold_seconds))
    return ENDPOINT_RUN_DB_ERROR;
  if (hold_seconds > 0)
  {
    record.m_unavailableReason = CERTSEARCH_UNAVAILABLE_QUOTA_EXHAUSTED;
    record.m_retryAfterSeconds = hold_seconds;
    serialize_CERTSEARCH_response(&record, json_buf);
    return ENDPOINT_RUN_OK;
  }

  unsigned int retry_after_seconds = 0;
  switch (certspotter_lookupCertificates(conn, &CERTSEARCH_QUOTA_RULE, record.ma_domain, &record.m_certificateList, &retry_after_seconds))
  {
    case CERTSPOTTER_OK:
      break;
    case CERTSPOTTER_QUOTA_EXHAUSTED:
      record.m_unavailableReason = CERTSEARCH_UNAVAILABLE_QUOTA_EXHAUSTED;
      record.m_retryAfterSeconds = quota_windowRemainingSeconds(&CERTSEARCH_QUOTA_RULE, time(NULL));
      serialize_CERTSEARCH_response(&record, json_buf);
      return ENDPOINT_RUN_OK;
    case CERTSPOTTER_DB_ERROR:
      return ENDPOINT_RUN_DB_ERROR;
    case CERTSPOTTER_RATE_LIMITED:
      quota_dbSetHold(conn, CERTSPOTTER_HOLD_NAME, retry_after_seconds);
      record.m_unavailableReason = CERTSEARCH_UNAVAILABLE_QUOTA_EXHAUSTED;
      record.m_retryAfterSeconds = retry_after_seconds;
      serialize_CERTSEARCH_response(&record, json_buf);
      return ENDPOINT_RUN_OK;
    case CERTSPOTTER_UPSTREAM_ERROR:
    case CERTSPOTTER_NO_API_KEY:
      return ENDPOINT_RUN_UPSTREAM_ERROR;
    case CERTSPOTTER_INVALID_NAME:
      *message_out = VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
  }

  JsonBuf_t* body_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (body_buf == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  serialize_CERTSEARCH_response(&record, body_buf);
  char* body = jsonbuf_finish(body_buf);
  jsonbuf_destroy(body_buf);
  if (body == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  cache_dbPut(conn, cache_key, body, false, CERTSEARCH_CACHE_EXPIRES_AFTER_SECONDS);
  jsonbuf_appendJsonText(json_buf, body);

  free(body);
  return ENDPOINT_RUN_OK;
}

#define SUBDOMAINENUM_CACHE_KEY_PREFIX              "subdomain:"
#define SUBDOMAINENUM_CACHE_EXPIRES_AFTER_SECONDS   86400
#define SUBDOMAINENUM_PARTIAL_CACHE_MIN_SECONDS     600

static const QuotaRule_t SUBDOMAINENUM_QUOTA_RULE = { "certspotter_subtree", 3600, 5 };

#define SUBDOMAINENUM_HOLD_NAME "certspotter_subtree"

static EndpointRunStatus_t static_SUBDOMAINENUMReserveRequest(PGconn* conn, SUBDOMAINENUMRecord_t* record)
{
  if (!certspotter_hasApiKey())
  {
    record->m_certificateLogStatus = SUBDOMAINENUM_CERTIFICATE_LOGS_UPSTREAM_ERROR;
    return ENDPOINT_RUN_OK;
  }

  unsigned int hold_seconds = 0;
  if (!quota_dbTryReadHoldRemainingSeconds(conn, SUBDOMAINENUM_HOLD_NAME, &hold_seconds))
    return ENDPOINT_RUN_DB_ERROR;
  if (hold_seconds > 0)
  {
    record->m_certificateLogStatus = SUBDOMAINENUM_CERTIFICATE_LOGS_QUOTA_EXHAUSTED;
    record->m_retryAfterSeconds    = hold_seconds;
    return ENDPOINT_RUN_OK;
  }

  switch (quota_dbReserve(conn, &SUBDOMAINENUM_QUOTA_RULE))
  {
    case QUOTA_GRANTED:
      break;
    case QUOTA_EXHAUSTED:
      record->m_certificateLogStatus = SUBDOMAINENUM_CERTIFICATE_LOGS_QUOTA_EXHAUSTED;
      record->m_retryAfterSeconds    = quota_windowRemainingSeconds(&SUBDOMAINENUM_QUOTA_RULE, time(NULL));
      return ENDPOINT_RUN_OK;
    case QUOTA_ERROR:
      return ENDPOINT_RUN_DB_ERROR;
  }
  return ENDPOINT_RUN_OK;
}

static EndpointRunStatus_t static_SUBDOMAINENUMAskCertSpotter(PGconn* conn, SUBDOMAINENUMRecord_t* record, const char** message_out)
{
  unsigned int retry_after_seconds = 0;
  switch (certspotter_lookupSubdomainNames(record->ma_domain, record->mp_nameSet, &record->m_isCertificateLogAnswerEmpty, &retry_after_seconds))
  {
    case CERTSPOTTER_OK:
      break;
    case CERTSPOTTER_RATE_LIMITED:
      quota_dbSetHold(conn, SUBDOMAINENUM_HOLD_NAME, retry_after_seconds);
      record->m_certificateLogStatus = SUBDOMAINENUM_CERTIFICATE_LOGS_QUOTA_EXHAUSTED;
      record->m_retryAfterSeconds    = retry_after_seconds;
      break;
    case CERTSPOTTER_UPSTREAM_ERROR:
    case CERTSPOTTER_NO_API_KEY:
    case CERTSPOTTER_QUOTA_EXHAUSTED:
    case CERTSPOTTER_DB_ERROR:
      record->m_certificateLogStatus = SUBDOMAINENUM_CERTIFICATE_LOGS_UPSTREAM_ERROR;
      break;
    case CERTSPOTTER_INVALID_NAME:
      *message_out = VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
  }
  return ENDPOINT_RUN_OK;
}

static EndpointRunStatus_t static_SUBDOMAINENUMWriteAndCache(PGconn* conn, const char* cache_key, const SUBDOMAINENUMRecord_t* record, JsonBuf_t* json_buf)
{
  JsonBuf_t* body_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (body_buf == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  serialize_SUBDOMAINENUM_response(record, body_buf);
  char* body = jsonbuf_finish(body_buf);
  jsonbuf_destroy(body_buf);
  if (body == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  unsigned int expires_after_seconds = SUBDOMAINENUM_PARTIAL_CACHE_MIN_SECONDS;
  if (record->m_certificateLogStatus == SUBDOMAINENUM_CERTIFICATE_LOGS_AVAILABLE)
    expires_after_seconds = SUBDOMAINENUM_CACHE_EXPIRES_AFTER_SECONDS;
  else if ( record->m_certificateLogStatus == SUBDOMAINENUM_CERTIFICATE_LOGS_QUOTA_EXHAUSTED && 
            record->m_retryAfterSeconds > SUBDOMAINENUM_PARTIAL_CACHE_MIN_SECONDS)
  {
    expires_after_seconds = record->m_retryAfterSeconds;
  }

  if (record->m_wildcardDns == SUBDOMAIN_WILDCARD_UNDETERMINED)
    expires_after_seconds = SUBDOMAINENUM_PARTIAL_CACHE_MIN_SECONDS;
  
  cache_dbPut(conn, cache_key, body, false, expires_after_seconds);
  jsonbuf_appendJsonText(json_buf, body);

  free(body);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_SUBDOMAINENUMRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  const char* registrable_domain = etld_findPlusOne(params->m_subdomainEnum.ma_domain);
  if (registrable_domain == NULL)
  {
    *message_out = ETLD_PUBLIC_SUFFIX_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  SUBDOMAINENUMRecord_t record;
  memset(&record, 0, sizeof(record));
  snprintf(record.ma_domain, sizeof(record.ma_domain), "%s", registrable_domain);

  char cache_key[sizeof(SUBDOMAINENUM_CACHE_KEY_PREFIX) + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(cache_key, sizeof(cache_key), "%s%s", SUBDOMAINENUM_CACHE_KEY_PREFIX, record.ma_domain);
  CacheEntry_t cache_entry;
  if (cache_dbGet(conn, cache_key, &cache_entry) == CACHE_HIT)
  {
    jsonbuf_appendJsonText(json_buf, cache_entry.mp_body);
    cache_entryFree(&cache_entry);
    return ENDPOINT_RUN_OK;
  }

  record.mp_nameSet = subdomain_createNameSet();
  if (record.mp_nameSet == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  EndpointRunStatus_t status = static_SUBDOMAINENUMReserveRequest(conn, &record);
  if (status == ENDPOINT_RUN_OK)
  {
    subdomain_lookupDnsNames(record.ma_domain, record.mp_nameSet, &record.m_wildcardDns);
    if (record.m_certificateLogStatus == SUBDOMAINENUM_CERTIFICATE_LOGS_AVAILABLE)
      status = static_SUBDOMAINENUMAskCertSpotter(conn, &record, message_out);
  }
  if (status == ENDPOINT_RUN_OK)
    status = static_SUBDOMAINENUMWriteAndCache(conn, cache_key, &record, json_buf);

  subdomain_destroyNameSet(record.mp_nameSet);
  return status;
}

EndpointRunStatus_t endpoint_D3FENDFORATTACKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  D3FENDFORATTACKResult_t result;
  memset(&result, 0, sizeof(result));
  if (db_D3FENDFORATTACK(conn, params->m_d3fendForAttack.ma_attackTechniqueId, &result) != DB_OK)
  {
    db_D3FENDFORATTACKResultFree(&result);
    return ENDPOINT_RUN_DB_ERROR;
  }

  serialize_D3FENDFORATTACK_response(&result, &params->m_d3fendForAttack, json_buf);
  db_D3FENDFORATTACKResultFree(&result);

  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_DRIVERLOOKUPRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  DRIVERLOOKUPRecord_t record;
  memset(&record, 0, sizeof(record));
  if (db_DRIVERLOOKUP(conn, params->m_driverLookup.ma_fileHash, params->m_driverLookup.m_isCommandIncluded, &record) != DB_OK)
  {
    db_DRIVERLOOKUPRecordFree(&record);
    return ENDPOINT_RUN_DB_ERROR;
  }

  serialize_DRIVERLOOKUP_response(&record, json_buf);
  db_DRIVERLOOKUPRecordFree(&record);

  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_PACKAGECHECKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;

  PACKAGECHECKResult_t result;
  memset(&result, 0, sizeof(result));
  if (db_PACKAGECHECK(conn, &params->m_packageCheck, &result) != DB_OK)
  {
    db_PACKAGECHECKResultFree(&result);
    return ENDPOINT_RUN_DB_ERROR;
  }

  serialize_PACKAGECHECK_response(&result, &params->m_packageCheck, json_buf);
  db_PACKAGECHECKResultFree(&result);

  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_PACKAGECHECKBULKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;
  const PACKAGECHECKBULKParams_t* bulk_params = &params->m_packageCheckBulk;
  int read_count = bulk_params->m_itemCount + bulk_params->m_notProcessedItemCount;

  PACKAGECHECKBULKItem_t* items = NULL;
  if (!endpoint_readKeptPackageItems(bulk_params, read_count, &items))
    return ENDPOINT_RUN_NO_MEMORY;

  PACKAGECHECKBULKResult_t result;
  memset(&result, 0, sizeof(result));
  if (bulk_params->m_itemCount > 0 && db_PACKAGECHECKBULK(conn, items, bulk_params->m_itemCount, &result) != DB_OK)
  {
    db_PACKAGECHECKBULKResultFree(&result);
    free(items);
    return ENDPOINT_RUN_DB_ERROR;
  }

  result.m_total                = bulk_params->m_itemCount + bulk_params->m_skippedItemCount + bulk_params->m_notProcessedItemCount;
  result.m_processed            = bulk_params->m_itemCount;
  result.m_skipped              = bulk_params->m_skippedItemCount;
  result.mp_notProcessedItems   = items != NULL ? &items[bulk_params->m_itemCount] : NULL;
  result.m_notProcessedCount    = bulk_params->m_notProcessedItemCount;

  serialize_PACKAGECHECKBULK_response(&result, json_buf);
  db_PACKAGECHECKBULKResultFree(&result);
  free(items);
  
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_DRIVERLOOKUPBULKRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)message_out;
  const BulkIdsParams_t* bulk_ids_params = &params->m_bulkIds;

  DRIVERLOOKUPBULKResult_t result;
  memset(&result, 0, sizeof(result));
  if (bulk_ids_params->m_idCount > 0 && db_DRIVERLOOKUPBULK(conn, bulk_ids_params, &result) != DB_OK)
  {
    db_DRIVERLOOKUPBULKResultFree(&result);
    return ENDPOINT_RUN_DB_ERROR;
  }
  result.m_total              = bulk_ids_params->m_idCount + bulk_ids_params->m_skippedIdCount + bulk_ids_params->m_notProcessedIdCount;
  result.m_processed          = bulk_ids_params->m_idCount;
  result.m_skipped            = bulk_ids_params->m_skippedIdCount;
  result.mp_notProcessedIds   = &bulk_ids_params->ma_ids[bulk_ids_params->m_idCount];
  result.m_notProcessedCount  = bulk_ids_params->m_notProcessedIdCount;

  serialize_DRIVERLOOKUPBULK_response(&result, json_buf);
  db_DRIVERLOOKUPBULKResultFree(&result);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_IMAGEINSPECTRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  assert(message_out != NULL);

  ImageScanResult_t scan_result;
  const EndpointByteSpan_t* image = &params->m_imageInspect.m_image;
  ImageScanStatus_t scan_status = imagescan_scan(image->mp_bytes, image->m_byteCount, &scan_result);
  switch (scan_status)
  {
    case IMAGESCAN_OK:
      break;
    case IMAGESCAN_ERR_UNKNOWN_FORMAT:
      *message_out = IMAGESCAN_UNKNOWN_FORMAT_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    case IMAGESCAN_ERR_HASH:
      return ENDPOINT_RUN_NO_MEMORY;
  }

  ExifClientResult_t  exif_result;
  EndpointRunStatus_t run_status = ENDPOINT_RUN_NO_MEMORY;
  switch (exifclient_inspect(image->mp_bytes, image->m_byteCount, &exif_result))
  {
    case EXIFCLIENT_OK:
    {
      ImageIndicatorResult_t indicators;
      imageindicator_find(&exif_result, &indicators);
      serialize_IMAGEINSPECT_response(&scan_result, &exif_result, &indicators, json_buf);
      run_status = ENDPOINT_RUN_OK;
      break;
    }
    case EXIFCLIENT_ERR_REFUSED:
      *message_out = EXIFCLIENT_REFUSAL_MESSAGE;
      run_status   = ENDPOINT_RUN_REFUSED;
      break;
    case EXIFCLIENT_ERR_CONNECT:
    case EXIFCLIENT_ERR_TRANSFER:
    case EXIFCLIENT_ERR_DEADLINE:
    case EXIFCLIENT_ERR_TOO_LARGE:
    case EXIFCLIENT_ERR_MALFORMED:
      run_status = ENDPOINT_RUN_UPSTREAM_ERROR;
      break;
    case EXIFCLIENT_ERR_NO_MEMORY:
      run_status = ENDPOINT_RUN_NO_MEMORY;
      break;
  }
  explicit_bzero(&exif_result, sizeof(exif_result));
  return run_status;
}
