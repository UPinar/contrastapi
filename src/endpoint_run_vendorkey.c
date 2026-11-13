#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>

#include "endpoint_run.h"
#include "db.h"
#include "external/abuseipdb.h"
#include "external/shodan.h"
#include "keyvault.h"
#include "pricing.h"
#include "request.h"
#include "serialize.h"
#include "vendorkey.h"

_Static_assert(offsetof(VENDORKEYEDITParams_t, mp_creditBudget) == 0,
               "endpoint_runRow writes the credit budget at offset 0 of the vendor_key_edit params");

#define VENDORKEYEDIT_PRO_KEY_REQUIRED_REFUSAL_MESSAGE  "pro_key_required: vendor keys need a Pro API key: " PRICING_PAGE_URL
#define VENDORKEYEDIT_LINK_EXPIRED_REFUSAL_MESSAGE      "link_expired: the link has ended; ask /privacy_my_data for a new one"
#define VENDORKEYEDIT_LINK_INVALID_REFUSAL_MESSAGE      "link_invalid: the link is not valid or was used already; ask /privacy_my_data for a new one"
#define VENDORKEYEDIT_NOTHING_TO_CHANGE_REFUSAL_MESSAGE "nothing_to_change: send shodan_key, abuseipdb_key, shodan_delete or abuseipdb_delete"
#define VENDORKEYEDIT_KEY_AND_DELETE_REFUSAL_MESSAGE    "bad_request: one vendor takes a key or a delete, not both"
#define VENDORKEYEDIT_STATUS_NEEDS_LINK_REFUSAL_MESSAGE "bad_request: status needs link, the part after #l= in a manage link"
#define VENDORKEYEDIT_VENDOR_KEY_FORMAT_REFUSAL_MESSAGE "vendor_key_format: a vendor key does not have the form its vendor uses"

#define VENDORKEYEDIT_ABUSEIPDB_CHECK_IP "127.0.0.1"

typedef enum {
  VENDORKEYEDIT_ACTION_APPLY = 0,
  VENDORKEYEDIT_ACTION_STATUS,
} VENDORKEYEDITAction_t;

typedef struct {
  int64_t        m_apiKeyId;
  char           ma_linkHash[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 1];
  int64_t        m_linkExpiresAt;
  char           ma_keyFingerprint[DB_VENDOR_KEY_FINGERPRINT_HEX_LEN + 1];
  char           ma_shodanSealedHex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  char           ma_abuseIpDbSealedHex[KEYVAULT_SEALED_HEX_MAX_LEN + 1];
  DbVendorKeys_t m_vendorKeys;
} VENDORKEYEDITAuth_t;

static VENDORKEYEDITAction_t static_VENDORKEYEDITFindAction(const VENDORKEYEDITParams_t* edit_params)
{
  return strcmp(edit_params->ma_action, "status") == 0 ? VENDORKEYEDIT_ACTION_STATUS : VENDORKEYEDIT_ACTION_APPLY;
}

bool endpoint_tryWriteVendorKeysManageUrl(PGconn* conn, const DbVendorKeys_t* vendor_keys, char* manage_url_out)
{
  assert(vendor_keys != NULL);
  assert(manage_url_out != NULL);

  manage_url_out[0] = '\0';
  if (vendor_keys->m_apiKeyId == 0)
    return false;

  char    link[KEYVAULT_VENDOR_KEY_LINK_LEN + 1];
  char    link_hash_hex[KEYVAULT_VENDOR_KEY_LINK_HASH_HEX_LEN + 1];
  int64_t link_expires_at = 0;
  if (!keyvault_tryWriteVendorKeyLink(link)                 ||
      !keyvault_tryHashVendorKeyLink(link, link_hash_hex)   ||
      db_openVendorKeyLink(conn, vendor_keys->m_apiKeyId, link_hash_hex, &link_expires_at) != DB_OK)
  {
    OPENSSL_cleanse(link, sizeof(link));
    return false;
  }

  snprintf(manage_url_out, ENDPOINT_RUN_VENDOR_KEYS_MANAGE_URL_BUF_SIZE, PRICING_VENDOR_KEYS_PAGE_URL "#l=%s", link);
  OPENSSL_cleanse(link, sizeof(link));
  return true;
}

bool endpoint_VENDORKEYEDITWillCallVendor(const EndpointAnyParams_t* params)
{
  const VENDORKEYEDITParams_t* edit_params = &params->m_vendorKeyEdit;

  if (static_VENDORKEYEDITFindAction(edit_params) == VENDORKEYEDIT_ACTION_STATUS)
    return edit_params->ma_link[0] != '\0';

  return edit_params->ma_shodanKey[0] != '\0' || edit_params->ma_abuseIpDbKey[0] != '\0';
}

static EndpointRunStatus_t static_VENDORKEYEDITReadLinkAuth(PGconn* conn, const char* link, VENDORKEYEDITAuth_t* auth_out, const char** message_out)
{
  if (!keyvault_tryHashVendorKeyLink(link, auth_out->ma_linkHash))
    return ENDPOINT_RUN_NO_MEMORY;

  DbVendorKeyLink_t vendor_key_link;
  if (db_readVendorKeyLink(conn, auth_out->ma_linkHash, &vendor_key_link) != DB_OK)
    return ENDPOINT_RUN_DB_ERROR;
  if (vendor_key_link.m_linkState == DB_VENDOR_KEY_LINK_EXPIRED)
  {
    *message_out = VENDORKEYEDIT_LINK_EXPIRED_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }
  else if (vendor_key_link.m_linkState != DB_VENDOR_KEY_LINK_OPEN)
  {
    *message_out = VENDORKEYEDIT_LINK_INVALID_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  auth_out->m_apiKeyId      = vendor_key_link.m_apiKeyId;
  auth_out->m_linkExpiresAt = vendor_key_link.m_linkExpiresAt;
  memcpy(auth_out->ma_shodanSealedHex, vendor_key_link.ma_shodanSealedHex, sizeof(auth_out->ma_shodanSealedHex));
  memcpy(auth_out->ma_abuseIpDbSealedHex, vendor_key_link.ma_abuseIpDbSealedHex, sizeof(auth_out->ma_abuseIpDbSealedHex));
  return ENDPOINT_RUN_OK;
}

static EndpointRunStatus_t static_VENDORKEYEDITReadAuth(PGconn* conn, const VENDORKEYEDITParams_t* edit_params, VENDORKEYEDITAuth_t* auth_out, const char** message_out)
{
  memset(auth_out, 0, sizeof(*auth_out));
  if (edit_params->ma_link[0] != '\0')
    return static_VENDORKEYEDITReadLinkAuth(conn, edit_params->ma_link, auth_out, message_out);

  if (edit_params->mp_creditBudget->m_tier != REQUEST_TIER_PRO)
  {
    *message_out = VENDORKEYEDIT_PRO_KEY_REQUIRED_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }
  if (db_readVendorKeys(conn, edit_params->mp_creditBudget->ma_budgetHash, &auth_out->m_vendorKeys) != DB_OK)
    return ENDPOINT_RUN_DB_ERROR;
  if (auth_out->m_vendorKeys.m_apiKeyId == 0)
  {
    *message_out = VENDORKEYEDIT_PRO_KEY_REQUIRED_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  auth_out->m_apiKeyId = auth_out->m_vendorKeys.m_apiKeyId;
  memcpy(auth_out->ma_keyFingerprint, auth_out->m_vendorKeys.ma_keyFingerprint, sizeof(auth_out->ma_keyFingerprint));
  memcpy(auth_out->ma_shodanSealedHex, auth_out->m_vendorKeys.ma_shodanSealedHex, sizeof(auth_out->ma_shodanSealedHex));
  memcpy(auth_out->ma_abuseIpDbSealedHex, auth_out->m_vendorKeys.ma_abuseIpDbSealedHex, sizeof(auth_out->ma_abuseIpDbSealedHex));
  return ENDPOINT_RUN_OK;
}

static const char* static_VENDORKEYEDITApplyRefusal(const VENDORKEYEDITParams_t* edit_params)
{
  bool has_shodan_key    = edit_params->ma_shodanKey[0] != '\0';
  bool has_abuseipdb_key = edit_params->ma_abuseIpDbKey[0] != '\0';

  if (!has_shodan_key && !has_abuseipdb_key && !edit_params->m_isShodanDeleted && !edit_params->m_isAbuseIpDbDeleted)
    return VENDORKEYEDIT_NOTHING_TO_CHANGE_REFUSAL_MESSAGE;
  if ((has_shodan_key && edit_params->m_isShodanDeleted) || (has_abuseipdb_key && edit_params->m_isAbuseIpDbDeleted))
    return VENDORKEYEDIT_KEY_AND_DELETE_REFUSAL_MESSAGE;
  if ((has_shodan_key && !shodan_isKeyAccepted(edit_params->ma_shodanKey)) ||
      (has_abuseipdb_key && !abuseipdb_isKeyAccepted(edit_params->ma_abuseIpDbKey)))
  {
    return VENDORKEYEDIT_VENDOR_KEY_FORMAT_REFUSAL_MESSAGE;
  }
  return NULL;
}

static bool static_VENDORKEYEDITTryCheckShodanKey(int64_t api_key_id, const char* vendor_key, VENDORKEYEDITVendorResult_t* vendor_result, char* sealed_hex_out)
{
  unsigned int   retry_after_seconds = 0;
  ShodanStatus_t shodan_status       = shodan_checkKey(vendor_key, &retry_after_seconds);
  if (shodan_status == SHODAN_OK)
  {
    vendor_result->m_outcome = VENDORKEYEDIT_OUTCOME_SAVED;
    return keyvault_trySeal(api_key_id, VENDORKEY_SHODAN_SEAL_NAME, vendor_key, strlen(vendor_key), sealed_hex_out);
  }
  else if (shodan_status == SHODAN_KEY_REJECTED)
    vendor_result->m_outcome = VENDORKEYEDIT_OUTCOME_REJECTED;
  else
  {
    vendor_result->m_outcome           = VENDORKEYEDIT_OUTCOME_UNAVAILABLE;
    vendor_result->m_retryAfterSeconds = retry_after_seconds;
  }
  return true;
}

static bool static_VENDORKEYEDITTryCheckAbuseIpDbKey(int64_t api_key_id, const char* vendor_key, VENDORKEYEDITVendorResult_t* vendor_result, char* sealed_hex_out)
{
  AbuseIpDbReport_t report;
  unsigned int      retry_after_seconds = 0;
  AbuseIpDbStatus_t abuseipdb_status    = abuseipdb_checkAddress(vendor_key, VENDORKEYEDIT_ABUSEIPDB_CHECK_IP, &report, &retry_after_seconds);
  if (abuseipdb_status == ABUSEIPDB_OK)
  {
    vendor_result->m_outcome = VENDORKEYEDIT_OUTCOME_SAVED;
    return keyvault_trySeal(api_key_id, VENDORKEY_ABUSEIPDB_SEAL_NAME, vendor_key, strlen(vendor_key), sealed_hex_out);
  }
  else if (abuseipdb_status == ABUSEIPDB_KEY_REJECTED)
    vendor_result->m_outcome = VENDORKEYEDIT_OUTCOME_REJECTED;
  else
  {
    vendor_result->m_outcome           = VENDORKEYEDIT_OUTCOME_UNAVAILABLE;
    vendor_result->m_retryAfterSeconds = retry_after_seconds;
  }
  return true;
}

static bool static_VENDORKEYEDITIsVendorAccepted(const VENDORKEYEDITVendorResult_t* vendor_result)
{
  return vendor_result->m_outcome != VENDORKEYEDIT_OUTCOME_REJECTED && vendor_result->m_outcome != VENDORKEYEDIT_OUTCOME_UNAVAILABLE;
}

static EndpointRunStatus_t static_VENDORKEYEDITApply(PGconn* conn, const VENDORKEYEDITParams_t* edit_params, JsonBuf_t* json_buf, const char** message_out)
{
  VENDORKEYEDITAuth_t auth;
  EndpointRunStatus_t auth_status = static_VENDORKEYEDITReadAuth(conn, edit_params, &auth, message_out);
  if (auth_status != ENDPOINT_RUN_OK)
    return auth_status;

  const char* refusal = static_VENDORKEYEDITApplyRefusal(edit_params);
  if (refusal != NULL)
  {
    *message_out = refusal;
    return ENDPOINT_RUN_REFUSED;
  }

  VENDORKEYEDITApplyResult_t result;
  memset(&result, 0, sizeof(result));
  char shodan_sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1]    = "";
  char abuseipdb_sealed_hex[KEYVAULT_SEALED_HEX_MAX_LEN + 1] = "";

  if (edit_params->ma_shodanKey[0] != '\0' &&
      !static_VENDORKEYEDITTryCheckShodanKey(auth.m_apiKeyId, edit_params->ma_shodanKey, &result.m_shodan, shodan_sealed_hex))
  {
    return ENDPOINT_RUN_NO_MEMORY;
  }
  if (edit_params->ma_abuseIpDbKey[0] != '\0' &&
      !static_VENDORKEYEDITTryCheckAbuseIpDbKey(auth.m_apiKeyId, edit_params->ma_abuseIpDbKey, &result.m_abuseIpDb, abuseipdb_sealed_hex))
  {
    return ENDPOINT_RUN_NO_MEMORY;
  }
  if (edit_params->m_isShodanDeleted)
    result.m_shodan.m_outcome = VENDORKEYEDIT_OUTCOME_DELETED;
  if (edit_params->m_isAbuseIpDbDeleted)
    result.m_abuseIpDb.m_outcome = VENDORKEYEDIT_OUTCOME_DELETED;

  bool is_link_auth       = auth.ma_linkHash[0] != '\0';
  bool is_shodan_saved    = result.m_shodan.m_outcome == VENDORKEYEDIT_OUTCOME_SAVED;
  bool is_abuseipdb_saved = result.m_abuseIpDb.m_outcome == VENDORKEYEDIT_OUTCOME_SAVED;
  if (is_shodan_saved || is_abuseipdb_saved || edit_params->m_isShodanDeleted || edit_params->m_isAbuseIpDbDeleted)
  {
    const DbVendorKeyChange_t change = {
      .m_apiKeyId              = auth.m_apiKeyId,
      .mp_linkHash             = is_link_auth ? auth.ma_linkHash : NULL,
      .mp_keyFingerprint       = is_link_auth ? NULL : auth.ma_keyFingerprint,
      .m_isLinkSpent           = is_link_auth && static_VENDORKEYEDITIsVendorAccepted(&result.m_shodan) && static_VENDORKEYEDITIsVendorAccepted(&result.m_abuseIpDb),
      .mp_shodanSealedHex      = is_shodan_saved ? shodan_sealed_hex : NULL,
      .m_isShodanDeleted       = edit_params->m_isShodanDeleted,
      .mp_abuseIpDbSealedHex   = is_abuseipdb_saved ? abuseipdb_sealed_hex : NULL,
      .m_isAbuseIpDbDeleted    = edit_params->m_isAbuseIpDbDeleted,
    };
    DbVendorKeyApplyStatus_t apply_status;
    if (db_applyVendorKeys(conn, &change, &apply_status) != DB_OK)
      return ENDPOINT_RUN_DB_ERROR;
    if (apply_status == DB_VENDOR_KEY_APPLY_EXPIRED)
    {
      *message_out = VENDORKEYEDIT_LINK_EXPIRED_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    }
    else if (apply_status != DB_VENDOR_KEY_APPLY_APPLIED)
    {
      *message_out = VENDORKEYEDIT_LINK_INVALID_REFUSAL_MESSAGE;
      return ENDPOINT_RUN_REFUSED;
    }
  }

  result.m_shodan.m_isConfigured    = is_shodan_saved || (auth.ma_shodanSealedHex[0] != '\0' && !edit_params->m_isShodanDeleted);
  result.m_abuseIpDb.m_isConfigured = is_abuseipdb_saved || (auth.ma_abuseIpDbSealedHex[0] != '\0' && !edit_params->m_isAbuseIpDbDeleted);

  char manage_url[ENDPOINT_RUN_VENDOR_KEYS_MANAGE_URL_BUF_SIZE] = "";
  if (!is_link_auth)
  {
    endpoint_tryWriteVendorKeysManageUrl(conn, &auth.m_vendorKeys, manage_url);
    result.mp_manageUrl = manage_url;
  }
  serialize_VENDORKEYEDIT_applyResponse(&result, json_buf);
  return ENDPOINT_RUN_OK;
}

static VENDORKEYEDITState_t static_VENDORKEYEDITCheckStoredShodanKey(int64_t api_key_id, const char* sealed_hex)
{
  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 0;
  if (!keyvault_tryOpen(api_key_id, VENDORKEY_SHODAN_SEAL_NAME, sealed_hex, vendor_key, &vendor_key_len))
    return VENDORKEYEDIT_STATE_UNAVAILABLE;

  unsigned int   retry_after_seconds = 0;
  ShodanStatus_t shodan_status       = shodan_checkKey(vendor_key, &retry_after_seconds);
  OPENSSL_cleanse(vendor_key, sizeof(vendor_key));
  if (shodan_status == SHODAN_OK)
    return VENDORKEYEDIT_STATE_WORKING;
  else if (shodan_status == SHODAN_KEY_REJECTED)
    return VENDORKEYEDIT_STATE_REJECTED;
  return VENDORKEYEDIT_STATE_UNAVAILABLE;
}

static VENDORKEYEDITState_t static_VENDORKEYEDITCheckStoredAbuseIpDbKey(int64_t api_key_id, const char* sealed_hex)
{
  char   vendor_key[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  size_t vendor_key_len = 0;
  if (!keyvault_tryOpen(api_key_id, VENDORKEY_ABUSEIPDB_SEAL_NAME, sealed_hex, vendor_key, &vendor_key_len))
    return VENDORKEYEDIT_STATE_UNAVAILABLE;

  AbuseIpDbReport_t report;
  unsigned int      retry_after_seconds = 0;
  AbuseIpDbStatus_t abuseipdb_status    = abuseipdb_checkAddress(vendor_key, VENDORKEYEDIT_ABUSEIPDB_CHECK_IP, &report, &retry_after_seconds);
  OPENSSL_cleanse(vendor_key, sizeof(vendor_key));
  if (abuseipdb_status == ABUSEIPDB_OK)
    return VENDORKEYEDIT_STATE_WORKING;
  else if (abuseipdb_status == ABUSEIPDB_KEY_REJECTED)
    return VENDORKEYEDIT_STATE_REJECTED;
  return VENDORKEYEDIT_STATE_UNAVAILABLE;
}

static EndpointRunStatus_t static_VENDORKEYEDITStatus(PGconn* conn, const VENDORKEYEDITParams_t* edit_params, JsonBuf_t* json_buf, const char** message_out)
{
  if (edit_params->ma_link[0] == '\0')
  {
    *message_out = VENDORKEYEDIT_STATUS_NEEDS_LINK_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_REFUSED;
  }

  VENDORKEYEDITAuth_t auth;
  memset(&auth, 0, sizeof(auth));
  EndpointRunStatus_t auth_status = static_VENDORKEYEDITReadLinkAuth(conn, edit_params->ma_link, &auth, message_out);
  if (auth_status != ENDPOINT_RUN_OK)
    return auth_status;

  VENDORKEYEDITStatusResult_t result;
  memset(&result, 0, sizeof(result));
  if (auth.ma_shodanSealedHex[0] != '\0')
    result.m_shodanState = static_VENDORKEYEDITCheckStoredShodanKey(auth.m_apiKeyId, auth.ma_shodanSealedHex);
  if (auth.ma_abuseIpDbSealedHex[0] != '\0')
    result.m_abuseIpDbState = static_VENDORKEYEDITCheckStoredAbuseIpDbKey(auth.m_apiKeyId, auth.ma_abuseIpDbSealedHex);

  int64_t expires_in_seconds = auth.m_linkExpiresAt - (int64_t)time(NULL);
  result.m_expiresInSeconds  = expires_in_seconds > 0 ? expires_in_seconds : 0;
  serialize_VENDORKEYEDIT_statusResponse(&result, json_buf);
  return ENDPOINT_RUN_OK;
}

EndpointRunStatus_t endpoint_VENDORKEYEDITRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  const VENDORKEYEDITParams_t* edit_params = &params->m_vendorKeyEdit;
  assert(edit_params->mp_creditBudget != NULL);

  EndpointRunStatus_t run_status = static_VENDORKEYEDITFindAction(edit_params) == VENDORKEYEDIT_ACTION_STATUS
                                 ? static_VENDORKEYEDITStatus(conn, edit_params, json_buf, message_out)
                                 : static_VENDORKEYEDITApply(conn, edit_params, json_buf, message_out);

  OPENSSL_cleanse((char*)edit_params->ma_shodanKey, sizeof(edit_params->ma_shodanKey));
  OPENSSL_cleanse((char*)edit_params->ma_abuseIpDbKey, sizeof(edit_params->ma_abuseIpDbKey));
  return run_status;
}
