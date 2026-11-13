#ifndef VENDORKEY_H
#define VENDORKEY_H

#include <stdbool.h>
#include <stdint.h>

#include "keyvault.h"
#include "request.h"

#define VENDORKEY_SHODAN_SEAL_NAME    "shodan"
#define VENDORKEY_ABUSEIPDB_SEAL_NAME "abuseipdb"

#define VENDORKEYEDIT_ACTION_MAX_LEN 6

typedef struct {
  const RequestCreditBudget_t* mp_creditBudget;
  char                         ma_action[VENDORKEYEDIT_ACTION_MAX_LEN + 1];
  char                         ma_link[KEYVAULT_VENDOR_KEY_LINK_LEN + 1];
  char                         ma_shodanKey[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  bool                         m_isShodanDeleted;
  char                         ma_abuseIpDbKey[KEYVAULT_VENDOR_KEY_MAX_LEN + 1];
  bool                         m_isAbuseIpDbDeleted;
} VENDORKEYEDITParams_t;

typedef enum {
  VENDORKEYEDIT_OUTCOME_UNCHANGED = 0,
  VENDORKEYEDIT_OUTCOME_SAVED,
  VENDORKEYEDIT_OUTCOME_DELETED,
  VENDORKEYEDIT_OUTCOME_REJECTED,
  VENDORKEYEDIT_OUTCOME_UNAVAILABLE,
} VENDORKEYEDITOutcome_t;

typedef struct {
  VENDORKEYEDITOutcome_t  m_outcome;
  bool                    m_isConfigured;
  unsigned int            m_retryAfterSeconds;
} VENDORKEYEDITVendorResult_t;

typedef struct {
  VENDORKEYEDITVendorResult_t m_shodan;
  VENDORKEYEDITVendorResult_t m_abuseIpDb;
  const char*                 mp_manageUrl;
} VENDORKEYEDITApplyResult_t;

typedef enum {
  VENDORKEYEDIT_STATE_NOT_CONFIGURED = 0,
  VENDORKEYEDIT_STATE_WORKING,
  VENDORKEYEDIT_STATE_REJECTED,
  VENDORKEYEDIT_STATE_UNAVAILABLE,
} VENDORKEYEDITState_t;

typedef struct {
  VENDORKEYEDITState_t m_shodanState;
  VENDORKEYEDITState_t m_abuseIpDbState;
  int64_t              m_expiresInSeconds;
} VENDORKEYEDITStatusResult_t;

typedef struct {
  bool        m_isShodanConfigured;
  bool        m_isAbuseIpDbConfigured;
  const char* mp_manageUrl;
} PRIVACYMYDATAVendorKeys_t;

#endif
