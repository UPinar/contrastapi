#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "cveidstate.h"
#include "cache.h"
#include "cve.h"
#include "datetime.h"
#include "external/cveservices.h"
#include "jsonread.h"
#include "monotonic.h"
#include "quota.h"
#include "upstream.h"
#include "usagelog.h"
#include "validate.h"

#define CVEIDSTATE_CACHE_KEY_PREFIX "cve_id_state:"

#define CVEIDSTATE_NAME_MAX_LEN 16

#define CVEIDSTATE_PUBLISHED_EXPIRES_AFTER_SECONDS   600
#define CVEIDSTATE_UNKNOWN_ID_EXPIRES_AFTER_SECONDS  600
#define CVEIDSTATE_RESERVED_EXPIRES_AFTER_SECONDS    3600
#define CVEIDSTATE_REJECTED_EXPIRES_AFTER_SECONDS    DATETIME_SECONDS_PER_DAY

static const QuotaRule_t CVEIDSTATE_CVE_SERVICES_QUOTA_RULE     = { "cve_services", 10, 10 };
static const QuotaRule_t CVEIDSTATE_CVE_SERVICES_DAY_QUOTA_RULE = { "cve_services_day", DATETIME_SECONDS_PER_DAY, 10000 };

#define CVEIDSTATE_CVE_SERVICES_HOLD_NAME  "cve_services"

static CveServicesCveIdState_t static_readKeptState(const char* kept_value)
{
  JsonReadSpan_t root_span  = { 0 };
  JsonReadSpan_t state_span = { 0 };
  char           state_name[CVEIDSTATE_NAME_MAX_LEN + 1];
  if (jsonread_root(kept_value, strlen(kept_value), &root_span) != JSONREAD_OK  ||
      jsonread_objectKey(root_span, "state", &state_span) != JSONREAD_OK        ||
      jsonread_spanToStrStatus(state_span, state_name, sizeof(state_name)) != JSONREAD_OK)
  {
    return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;
  }

  static const CveServicesCveIdState_t known_states[] = {
    CVESERVICES_CVE_ID_STATE_PUBLISHED,
    CVESERVICES_CVE_ID_STATE_RESERVED,
    CVESERVICES_CVE_ID_STATE_REJECTED,
    CVESERVICES_CVE_ID_STATE_UNKNOWN_ID,
  };
  for (size_t i = 0; i < sizeof(known_states) / sizeof(known_states[0]); i++)
    if (strcmp(state_name, cveservices_cveIdStateName(known_states[i])) == 0)
      return known_states[i];

  return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;
}

static unsigned int static_stateExpiresAfterSeconds(CveServicesCveIdState_t state)
{
  switch (state)
  {
    case CVESERVICES_CVE_ID_STATE_PUBLISHED:   return CVEIDSTATE_PUBLISHED_EXPIRES_AFTER_SECONDS;
    case CVESERVICES_CVE_ID_STATE_RESERVED:    return CVEIDSTATE_RESERVED_EXPIRES_AFTER_SECONDS;
    case CVESERVICES_CVE_ID_STATE_REJECTED:    return CVEIDSTATE_REJECTED_EXPIRES_AFTER_SECONDS;
    case CVESERVICES_CVE_ID_STATE_UNKNOWN_ID:  return CVEIDSTATE_UNKNOWN_ID_EXPIRES_AFTER_SECONDS;
    case CVESERVICES_CVE_ID_STATE_NOT_CHECKED: break;
  }
  assert(false && "only a state CVE.org named is kept");
  return CVEIDSTATE_PUBLISHED_EXPIRES_AFTER_SECONDS;
}

CveServicesCveIdState_t cveidstate_dbFind(PGconn* conn, const char* cve_id)
{
  if (!validate_isCveIdInCveSyntax(cve_id))
    return CVESERVICES_CVE_ID_STATE_UNKNOWN_ID;

  char cache_key[sizeof(CVEIDSTATE_CACHE_KEY_PREFIX) + CVELOOKUP_ID_MAX_LEN];
  int cache_key_len = snprintf(cache_key, sizeof(cache_key), "%s%s", CVEIDSTATE_CACHE_KEY_PREFIX, cve_id);
  if (cache_key_len < 0 || (size_t)cache_key_len >= sizeof(cache_key))
    return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;

  CacheEntry_t  cache_entry;
  CacheStatus_t cache_status = cache_dbGet(conn, cache_key, &cache_entry);
  if (cache_status == CACHE_ERROR)
    return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;
  if (cache_status == CACHE_HIT)
  {
    CveServicesCveIdState_t kept_state = static_readKeptState(cache_entry.mp_body);
    cache_entryFree(&cache_entry);
    if (kept_state != CVESERVICES_CVE_ID_STATE_NOT_CHECKED)
      return kept_state;
  }

  unsigned int hold_seconds = 0;
  if (!quota_dbTryReadHoldRemainingSeconds(conn, CVEIDSTATE_CVE_SERVICES_HOLD_NAME, &hold_seconds) || hold_seconds > 0)
    return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;
  if (quota_dbReserve(conn, &CVEIDSTATE_CVE_SERVICES_QUOTA_RULE) != QUOTA_GRANTED)
    return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;

  QuotaStatus_t day_status = quota_dbReserve(conn, &CVEIDSTATE_CVE_SERVICES_DAY_QUOTA_RULE);
  if (day_status == QUOTA_EXHAUSTED)
    usagelog_writeEventOncePerDay(USAGELOG_EVENT_CVE_SERVICES_CAP_REACHED);
  if (day_status != QUOTA_GRANTED)
    return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;

  if (!upstream_tryEnter())
    return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;

  CveServicesCveIdState_t state               = CVESERVICES_CVE_ID_STATE_NOT_CHECKED;
  unsigned int            retry_after_seconds = 0;
  CveServicesStatus_t     status              = cveservices_askCveIdState(cve_id, monotonic_nowMs() + CVESERVICES_ASK_DEADLINE_MS, &state, &retry_after_seconds);
  upstream_leave();

  if (status == CVESERVICES_RATE_LIMITED)
    quota_dbSetHold(conn, CVEIDSTATE_CVE_SERVICES_HOLD_NAME, retry_after_seconds);
  const char* state_name = cveservices_cveIdStateName(state);
  if (status != CVESERVICES_OK || state_name == NULL)
    return CVESERVICES_CVE_ID_STATE_NOT_CHECKED;

  char kept_value[sizeof("{\"state\":\"\"}") + CVEIDSTATE_NAME_MAX_LEN];
  int kept_value_len = snprintf(kept_value, sizeof(kept_value), "{\"state\":\"%s\"}", state_name);
  if (kept_value_len < 0 || (size_t)kept_value_len >= sizeof(kept_value))
    return state;
  cache_dbPut(conn, cache_key, kept_value, false, static_stateExpiresAfterSeconds(state));
  return state;
}
