#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "throttle.h"
#include "throttle_stub.h"

ThrottleStatus_t g_stub_THROTTLE_charge_status       = THROTTLE_CHARGED;
unsigned int     g_stub_THROTTLE_retry_after_seconds = 0;

int            g_stub_THROTTLE_charge_count       = 0;
PGconn*        g_stub_THROTTLE_last_conn          = NULL;
ThrottleRule_t g_stub_THROTTLE_last_rule          = { NULL, 0, 0 };
char           g_stub_THROTTLE_last_target_name[THROTTLE_TARGET_NAME_MAX_LEN + 1] = "";
unsigned int   g_stub_THROTTLE_last_charged_count = 0;

ThrottleStubLoad_t g_stub_THROTTLE_loads[THROTTLE_STUB_MAX_LOAD_COUNT]  = { { NULL, 0, false } };
unsigned int       g_stub_THROTTLE_default_load                         = 0;
bool               g_stub_THROTTLE_is_read_answered                     = true;
unsigned int       g_stub_THROTTLE_read_retry_after_seconds             = 0;
int                g_stub_THROTTLE_read_count                           = 0;

ThrottleStubCall_t g_stub_THROTTLE_calls[THROTTLE_STUB_MAX_CALL_COUNT];
int                g_stub_THROTTLE_call_count = 0;

static void static_recordCall(bool is_charge, const ThrottleRule_t* rule, const char* target_name, unsigned int charged_count)
{
  if (g_stub_THROTTLE_call_count < THROTTLE_STUB_MAX_CALL_COUNT)
  {
    ThrottleStubCall_t* call = &g_stub_THROTTLE_calls[g_stub_THROTTLE_call_count];
    call->m_isCharge      = is_charge;
    snprintf(call->ma_ruleName, sizeof(call->ma_ruleName), "%s", rule->mp_throttleRuleName != NULL ? rule->mp_throttleRuleName : "");
    call->m_windowSeconds = rule->m_windowSeconds;
    call->m_chargeLimit   = rule->m_chargeLimit;
    snprintf(call->ma_targetName, sizeof(call->ma_targetName), "%s", target_name);
    call->m_chargedCount  = charged_count;
  }
  g_stub_THROTTLE_call_count++;
}

ThrottleStatus_t throttle_dbCharge(PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int charged_count, unsigned int* retry_after_seconds_out)
{
  g_stub_THROTTLE_charge_count++;
  g_stub_THROTTLE_last_conn          = conn;
  g_stub_THROTTLE_last_rule          = *rule;
  g_stub_THROTTLE_last_charged_count = charged_count;
  strncpy(g_stub_THROTTLE_last_target_name, target_name, THROTTLE_TARGET_NAME_MAX_LEN);
  g_stub_THROTTLE_last_target_name[THROTTLE_TARGET_NAME_MAX_LEN] = '\0';
  static_recordCall(true, rule, target_name, charged_count);

  *retry_after_seconds_out = g_stub_THROTTLE_charge_status == THROTTLE_REFUSED ? g_stub_THROTTLE_retry_after_seconds : 0;
  return g_stub_THROTTLE_charge_status;
}

bool throttle_dbTryReadLoad(PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int* load_count_out, unsigned int* retry_after_seconds_out)
{
  (void)conn;
  g_stub_THROTTLE_read_count++;
  static_recordCall(false, rule, target_name, 0);

  *load_count_out          = 0;
  *retry_after_seconds_out = 0;
  if (!g_stub_THROTTLE_is_read_answered)
    return false;

  unsigned int load_count = g_stub_THROTTLE_default_load;
  for (int i = 0; i < THROTTLE_STUB_MAX_LOAD_COUNT && g_stub_THROTTLE_loads[i].mp_ruleName != NULL; i++)
  {
    if (rule->mp_throttleRuleName != NULL && strcmp(g_stub_THROTTLE_loads[i].mp_ruleName, rule->mp_throttleRuleName) == 0)
    {
      if (g_stub_THROTTLE_loads[i].m_isFailed)
        return false;
      load_count = g_stub_THROTTLE_loads[i].m_loadCount;
      break;
    }
  }
  *load_count_out          = load_count;
  *retry_after_seconds_out = g_stub_THROTTLE_read_retry_after_seconds;
  return true;
}
