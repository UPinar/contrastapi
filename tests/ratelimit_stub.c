#include <limits.h>
#include <stdbool.h>
#include <stdio.h>

#include "ratelimit.h"
#include "ratelimit_stub.h"

RateLimitStatus_t g_stub_credit_budget_status = RATELIMIT_ALLOW;
time_t g_stub_credit_budget_reset = 0;
unsigned int g_stub_credit_budget_remaining = RL_STUB_BUDGET_UNCAPPED;
unsigned int g_stub_last_credit_cost = 0;
bool g_stub_last_is_partial_charge_allowed = false;
char g_stub_last_ip_hash[SHA256_HEX_LEN + 1] = "";
int g_stub_credit_budget_check_call_count = 0;
int g_stub_credit_budget_remaining_call_count = 0;
char g_stub_last_remaining_ip_hash[SHA256_HEX_LEN + 1] = "";
bool g_stub_last_remaining_has_api_key = false;
bool g_stub_credit_budget_is_check_denied = false;

RateLimitStatus_t ratelimit_dbCreditBudgetRemaining(PGconn* conn, const char* ip_hash, bool has_api_key, RateLimitInfo_t* info_out, unsigned int* remaining_credit_count_out)
{
  (void)conn;
  g_stub_credit_budget_remaining_call_count++;
  snprintf(g_stub_last_remaining_ip_hash, sizeof(g_stub_last_remaining_ip_hash), "%s", ip_hash ? ip_hash : "");
  g_stub_last_remaining_has_api_key = has_api_key;
  *remaining_credit_count_out = 0;

  RateLimitStatus_t status = g_stub_credit_budget_status;
  if (status == RATELIMIT_ALLOW && g_stub_credit_budget_remaining == 0)
    status = RATELIMIT_DENY;
  if (status == RATELIMIT_ERROR)
    return status;

  if (info_out)
  {
    info_out->m_limit     = has_api_key ? RL_KEY_CREDIT_LIMIT : RL_ANON_CREDIT_LIMIT;
    info_out->m_remaining = 0;
    info_out->m_reset     = g_stub_credit_budget_reset;
  }
  if (status == RATELIMIT_ALLOW)
    *remaining_credit_count_out = g_stub_credit_budget_remaining;
  return status;
}

RateLimitStatus_t ratelimit_dbCreditBudgetCheck(PGconn* conn, const char* ip_hash, bool has_api_key, unsigned int credit_cost, bool is_partial_charge_allowed, RateLimitInfo_t* info_out, unsigned int* charged_credit_count_out)
{
  (void)conn;
  g_stub_credit_budget_check_call_count++;
  g_stub_last_credit_cost               = credit_cost;
  g_stub_last_is_partial_charge_allowed = is_partial_charge_allowed;
  snprintf(g_stub_last_ip_hash, sizeof(g_stub_last_ip_hash), "%s", ip_hash ? ip_hash : "");

  RateLimitStatus_t status = g_stub_credit_budget_is_check_denied ? RATELIMIT_DENY : g_stub_credit_budget_status;
  unsigned int charged     = credit_cost;
  int remaining            = (status == RATELIMIT_DENY) ? 0 : 10;
  if (status == RATELIMIT_ALLOW && g_stub_credit_budget_remaining != RL_STUB_BUDGET_UNCAPPED)
  {
    unsigned int min_charged_credit_count = is_partial_charge_allowed ? 1 : credit_cost;
    if (g_stub_credit_budget_remaining < min_charged_credit_count)
    {
      status    = RATELIMIT_DENY;
      remaining = (int)g_stub_credit_budget_remaining;
    }
    else
    {
      charged   = (credit_cost <= g_stub_credit_budget_remaining) ? credit_cost : g_stub_credit_budget_remaining;
      remaining = (int)(g_stub_credit_budget_remaining - charged);
    }
  }

  if (info_out)
  {
    info_out->m_limit     = has_api_key ? RL_KEY_CREDIT_LIMIT : RL_ANON_CREDIT_LIMIT;
    info_out->m_remaining = remaining;
    info_out->m_reset     = g_stub_credit_budget_reset;
  }
  if (charged_credit_count_out)
    *charged_credit_count_out = (status == RATELIMIT_ALLOW) ? charged : 0;
  return status;
}
