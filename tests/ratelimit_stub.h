#ifndef RATELIMIT_STUB_H
#define RATELIMIT_STUB_H

#include <limits.h>

#include "ratelimit.h"
#include "auth.h"

#define RL_STUB_BUDGET_UNCAPPED UINT_MAX

extern RateLimitStatus_t g_stub_credit_budget_status;

extern unsigned int g_stub_credit_budget_remaining;

extern time_t g_stub_credit_budget_reset;
extern unsigned int g_stub_last_credit_cost;

extern bool g_stub_last_is_partial_charge_allowed;

extern char g_stub_last_ip_hash[SHA256_HEX_LEN + 1];

extern int g_stub_credit_budget_check_call_count;
extern int g_stub_credit_budget_remaining_call_count;

extern char g_stub_last_remaining_ip_hash[SHA256_HEX_LEN + 1];
extern bool g_stub_last_remaining_has_api_key;

extern bool g_stub_credit_budget_is_check_denied;

#endif
