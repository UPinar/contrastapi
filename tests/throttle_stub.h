#ifndef THROTTLE_STUB_H
#define THROTTLE_STUB_H

#include <stdbool.h>

#include "throttle.h"

extern ThrottleStatus_t g_stub_THROTTLE_charge_status;
extern unsigned int     g_stub_THROTTLE_retry_after_seconds;

extern int            g_stub_THROTTLE_charge_count;
extern PGconn*        g_stub_THROTTLE_last_conn;
extern ThrottleRule_t g_stub_THROTTLE_last_rule;
extern char           g_stub_THROTTLE_last_target_name[THROTTLE_TARGET_NAME_MAX_LEN + 1];
extern unsigned int   g_stub_THROTTLE_last_charged_count;

#define THROTTLE_STUB_MAX_LOAD_COUNT 4

typedef struct {
  const char*  mp_ruleName;
  unsigned int m_loadCount;
  bool         m_isFailed;
} ThrottleStubLoad_t;

extern ThrottleStubLoad_t g_stub_THROTTLE_loads[THROTTLE_STUB_MAX_LOAD_COUNT];
extern unsigned int       g_stub_THROTTLE_default_load;
extern bool               g_stub_THROTTLE_is_read_answered;
extern unsigned int       g_stub_THROTTLE_read_retry_after_seconds;
extern int                g_stub_THROTTLE_read_count;

#define THROTTLE_STUB_MAX_CALL_COUNT     12
#define THROTTLE_STUB_RULE_NAME_BUF_SIZE 33

typedef struct {
  bool         m_isCharge;
  char         ma_ruleName[THROTTLE_STUB_RULE_NAME_BUF_SIZE];
  unsigned int m_windowSeconds;
  unsigned int m_chargeLimit;
  char         ma_targetName[THROTTLE_TARGET_NAME_MAX_LEN + 1];
  unsigned int m_chargedCount;
} ThrottleStubCall_t;

extern ThrottleStubCall_t g_stub_THROTTLE_calls[THROTTLE_STUB_MAX_CALL_COUNT];
extern int                g_stub_THROTTLE_call_count;

#endif
