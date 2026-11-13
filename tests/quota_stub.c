#include <stddef.h>
#include <string.h>

#include "quota.h"

QuotaStatus_t g_stub_QUOTA_reserve_status = QUOTA_GRANTED;

#define QUOTA_STUB_RESERVE_STATUS_MAX_COUNT 4
QuotaStatus_t g_stub_QUOTA_reserve_statuses[QUOTA_STUB_RESERVE_STATUS_MAX_COUNT];
int           g_stub_QUOTA_reserve_status_count = 0;

int         g_stub_QUOTA_reserve_count     = 0;
PGconn*     g_stub_QUOTA_last_reserve_conn = NULL;
QuotaRule_t g_stub_QUOTA_last_reserve_rule = { NULL, 0, 0 };

int         g_stub_QUOTA_mark_count     = 0;
PGconn*     g_stub_QUOTA_last_mark_conn = NULL;
QuotaRule_t g_stub_QUOTA_last_mark_rule = { NULL, 0, 0 };

QuotaStatus_t quota_dbReserve(PGconn* conn, const QuotaRule_t* rule)
{
  g_stub_QUOTA_reserve_count++;
  g_stub_QUOTA_last_reserve_conn = conn;
  g_stub_QUOTA_last_reserve_rule = *rule;
  if (g_stub_QUOTA_reserve_count <= g_stub_QUOTA_reserve_status_count)
    return g_stub_QUOTA_reserve_statuses[g_stub_QUOTA_reserve_count - 1];
  return g_stub_QUOTA_reserve_status;
}

#define QUOTA_STUB_HOLD_NAME_MAX_LEN 300

bool         g_stub_QUOTA_hold_read_result = true;
unsigned int g_stub_QUOTA_hold_seconds     = 0;

int     g_stub_QUOTA_hold_read_count     = 0;
PGconn* g_stub_QUOTA_last_hold_read_conn = NULL;
char    g_stub_QUOTA_last_hold_read_name[QUOTA_STUB_HOLD_NAME_MAX_LEN + 1] = "";

int          g_stub_QUOTA_hold_set_count        = 0;
PGconn*      g_stub_QUOTA_last_hold_set_conn    = NULL;
char         g_stub_QUOTA_last_hold_set_name[QUOTA_STUB_HOLD_NAME_MAX_LEN + 1] = "";
unsigned int g_stub_QUOTA_last_hold_set_seconds = 0;

bool quota_dbTryReadHoldRemainingSeconds(PGconn* conn, const char* hold_name, unsigned int* remaining_seconds_out)
{
  g_stub_QUOTA_hold_read_count++;
  g_stub_QUOTA_last_hold_read_conn = conn;
  strncpy(g_stub_QUOTA_last_hold_read_name, hold_name, QUOTA_STUB_HOLD_NAME_MAX_LEN);
  g_stub_QUOTA_last_hold_read_name[QUOTA_STUB_HOLD_NAME_MAX_LEN] = '\0';

  *remaining_seconds_out = g_stub_QUOTA_hold_read_result ? g_stub_QUOTA_hold_seconds : 0;
  return g_stub_QUOTA_hold_read_result;
}

bool quota_dbSetHold(PGconn* conn, const char* hold_name, unsigned int hold_seconds)
{
  g_stub_QUOTA_hold_set_count++;
  g_stub_QUOTA_last_hold_set_conn    = conn;
  g_stub_QUOTA_last_hold_set_seconds = hold_seconds;
  strncpy(g_stub_QUOTA_last_hold_set_name, hold_name, QUOTA_STUB_HOLD_NAME_MAX_LEN);
  g_stub_QUOTA_last_hold_set_name[QUOTA_STUB_HOLD_NAME_MAX_LEN] = '\0';
  return true;
}

bool quota_dbMarkExhausted(PGconn* conn, const QuotaRule_t* rule)
{
  g_stub_QUOTA_mark_count++;
  g_stub_QUOTA_last_mark_conn = conn;
  g_stub_QUOTA_last_mark_rule = *rule;
  return true;
}

unsigned int g_stub_QUOTA_window_remaining_seconds   = 0;
QuotaRule_t  g_stub_QUOTA_last_window_remaining_rule = { NULL, 0, 0 };

unsigned int quota_windowRemainingSeconds(const QuotaRule_t* rule, time_t now)
{
  (void)now;
  g_stub_QUOTA_last_window_remaining_rule = *rule;
  return g_stub_QUOTA_window_remaining_seconds;
}
