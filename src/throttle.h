#ifndef THROTTLE_H
#define THROTTLE_H

#include <stdbool.h>
#include <libpq-fe.h>

#define THROTTLE_PURGE_BATCH_ROW_COUNT 10000

#define THROTTLE_TARGET_NAME_MAX_LEN 253

typedef enum {
  THROTTLE_CHARGED,
  THROTTLE_REFUSED,
  THROTTLE_ERROR,
} ThrottleStatus_t;

typedef struct {
  const char*  mp_throttleRuleName;
  unsigned int m_windowSeconds;
  unsigned int m_chargeLimit;
} ThrottleRule_t;

ThrottleStatus_t throttle_dbCharge(PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int charged_count, unsigned int* retry_after_seconds_out);

bool throttle_dbTryReadLoad(PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int* load_count_out, unsigned int* retry_after_seconds_out);

bool throttle_dbPurgeExpiredRows(PGconn* conn);

#endif
