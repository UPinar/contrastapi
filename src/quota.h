#ifndef QUOTA_H
#define QUOTA_H

#include <stdbool.h>
#include <time.h>
#include <libpq-fe.h>

#define QUOTA_PURGE_BATCH_ROW_COUNT 10000

typedef enum {
  QUOTA_GRANTED,
  QUOTA_EXHAUSTED,
  QUOTA_ERROR,
} QuotaStatus_t;

typedef struct {
  const char*  mp_sourceName;
  unsigned int m_windowSeconds;
  unsigned int m_callLimit;
} QuotaRule_t;

QuotaStatus_t quota_dbReserve       (PGconn* conn, const QuotaRule_t* rule);
bool          quota_dbMarkExhausted (PGconn* conn, const QuotaRule_t* rule);

unsigned int quota_windowRemainingSeconds(const QuotaRule_t* rule, time_t now);

bool quota_dbSetHold                     (PGconn* conn, const char* hold_name, unsigned int hold_seconds);
bool quota_dbTryReadHoldRemainingSeconds (PGconn* conn, const char* hold_name, unsigned int* remaining_seconds_out);

bool quota_dbPurgeExpiredRows(PGconn* conn);

#endif
