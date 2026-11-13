#ifndef CACHE_H
#define CACHE_H

#include <stdbool.h>
#include <libpq-fe.h>

#define CACHE_MAX_BODY_LEN 1048576

#define CACHE_KEY_MAX_LEN 512

#define CACHE_FETCHED_AT_LEN 20

#define CACHE_PURGE_BATCH_ROW_COUNT 10000

typedef enum {
  CACHE_HIT,
  CACHE_MISS,
  CACHE_ERROR,
} CacheStatus_t;

typedef struct {
  char* mp_body;
  bool  m_isError;
  char  ma_fetchedAt[CACHE_FETCHED_AT_LEN + 1];
} CacheEntry_t;

CacheStatus_t cache_dbGet     (PGconn* conn, const char* cache_key, CacheEntry_t* entry_out);
bool          cache_dbPut     (PGconn* conn, const char* cache_key, const char* body, bool is_error, unsigned int expires_after_seconds);
void          cache_entryFree (CacheEntry_t* entry);

bool cache_dbPurgeExpiredRows(PGconn* conn);

#endif
