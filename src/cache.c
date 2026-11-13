#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache.h"
#include "dbhelper.h"
#include "jsonbuf.h"
#include "version.h"

_Static_assert(CACHE_MAX_BODY_LEN <= JSONBUF_DEFAULT_CEILING, "a cached body must fit a response buffer");

#define CACHE_GET_COLUMNS(X)                   \
  X(CACHE_GET_COLUMN_BODY,       "body")       \
  X(CACHE_GET_COLUMN_IS_ERROR,   "is_error")   \
  X(CACHE_GET_COLUMN_FETCHED_AT, "fetched_at")
enum { CACHE_GET_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CACHE_GET_COLUMN_NAMES[] = { CACHE_GET_COLUMNS(DBHELPER_COLUMN_NAME) };

#define CACHE_PUT_COLUMNS(X)                   \
  X(CACHE_PUT_COLUMN_IS_WRITTEN, "is_written")
enum { CACHE_PUT_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CACHE_PUT_COLUMN_NAMES[] = { CACHE_PUT_COLUMNS(DBHELPER_COLUMN_NAME) };

static bool static_writeVersionedKey(const char* cache_key, char* versioned_key_out);

CacheStatus_t cache_dbGet(PGconn* conn, const char* cache_key, CacheEntry_t* entry_out)
{
  assert(cache_key != NULL);
  assert(entry_out != NULL);

  memset(entry_out, 0, sizeof(*entry_out));
  if (!conn)
  {
    fprintf(stderr, "cache_dbGet: no database connection\n");
    return CACHE_ERROR;
  }

  char versioned_key[CACHE_KEY_MAX_LEN + 1];
  if (!static_writeVersionedKey(cache_key, versioned_key))
    return CACHE_ERROR;

  const char* param_values[] = { versioned_key };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_upstream_cache_get($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return CACHE_ERROR;

  if (!dbhelper_isColumnListEqual(res, CACHE_GET_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CACHE_GET_COLUMN_NAMES)))
  {
    PQclear(res);
    return CACHE_ERROR;
  }
  if (PQntuples(res) == 0)
  {
    PQclear(res);
    return CACHE_MISS;
  }

  bool is_read = PQntuples(res) == 1                                                                                      &&
                 !PQgetisnull(res, 0, CACHE_GET_COLUMN_BODY)                                                              &&
                 dbhelper_isColWithinLength(res, 0, CACHE_GET_COLUMN_BODY, CACHE_MAX_BODY_LEN)                            &&
                 dbhelper_fetchColBool(res, 0, CACHE_GET_COLUMN_IS_ERROR, &entry_out->m_isError)                          &&
                 dbhelper_fetchColStr(res, 0, CACHE_GET_COLUMN_FETCHED_AT, entry_out->ma_fetchedAt, CACHE_FETCHED_AT_LEN) &&
                 dbhelper_fetchColStrdup(res, 0, CACHE_GET_COLUMN_BODY, &entry_out->mp_body);
  PQclear(res);

  if (!is_read)
  {
    cache_entryFree(entry_out);
    return CACHE_ERROR;
  }

  return CACHE_HIT;
}

bool cache_dbPut(PGconn* conn, const char* cache_key, const char* body, bool is_error, unsigned int expires_after_seconds)
{
  assert(cache_key != NULL);
  assert(body      != NULL);

  if (!conn)
  {
    fprintf(stderr, "cache_dbPut: no database connection\n");
    return false;
  }
  if (expires_after_seconds == 0)
  {
    fprintf(stderr, "cache_dbPut: expires_after_seconds is 0\n");
    return false;
  }
  if (strlen(body) > CACHE_MAX_BODY_LEN)
  {
    fprintf(stderr, "cache_dbPut: body longer than CACHE_MAX_BODY_LEN\n");
    return false;
  }

  char versioned_key[CACHE_KEY_MAX_LEN + 1];
  if (!static_writeVersionedKey(cache_key, versioned_key))
    return false;

  char expires_after_seconds_str[DBHELPER_UINT_STR_BUF_SIZE];
  int expires_after_seconds_len = snprintf(expires_after_seconds_str, sizeof(expires_after_seconds_str), "%u", expires_after_seconds);
  if (expires_after_seconds_len < 0 || (size_t)expires_after_seconds_len >= sizeof(expires_after_seconds_str))
    return false;

  const char* param_values[] = { versioned_key, body, is_error ? "true" : "false", expires_after_seconds_str };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_upstream_cache_put($1, $2, $3, $4) AS is_written",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return false;

  bool is_written = false;
  bool is_read   = PQntuples(res) == 1                                                                                    &&
                   dbhelper_isColumnListEqual(res, CACHE_PUT_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CACHE_PUT_COLUMN_NAMES)) &&
                   dbhelper_fetchColBool(res, 0, CACHE_PUT_COLUMN_IS_WRITTEN, &is_written);
  PQclear(res);
  return is_read && is_written;
}

void cache_entryFree(CacheEntry_t* entry)
{
  assert(entry != NULL);

  free(entry->mp_body);
  memset(entry, 0, sizeof(*entry));
}

bool cache_dbPurgeExpiredRows(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_upstream_cache_purge($1) AS purged_row_count",
                               "purged_row_count",
                               CACHE_PURGE_BATCH_ROW_COUNT);
}

static bool static_writeVersionedKey(const char* cache_key, char* versioned_key_out)
{
  if (cache_key[0] == '\0')
  {
    versioned_key_out[0] = '\0';
    fprintf(stderr, "static_writeVersionedKey: empty key\n");
    return false;
  }

  int key_len = snprintf(versioned_key_out, CACHE_KEY_MAX_LEN + 1, "%s:%s", CONTRASTAPI_VERSION, cache_key);
  if (key_len < 0 || key_len > CACHE_KEY_MAX_LEN)
  {
    versioned_key_out[0] = '\0';
    fprintf(stderr, "static_writeVersionedKey: key longer than CACHE_KEY_MAX_LEN\n");
    return false;
  }
  return true;
}
