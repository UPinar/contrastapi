#include <stdlib.h>
#include <string.h>

#include "cache.h"

#define CACHE_STUB_BODY_SIZE 32768

CacheStatus_t g_stub_CACHE_get_status = CACHE_MISS;
const char*   g_stub_CACHE_get_body   = "{}\n";
bool          g_stub_CACHE_put_result = true;

int g_stub_CACHE_get_count  = 0;
int g_stub_CACHE_put_count  = 0;
int g_stub_CACHE_free_count = 0;

PGconn* g_stub_CACHE_last_get_conn = NULL;
PGconn* g_stub_CACHE_last_put_conn = NULL;
char    g_stub_CACHE_last_get_key[CACHE_KEY_MAX_LEN + 1] = "";
char    g_stub_CACHE_last_put_key[CACHE_KEY_MAX_LEN + 1] = "";

char         g_stub_CACHE_last_put_body[CACHE_STUB_BODY_SIZE]   = "";
size_t       g_stub_CACHE_last_put_body_len                     = 0;
bool         g_stub_CACHE_last_put_is_error                     = false;
unsigned int g_stub_CACHE_last_put_expires_after_seconds        = 0;

CacheStatus_t cache_dbGet(PGconn* conn, const char* cache_key, CacheEntry_t* entry_out)
{
  g_stub_CACHE_get_count++;
  g_stub_CACHE_last_get_conn = conn;
  strncpy(g_stub_CACHE_last_get_key, cache_key, CACHE_KEY_MAX_LEN);
  g_stub_CACHE_last_get_key[CACHE_KEY_MAX_LEN] = '\0';

  memset(entry_out, 0, sizeof(*entry_out));
  if (g_stub_CACHE_get_status != CACHE_HIT)
    return g_stub_CACHE_get_status;

  entry_out->mp_body = strdup(g_stub_CACHE_get_body);
  if (entry_out->mp_body == NULL)
    return CACHE_ERROR;
  memcpy(entry_out->ma_fetchedAt, "2026-01-02T03:04:05Z", CACHE_FETCHED_AT_LEN + 1);
  return CACHE_HIT;
}

bool cache_dbPut(PGconn* conn, const char* cache_key, const char* body, bool is_error, unsigned int expires_after_seconds)
{
  g_stub_CACHE_put_count++;
  g_stub_CACHE_last_put_conn = conn;
  strncpy(g_stub_CACHE_last_put_key, cache_key, CACHE_KEY_MAX_LEN);
  g_stub_CACHE_last_put_key[CACHE_KEY_MAX_LEN] = '\0';
  strncpy(g_stub_CACHE_last_put_body, body, CACHE_STUB_BODY_SIZE - 1);
  g_stub_CACHE_last_put_body[CACHE_STUB_BODY_SIZE - 1] = '\0';
  g_stub_CACHE_last_put_body_len              = strlen(body);
  g_stub_CACHE_last_put_is_error              = is_error;
  g_stub_CACHE_last_put_expires_after_seconds = expires_after_seconds;
  return g_stub_CACHE_put_result;
}

void cache_entryFree(CacheEntry_t* entry)
{
  g_stub_CACHE_free_count++;
  free(entry->mp_body);
  memset(entry, 0, sizeof(*entry));
}
